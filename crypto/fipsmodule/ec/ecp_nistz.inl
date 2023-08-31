/* Copyright (c) 2014, Intel Corporation.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* Developers and authors:
 * Shay Gueron (1, 2), and Vlad Krasnov (1)
 * (1) Intel Corporation, Israel Development Center
 * (2) University of Haifa
 * Reference:
 *   Shay Gueron and Vlad Krasnov
 *   "Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes"
 *   http://eprint.iacr.org/2013/816 */
#include "ecp_nistz.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

#define RENAME_FUNC(bits, func) nistz ## bits ## _ ## func

#define point_add(bits) RENAME_FUNC(bits, point_add)
#define point_double(bits) RENAME_FUNC(bits, point_double)
#define point_mul(bits) RENAME_FUNC(bits, point_mul)

typedef Limb Elem[FE_LIMBS];
typedef Limb ScalarMont[FE_LIMBS];
typedef Limb Scalar[FE_LIMBS];

typedef struct {
  Limb X[FE_LIMBS];
  Limb Y[FE_LIMBS];
  Limb Z[FE_LIMBS];
} NIST_POINT;

typedef struct {
  Limb X[FE_LIMBS];
  Limb Y[FE_LIMBS];
} NIST_POINT_AFFINE;

#define TBL_SZ (1 << (W_BITS - 1))
#define W_MASK ((1 << (W_BITS + 1)) - 1)

static inline Limb is_equal(const Elem a, const Elem b) {
  return LIMBS_equal(a, b, FE_LIMBS);
}

static inline Limb is_zero(const BN_ULONG a[FE_LIMBS]) {
  return LIMBS_are_zero(a, FE_LIMBS);
}

static inline void copy_conditional(Elem r, const Elem a,
                                                const Limb condition) {
  for (size_t i = 0; i < FE_LIMBS; ++i) {
    r[i] = constant_time_select_w(condition, a[i], r[i]);
  }
}

static inline void elem_add(Elem r, const Elem a, const Elem b) {
  LIMBS_add_mod(r, a, b, Q, FE_LIMBS);
}

static inline void elem_sub(Elem r, const Elem a, const Elem b) {
  LIMBS_sub_mod(r, a, b, Q, FE_LIMBS);
}

static void elem_div_by_2(Elem r, const Elem a) {
  /* Consider the case where `a` is even. Then we can shift `a` right one bit
   * and the result will still be valid because we didn't lose any bits and so
   * `(a >> 1) * 2 == a (mod q)`, which is the invariant we must satisfy.
   *
   * The remainder of this comment is considering the case where `a` is odd.
   *
   * Since `a` is odd, it isn't the case that `(a >> 1) * 2 == a (mod q)`
   * because the lowest bit is lost during the shift. For example, consider:
   *
   * ```python
   * q = 2**384 - 2**128 - 2**96 + 2**32 - 1
   * a = 2**383
   * two_a = a * 2 % q
   * assert two_a == 0x100000000ffffffffffffffff00000001
   * ```
   *
   * Notice there how `(2 * a) % q` wrapped around to a smaller odd value. When
   * we divide `two_a` by two (mod q), we need to get the value `2**383`, which
   * we obviously can't get with just a right shift.
   *
   * `q` is odd, and `a` is odd, so `a + q` is even. We could calculate
   * `(a + q) >> 1` and then reduce it mod `q`. However, then we would have to
   * keep track of an extra most significant bit. We can avoid that by instead
   * calculating `(a >> 1) + ((q + 1) >> 1)`. The `1` in `q + 1` is the least
   * significant bit of `a`. `q + 1` is even, which means it can be shifted
   * without losing any bits. Since `q` is odd, `q - 1` is even, so the largest
   * odd field element is `q - 2`. Thus we know that `a <= q - 2`. We know
   * `(q + 1) >> 1` is `(q + 1) / 2` since (`q + 1`) is even. The value of
   * `a >> 1` is `(a - 1)/2` since the shift will drop the least significant
   * bit of `a`, which is 1. Thus:
   *
   * sum  =  ((q + 1) >> 1) + (a >> 1)
   * sum  =  (q + 1)/2 + (a >> 1)       (substituting (q + 1)/2)
   *     <=  (q + 1)/2 + (q - 2 - 1)/2  (substituting a <= q - 2)
   *     <=  (q + 1)/2 + (q - 3)/2      (simplifying)
   *     <=  (q + 1 + q - 3)/2          (factoring out the common divisor)
   *     <=  (2q - 2)/2                 (simplifying)
   *     <=  q - 1                      (simplifying)
   *
   * Thus, no reduction of the sum mod `q` is necessary. */

  Limb is_odd = constant_time_is_nonzero_w(a[0] & 1);

  /* r = a >> 1. */
  Limb carry = a[FE_LIMBS - 1] & 1;
  r[FE_LIMBS - 1] = a[FE_LIMBS - 1] >> 1;
  for (size_t i = 1; i < FE_LIMBS; ++i) {
    Limb new_carry = a[FE_LIMBS - i - 1];
    r[FE_LIMBS - i - 1] =
        (a[FE_LIMBS - i - 1] >> 1) | (carry << (LIMB_BITS - 1));
    carry = new_carry;
  }

  Elem adjusted;
  BN_ULONG carry2 = limbs_add(adjusted, r, Q_PLUS_1_SHR_1, FE_LIMBS);
  dev_assert_secret(carry2 == 0);
  (void)carry2;
  copy_conditional(r, adjusted, is_odd);
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  /* XXX: Not (clearly) constant-time; inefficient.*/
  bn_mul_mont(r, a, b, Q, Q_N0, FE_LIMBS);
}

static inline void elem_mul_by_2(Elem r, const Elem a) {
  LIMBS_shl_mod(r, a, Q, FE_LIMBS);
}

static INLINE_IF_POSSIBLE void elem_mul_by_3(Elem r, const Elem a) {
  /* XXX: inefficient. TODO: Replace with an integrated shift + add. */
  Elem doubled;
  elem_add(doubled, a, a);
  elem_add(r, doubled, a);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: Add a dedicated squaring routine. */
  elem_mul_mont(r, a, a);
}

static void elem_neg(Elem r, const Elem a) {
  Limb is_zero = LIMBS_are_zero(a, FE_LIMBS);
  Carry borrow = limbs_sub(r, Q, a, FE_LIMBS);
  dev_assert_secret(borrow == 0);
  (void)borrow;
  for (size_t i = 0; i < FE_LIMBS; ++i) {
    r[i] = constant_time_select_w(is_zero, 0, r[i]);
  }
}

/* Point double: r = 2*a */
void point_double(BITS)(NIST_POINT *r, const NIST_POINT *a) {
  BN_ULONG S[FE_LIMBS];
  BN_ULONG M[FE_LIMBS];
  BN_ULONG Zsqr[FE_LIMBS];
  BN_ULONG tmp0[FE_LIMBS];

  const BN_ULONG *in_x = a->X;
  const BN_ULONG *in_y = a->Y;
  const BN_ULONG *in_z = a->Z;

  BN_ULONG *res_x = r->X;
  BN_ULONG *res_y = r->Y;
  BN_ULONG *res_z = r->Z;

  elem_mul_by_2(S, in_y);

  elem_sqr_mont(Zsqr, in_z);

  elem_sqr_mont(S, S);

  elem_mul_mont(res_z, in_z, in_y);
  elem_mul_by_2(res_z, res_z);

  elem_add(M, in_x, Zsqr);
  elem_sub(Zsqr, in_x, Zsqr);

  elem_sqr_mont(res_y, S);
  elem_div_by_2(res_y, res_y);

  elem_mul_mont(M, M, Zsqr);
  elem_mul_by_3(M, M);

  elem_mul_mont(S, S, in_x);
  elem_mul_by_2(tmp0, S);

  elem_sqr_mont(res_x, M);

  elem_sub(res_x, res_x, tmp0);
  elem_sub(S, S, res_x);

  elem_mul_mont(S, S, M);
  elem_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
void point_add(BITS)(NIST_POINT *r, const NIST_POINT *a,
                            const NIST_POINT *b) {
  BN_ULONG U2[FE_LIMBS], S2[FE_LIMBS];
  BN_ULONG U1[FE_LIMBS], S1[FE_LIMBS];
  BN_ULONG Z1sqr[FE_LIMBS];
  BN_ULONG Z2sqr[FE_LIMBS];
  BN_ULONG H[FE_LIMBS], R[FE_LIMBS];
  BN_ULONG Hsqr[FE_LIMBS];
  BN_ULONG Rsqr[FE_LIMBS];
  BN_ULONG Hcub[FE_LIMBS];

  BN_ULONG res_x[FE_LIMBS];
  BN_ULONG res_y[FE_LIMBS];
  BN_ULONG res_z[FE_LIMBS];

  const BN_ULONG *in1_x = a->X;
  const BN_ULONG *in1_y = a->Y;
  const BN_ULONG *in1_z = a->Z;

  const BN_ULONG *in2_x = b->X;
  const BN_ULONG *in2_y = b->Y;
  const BN_ULONG *in2_z = b->Z;

  BN_ULONG in1infty = is_zero(a->Z);
  BN_ULONG in2infty = is_zero(b->Z);

  elem_sqr_mont(Z2sqr, in2_z); /* Z2^2 */
  elem_sqr_mont(Z1sqr, in1_z); /* Z1^2 */

  elem_mul_mont(S1, Z2sqr, in2_z); /* S1 = Z2^3 */
  elem_mul_mont(S2, Z1sqr, in1_z); /* S2 = Z1^3 */

  elem_mul_mont(S1, S1, in1_y); /* S1 = Y1*Z2^3 */
  elem_mul_mont(S2, S2, in2_y); /* S2 = Y2*Z1^3 */
  elem_sub(R, S2, S1);          /* R = S2 - S1 */

  elem_mul_mont(U1, in1_x, Z2sqr); /* U1 = X1*Z2^2 */
  elem_mul_mont(U2, in2_x, Z1sqr); /* U2 = X2*Z1^2 */
  elem_sub(H, U2, U1);             /* H = U2 - U1 */

  BN_ULONG is_exceptional = is_equal(U1, U2) & ~in1infty & ~in2infty;
  if (is_exceptional) {
    if (is_equal(S1, S2)) {
      point_double(BITS)(r, a);
    } else {
      limbs_zero(r->X, FE_LIMBS);
      limbs_zero(r->Y, FE_LIMBS);
      limbs_zero(r->Z, FE_LIMBS);
    }
    return;
  }

  elem_sqr_mont(Rsqr, R);             /* R^2 */
  elem_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
  elem_sqr_mont(Hsqr, H);             /* H^2 */
  elem_mul_mont(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
  elem_mul_mont(Hcub, Hsqr, H);       /* H^3 */

  elem_mul_mont(U2, U1, Hsqr); /* U1*H^2 */
  elem_mul_by_2(Hsqr, U2);     /* 2*U1*H^2 */

  elem_sub(res_x, Rsqr, Hsqr);
  elem_sub(res_x, res_x, Hcub);

  elem_sub(res_y, U2, res_x);

  elem_mul_mont(S2, S1, Hcub);
  elem_mul_mont(res_y, R, res_y);
  elem_sub(res_y, res_y, S2);

  copy_conditional(res_x, in2_x, in1infty);
  copy_conditional(res_y, in2_y, in1infty);
  copy_conditional(res_z, in2_z, in1infty);

  copy_conditional(res_x, in1_x, in2infty);
  copy_conditional(res_y, in1_y, in2infty);
  copy_conditional(res_z, in1_z, in2infty);

  limbs_copy(r->X, res_x, FE_LIMBS);
  limbs_copy(r->Y, res_y, FE_LIMBS);
  limbs_copy(r->Z, res_z, FE_LIMBS);
}

static void NIST_POINT_select_w(NIST_POINT *out,
                                const NIST_POINT table[TBL_SZ], size_t index) {
  Elem x; limbs_zero(x, FE_LIMBS);
  Elem y; limbs_zero(y, FE_LIMBS);
  Elem z; limbs_zero(z, FE_LIMBS);

  // TODO: Rewrite in terms of |limbs_select|.
  for (size_t i = 0; i < TBL_SZ; ++i) {
    crypto_word_t equal = constant_time_eq_w(index, (crypto_word_t)i + 1);
    for (size_t j = 0; j < FE_LIMBS; ++j) {
      x[j] = constant_time_select_w(equal, table[i].X[j], x[j]);
      y[j] = constant_time_select_w(equal, table[i].Y[j], y[j]);
      z[j] = constant_time_select_w(equal, table[i].Z[j], z[j]);
    }
  }

  limbs_copy(out->X, x, FE_LIMBS);
  limbs_copy(out->Y, y, FE_LIMBS);
  limbs_copy(out->Z, z, FE_LIMBS);
}

static void add_precomputed_w(NIST_POINT *r, crypto_word_t wvalue,
                              const NIST_POINT table[TBL_SZ]) {
  crypto_word_t recoded_is_negative;
  crypto_word_t recoded;
  booth_recode(&recoded_is_negative, &recoded, wvalue, W_BITS);

  alignas(64) NIST_POINT h;
  NIST_POINT_select_w(&h, table, recoded);

  alignas(64) BN_ULONG tmp[FE_LIMBS];
  elem_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, recoded_is_negative);

  point_add(BITS)(r, r, &h);
}

/* r = p * p_scalar */
void point_mul(BITS)(NIST_POINT *r, const BN_ULONG p_scalar[FE_LIMBS],
                            const BN_ULONG p_x[FE_LIMBS],
                            const BN_ULONG p_y[FE_LIMBS]) {
  uint8_t p_str[(FE_LIMBS * sizeof(Limb)) + 1];
  little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                  p_scalar, FE_LIMBS);

  /* A |NIST_POINT| is (3 * 48) = 144 bytes, and the 64-byte alignment should
  * add no more than 63 bytes of overhead. Thus, |table| should require
  * ~2367 ((144 * 16) + 63) bytes of stack space. */
  alignas(64) NIST_POINT table[TBL_SZ];

  /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
  * not stored. All other values are actually stored with an offset of -1 in
  * table. */
  NIST_POINT *row = table;

  limbs_copy(row[0].X, p_x, FE_LIMBS);
  limbs_copy(row[0].Y, p_y, FE_LIMBS);
  limbs_copy(row[0].Z, ONE, FE_LIMBS);

  point_double(BITS)(&row[1], &row[0]);

  for (int i = 2; i < TBL_SZ; i += 2) {
    point_add(BITS)(&row[i], &row[i - 1], &row[0]);
    point_double(BITS)(&row[i + 1], &row[i / 2]);
  }

  static const size_t ROUND_SIZE = (BITS + W_BITS - 1) / W_BITS * W_BITS;
  static const size_t START_INDEX = ROUND_SIZE == BITS + 1 ? ROUND_SIZE - W_BITS: ROUND_SIZE;
  size_t index = START_INDEX;

  BN_ULONG recoded_is_negative;
  crypto_word_t recoded;

  crypto_word_t wvalue = p_str[(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & W_MASK;

  booth_recode(&recoded_is_negative, &recoded, wvalue, W_BITS);
  dev_assert_secret(!recoded_is_negative);

  NIST_POINT_select_w(r, table, recoded);

  while (index >= W_BITS) {
    if (index != START_INDEX) {
      size_t off = (index - 1) / 8;

      wvalue = p_str[off] | p_str[off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & W_MASK;
      add_precomputed_w(r, wvalue, table);
    }

    index -= W_BITS;

    for (int i = 0; i < W_BITS; i++) {
      point_double(BITS)(r, r);
    }
  }

  /* Final window */
  wvalue = p_str[0];
  wvalue = (wvalue << 1) & W_MASK;
  add_precomputed_w(r, wvalue, table);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
