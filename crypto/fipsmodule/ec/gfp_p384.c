/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "../../limbs/limbs.h"

#include "../bn/internal.h"
#include "../../internal.h"

#include "../../limbs/limbs.inl"

#define P384_LIMBS (384u / LIMB_BITS)

static const BN_ULONG Q[P384_LIMBS] = {
  TOBN(0x00000000, 0xffffffff),
  TOBN(0xffffffff, 0x00000000),
  TOBN(0xffffffff, 0xfffffffe),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
};

static const BN_ULONG N[P384_LIMBS] = {
  TOBN(0xecec196a, 0xccc52973),
  TOBN(0x581a0db2, 0x48b0a77a),
  TOBN(0xc7634d81, 0xf4372ddf),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
};

static const BN_ULONG ONE[P384_LIMBS] = {
  TOBN(0xffffffff, 1), TOBN(0, 0xffffffff), TOBN(0, 1), TOBN(0, 0), TOBN(0, 0),
  TOBN(0, 0),
};

static const BN_ULONG Q_PLUS_1_SHR_1[P384_LIMBS] = {
  TOBN(0x00000000, 0x80000000),
  TOBN(0x7fffffff, 0x80000000),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0x7fffffff, 0xffffffff),
};

static const BN_ULONG Q_N0[] = {
  BN_MONT_CTX_N0(0x1, 0x1)
};

/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER) && !defined(__clang__) && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif

#define BITS 384
/* Window values that are Ok for P384 (look at `ecp_nistz.h`): 2, 5, 6, 7 */
#define W_BITS 5
#define FE_LIMBS P384_LIMBS

#include "ecp_nistz.inl"

void p384_elem_sub(Elem r, const Elem a, const Elem b) {
  elem_sub(r, a, b);
}

void p384_elem_div_by_2(Elem r, const Elem a) {
  elem_div_by_2(r, a);
}

void p384_elem_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}

void p384_elem_neg(Elem r, const Elem a) {
  elem_neg(r, a);
}

void p384_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  static const BN_ULONG N_N0[] = {
    BN_MONT_CTX_N0(0x6ed46089, 0xe88fdc45)
  };
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  bn_mul_mont(r, a, b, N, N_N0, FE_LIMBS);
}
