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

#define P521_LIMBS ((521u + LIMB_BITS - 1u)/ LIMB_BITS)
#if defined(OPENSSL_64_BIT)

static const BN_ULONG Q[P521_LIMBS] = {
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff
};

static const BN_ULONG N[P521_LIMBS] = {
    0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0,
    0x51868783bf2f966b, 0xfffffffffffffffa, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x00000000000001ff
};

static const BN_ULONG ONE[P521_LIMBS] = {
    0x0080000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000
};

/* This is just 2**520 */
static const BN_ULONG Q_PLUS_1_SHR_1[P521_LIMBS] = {
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000100
};

#elif defined(OPENSSL_32_BIT)

static const BN_ULONG Q[P521_LIMBS] = {
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff
};

static const BN_ULONG N[P521_LIMBS] = {
    0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, 0xf709a5d0, 0x7fcc0148,
    0xbf2f966b, 0x51868783, 0xfffffffa, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x000001ff
};

static const BN_ULONG ONE[P521_LIMBS] = {
    0x00800000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const BN_ULONG Q_PLUS_1_SHR_1[P521_LIMBS] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000100
};

#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif

static const BN_ULONG Q_N0[] = {
  BN_MONT_CTX_N0(0x0, 0x1)
};

/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER) && !defined(__clang__) && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif

#define BITS 521
/* Window values that are Ok for p521 (look at `ecp_nistz.h`): 4 */
#define W_BITS 4
#define FE_LIMBS P521_LIMBS

#include "ecp_nistz.inl"

void p521_elem_sub(Elem r, const Elem a, const Elem b) {
  elem_sub(r, a, b);
}

void p521_elem_div_by_2(Elem r, const Elem a) {
  elem_div_by_2(r, a);
}

void p521_elem_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}

void p521_elem_neg(Elem r, const Elem a) {
  elem_neg(r, a);
}

void p521_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  static const BN_ULONG N_N0[] = {
    BN_MONT_CTX_N0(0x1d2f5ccd, 0x79a995c7)
  };
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  bn_mul_mont(r, a, b, N, N_N0, FE_LIMBS);
}
