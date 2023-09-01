// Copyright 2023 Brian Smith.
// Copyright 2023 Cloudflare
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    elem::{binary_op, binary_op_assign},
    Modulus, *,
};

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: (521 + LIMB_BITS - 1) / LIMB_BITS,
    order_bits: 521,

    q: Modulus {
        p: limbs_from_hex("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        #[cfg(target_pointer_width = "64")]
        rr: limbs_from_hex("4000000000000000000000000000"),
        #[cfg(target_pointer_width = "32")]
        rr: limbs_from_hex("400000000000"),
    },
    n: Elem::from_hex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"),

    #[cfg(target_pointer_width = "64")]
    a: Elem::from_hex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7fffffffffffff"),
    #[cfg(target_pointer_width = "32")]
    a: Elem::from_hex("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe7fffff"),
    #[cfg(target_pointer_width = "64")]
    b: Elem::from_hex("4d0fc94d10d05b42a077516d392dccd98af9dc5a44c8c77884f0ab0c9ca8f63f49bd8b29605e9dd8df839ab9efc41e961a78f7a28fea35a81f8014654fae586387"),
    #[cfg(target_pointer_width = "32")]
    b: Elem::from_hex("15cb0c70e4d0fc94d10d05b42a077516d392dccd98af9dc5a44c8c77884f0ab0c9ca8f63f49bd8b29605e9dd8df839ab9efc41e961a78f7a28fea35a81f8014654f"),

    elem_mul_mont: p521_elem_mul_mont,
    elem_sqr_mont: p521_elem_sqr_mont,
    point_double_jacobian_impl: p521_point_double,
    point_add_jacobian_impl: p521_point_add,
};

#[cfg(target_pointer_width = "64")]
const GENERATOR: (Elem<R>, Elem<R>) = (
    Elem::from_hex("74e6cf1f65b311cada214e32409c829fda90fc1457b035a69edd50a5af3bf7f3ac947f0ee093d17fd46f19a459e0c2b5214dfcbf3f18e172deb331a16381adc101"),
    Elem::from_hex("1e0022e452fda163e8deccc7aa224abcda2340bd7de8b939f33164bf7394caf7a132062a85c809fd683b09a9e384351396120445f4a3b4fe8b328460e4a5a9e268e"),
);

#[cfg(target_pointer_width = "32")]
const GENERATOR: (Elem<R>, Elem<R>) = (
    Elem::from_hex("1035b820274e6cf1f65b311cada214e32409c829fda90fc1457b035a69edd50a5af3bf7f3ac947f0ee093d17fd46f19a459e0c2b5214dfcbf3f18e172deb331a163"),
    Elem::from_hex("b53c4d1de0022e452fda163e8deccc7aa224abcda2340bd7de8b939f33164bf7394caf7a132062a85c809fd683b09a9e384351396120445f4a3b4fe8b328460e4a"),
);

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_inv_to_mont_impl: p521_scalar_inv_to_mont,
    scalar_mul_mont: p521_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    twin_mul: |g_scalar, p_scalar, p_xy| {
        vartime::points_mul_vartime(&COMMON_OPS, g_scalar, &GENERATOR, p_scalar, p_xy)
    },

    q_minus_n: Elem::from_hex("5ae79787c40d069948033feb708f65a2fc44a36477663b851449048e16ec79bf6"),
};

#[allow(dead_code)]
pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,
    oneRR_mod_n: Scalar::from_hex(N_RR_HEX),
};

fn p521_scalar_inv_to_mont(a: &Scalar<Unencoded>) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //   a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //     0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
    //       ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386\
    //       407
    fn mul(a: &Scalar<R>, b: &Scalar<R>) -> Scalar<R> {
        binary_op(p521_scalar_mul_mont, a, b)
    }

    fn sqr(a: &Scalar<R>) -> Scalar<R> {
        binary_op(p521_scalar_mul_mont, a, a)
    }

    fn sqr_mut(a: &mut Scalar<R>) {
        unary_op_from_binary_op_assign(p521_scalar_mul_mont, a);
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &Scalar<R>, squarings: usize, b: &Scalar<R>) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = sqr(a);
        for _ in 1..squarings {
            sqr_mut(&mut tmp);
        }
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: usize, b: &Scalar<R>) {
        debug_assert!(squarings >= 1);
        for _ in 0..squarings {
            sqr_mut(acc);
        }
        binary_op_assign(p521_scalar_mul_mont, acc, b)
    }

    fn to_mont(a: &Scalar<Unencoded>) -> Scalar<R> {
        binary_op(p521_scalar_mul_mont, a, &PRIVATE_SCALAR_OPS.oneRR_mod_n)
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_11: usize = 1;
    const B_101: usize = 2;
    const B_111: usize = 3;
    const B_1001: usize = 4;
    const B_1011: usize = 5;
    const B_1101: usize = 6;
    const B_1111: usize = 7;
    const DIGIT_COUNT: usize = 8;

    let mut d = [Scalar::zero(); DIGIT_COUNT];
    d[B_1] = to_mont(a);
    let b_10 = sqr(&d[B_1]);
    for i in B_11..DIGIT_COUNT {
        d[i] = mul(&d[i - 1], &b_10);
    }

    let ff = sqr_mul(&d[B_1111], 0 + 4, &d[B_1111]);
    let ffff = sqr_mul(&ff, 0 + 8, &ff);
    let ffffffff = sqr_mul(&ffff, 0 + 16, &ffff);
    let ffffffffffffffff = sqr_mul(&ffffffff, 0 + 32, &ffffffff);
    let fx32 = sqr_mul(&ffffffffffffffff, 0 + 64, &ffffffffffffffff);
    let mut acc = sqr_mul(&fx32, 0 + 128, &fx32);

    // After the first 256 bits, the remaining 265 bits are:
    // 1fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386407

    // The rest of the exponent, in binary, is:
    //
    // 1111110100101000110000110100001111000001110111111001011111001011
    // 0011010110111111111001100000000010100100011110111000010011010010
    // 1110100000011101110110101110010011011100010001001100111000100011
    // 110101110101110110110111110110111000111101001000100111000011001
    // 0000000111

    static REMAINING_WINDOWS: [(u8, u8); 54] = [
        (4, B_1111 as u8),
        (0 + 4, B_1101 as u8),
        (2 + 3, B_101 as u8),
        (3 + 2, B_11 as u8),
        (4 + 4, B_1101 as u8),
        (4 + 4, B_1111 as u8),
        (5 + 3, B_111 as u8),
        (1 + 4, B_1111 as u8),
        (0 + 2, B_11 as u8),
        (2 + 4, B_1011 as u8),
        (0 + 3, B_111 as u8),
        (2 + 4, B_1011 as u8),
        (2 + 4, B_1101 as u8),
        (1 + 4, B_1101 as u8),
        (0 + 4, B_1111 as u8),
        (0 + 4, B_1111 as u8),
        (2 + 2, B_11 as u8),
        (9 + 3, B_101 as u8),
        (2 + 1, B_1 as u8),
        (3 + 4, B_1111 as u8),
        (1 + 3, B_111 as u8),
        (4 + 4, B_1001 as u8),
        (0 + 3, B_101 as u8),
        (2 + 4, B_1011 as u8),
        (0 + 3, B_101 as u8),
        (6 + 3, B_111 as u8),
        (1 + 3, B_111 as u8),
        (1 + 4, B_1101 as u8),
        (1 + 3, B_111 as u8),
        (2 + 4, B_1001 as u8),
        (0 + 4, B_1011 as u8),
        (0 + 1, B_1 as u8),
        (3 + 1, B_1 as u8),
        (3 + 1, B_1 as u8),
        (2 + 2, B_11 as u8),
        (2 + 3, B_111 as u8),
        (3 + 1, B_1 as u8),
        (3 + 4, B_1111 as u8),
        (1 + 4, B_1011 as u8),
        (0 + 3, B_101 as u8),
        (1 + 3, B_111 as u8),
        (1 + 4, B_1101 as u8),
        (0 + 4, B_1011 as u8),
        (0 + 3, B_111 as u8),
        (1 + 4, B_1101 as u8),
        (0 + 2, B_11 as u8),
        (3 + 4, B_1111 as u8),
        (1 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (3 + 4, B_1001 as u8),
        (0 + 2, B_11 as u8),
        (4 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (7 + 3, B_111 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS[..] {
        sqr_mul_acc(&mut acc, usize::from(squarings), &d[usize::from(digit)]);
    }

    acc
}

unsafe extern "C" fn p521_elem_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    // XXX: Inefficient. TODO: Make a dedicated squaring routine.
    p521_elem_mul_mont(r, a, a);
}

#[cfg(target_pointer_width = "64")]
const N_RR_HEX: &str = "3d2d8e03d1492d0d455bcc6d61a8e567bccff3d142b7756e3edd6e23d82e49c7dbd3721ef557f75e0612a78d38794573fff707badce5547ea3137cd04dcf15dd04";

#[cfg(target_pointer_width = "32")]
const N_RR_HEX: &str = "19a5b5a3afe8c44383d2d8e03d1492d0d455bcc6d61a8e567bccff3d142b7756e3a4fb35b72d34027055d4dd6d30791d9dc18354a564374a6421163115a61c64ca7";

prefixed_extern! {
    fn p521_elem_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );

    fn p521_point_add(
        r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        a: *const Limb, // [3][COMMON_OPS.num_limbs]
        b: *const Limb, // [3][COMMON_OPS.num_limbs]
    );
    fn p521_point_double(
        r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        a: *const Limb, // [3][COMMON_OPS.num_limbs]
    );

    fn p521_scalar_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );
}
