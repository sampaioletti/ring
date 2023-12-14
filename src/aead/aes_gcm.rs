// Copyright 2015-2016 Brian Smith.
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
    aes::{self, Counter},
    block::{Block, BLOCK_LEN},
    gcm, Aad, InOut, Nonce, Tag,
};
use crate::{
    aead, cpu, error,
    polyfill::{self},
};
use core::ptr;

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_128_GCM: aead::Algorithm = aead::Algorithm {
    key_len: 16,
    init: init_128,
    seal,
    open,
    id: aead::AlgorithmID::AES_128_GCM,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
pub static AES_256_GCM: aead::Algorithm = aead::Algorithm {
    key_len: 32,
    init: init_256,
    seal,
    open,
    id: aead::AlgorithmID::AES_256_GCM,
    max_input_len: AES_GCM_MAX_INPUT_LEN,
};

#[derive(Clone)]
pub struct Key {
    gcm_key: gcm::Key, // First because it has a large alignment requirement.
    aes_key: aes::Key,
}

fn init_128(key: &[u8], cpu_features: cpu::Features) -> Result<aead::KeyInner, error::Unspecified> {
    init(key, aes::Variant::AES_128, cpu_features)
}

fn init_256(key: &[u8], cpu_features: cpu::Features) -> Result<aead::KeyInner, error::Unspecified> {
    init(key, aes::Variant::AES_256, cpu_features)
}

fn init(
    key: &[u8],
    variant: aes::Variant,
    cpu_features: cpu::Features,
) -> Result<aead::KeyInner, error::Unspecified> {
    let aes_key = aes::Key::new(key, variant, cpu_features)?;
    let gcm_key = gcm::Key::new(
        aes_key.encrypt_block(Block::zero(), cpu_features),
        cpu_features,
    );
    Ok(aead::KeyInner::AesGcm(Key { gcm_key, aes_key }))
}

const CHUNK_BLOCKS: usize = 3 * 1024 / 16;
const STRIDE_LEN: usize = CHUNK_BLOCKS * BLOCK_LEN;

fn seal(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    mut in_out: InOut,
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key { gcm_key, aes_key } = match key {
        aead::KeyInner::AesGcm(key) => key,
        _ => unreachable!(),
    };

    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment();

    let total_in_out_len = in_out.len();
    let aad_len = aad.0.len();
    let mut auth = gcm::Context::new(gcm_key, aad, cpu_features);

    #[cfg(target_arch = "x86_64")]
    if aes_key.is_aes_hw(cpu_features) && auth.is_avx() {
        use crate::c;
        let (htable, xi) = auth.inner();
        prefixed_extern! {
            // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
            // assembly says it needs just nine values in that array.
            fn aesni_gcm_encrypt(
                input: *const u8,
                output: *mut core::mem::MaybeUninit<u8>,
                len: c::size_t,
                key: &aes::AES_KEY,
                ivec: &mut Counter,
                Htable: &gcm::HTable,
                Xi: &mut gcm::Xi) -> c::size_t;
        }
        in_out.advance_after_partial(|chunk| unsafe {
            let input = chunk.input_ptr();
            let len = chunk.len();
            aesni_gcm_encrypt(
                input,
                chunk.into_output_ptr(),
                len,
                aes_key.inner_less_safe(),
                &mut ctr,
                htable,
                xi,
            )
        })?;
    }

    loop {
        let chunk_len = if STRIDE_LEN < in_out.len() {
            STRIDE_LEN
        } else if in_out.len() < BLOCK_LEN {
            break;
        } else {
            in_out.len() - (in_out.len() % BLOCK_LEN)
        };
        let ciphertext = in_out.advance_after(chunk_len, |chunk| {
            aes_key.ctr32_encrypt_within(chunk, &mut ctr, cpu_features)
        })??;
        auth.update_blocks(ciphertext);
    }

    let remaining = in_out.len();
    if remaining > 0 {
        let mut input = Block::zero();
        input.overwrite_part_at(0, in_out.input());
        let mut ciphertext = aes_key.encrypt_iv_xor_block(ctr.into(), input, cpu_features);
        ciphertext.zero_from(remaining);
        auth.update_block(ciphertext);
        let ciphertext = ciphertext.as_ref().as_ptr();
        let output = in_out.into_output().as_mut_ptr().cast();
        unsafe { core::ptr::copy_nonoverlapping(ciphertext, output, remaining) };
    }

    finish(
        aes_key,
        auth,
        tag_iv,
        aad_len,
        total_in_out_len,
        cpu_features,
    )
}

fn open(
    key: &aead::KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    mut in_out: InOut,
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    let Key { gcm_key, aes_key } = match key {
        aead::KeyInner::AesGcm(key) => key,
        _ => unreachable!(),
    };

    let total_in_out_len = in_out.len();

    let mut ctr = Counter::one(nonce);
    let tag_iv = ctr.increment();

    let aad_len = aad.0.len();
    let mut auth = gcm::Context::new(gcm_key, aad, cpu_features);

    #[cfg(target_arch = "x86_64")]
    if aes_key.is_aes_hw(cpu_features) && auth.is_avx() {
        use crate::c;
        let (htable, xi) = auth.inner();
        prefixed_extern! {
            // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
            // assembly says it needs just nine values in that array.
            fn aesni_gcm_decrypt(
                input: *const u8,
                output: *mut core::mem::MaybeUninit<u8>,
                len: c::size_t,
                key: &aes::AES_KEY,
                ivec: &mut Counter,
                Htable: &gcm::HTable,
                Xi: &mut gcm::Xi) -> c::size_t;
        }

        in_out.advance_after_partial(|chunk| unsafe {
            let input = chunk.input_ptr();
            let len = chunk.len();
            aesni_gcm_decrypt(
                input,
                chunk.into_output_ptr(),
                len,
                aes_key.inner_less_safe(),
                &mut ctr,
                htable,
                xi,
            )
        })?;
    }

    loop {
        let chunk_len = if STRIDE_LEN < in_out.len() {
            STRIDE_LEN
        } else if in_out.len() < BLOCK_LEN {
            break;
        } else {
            in_out.len() - (in_out.len() % BLOCK_LEN)
        };
        let _plaintext: &mut [u8] = in_out.advance_after(chunk_len, |chunk| {
            auth.update_blocks(chunk.input());
            aes_key.ctr32_encrypt_within(chunk, &mut ctr, cpu_features)
        })??;
    }

    let remaining = in_out.len();
    if remaining > 0 {
        let mut input = Block::zero();
        input.overwrite_part_at(0, in_out.input());
        auth.update_block(input);
        let plaintext = aes_key.encrypt_iv_xor_block(ctr.into(), input, cpu_features);
        let plaintext = plaintext.as_ref()[..remaining].as_ptr();
        let output = in_out.into_output_ptr();
        unsafe {
            ptr::copy_nonoverlapping(plaintext, output.cast(), remaining);
        }
    }

    finish(
        aes_key,
        auth,
        tag_iv,
        aad_len,
        total_in_out_len,
        cpu_features,
    )
}

fn finish(
    aes_key: &aes::Key,
    mut gcm_ctx: gcm::Context,
    tag_iv: aes::Iv,
    aad_len: usize,
    in_out_len: usize,
    cpu_features: cpu::Features,
) -> Result<Tag, error::Unspecified> {
    // Authenticate the final block containing the input lengths.
    let aad_bits = polyfill::u64_from_usize(aad_len) << 3;
    let ciphertext_bits = polyfill::u64_from_usize(in_out_len) << 3;
    gcm_ctx.update_block(Block::from(
        [aad_bits, ciphertext_bits].map(u64::to_be_bytes),
    ));

    // Finalize the tag and return it.
    Ok(gcm_ctx.pre_finish(|pre_tag| {
        let encrypted_iv = aes_key.encrypt_block(tag_iv.into_block_less_safe(), cpu_features);
        let tag = pre_tag ^ encrypted_iv;
        Tag(*tag.as_ref())
    }))
}

const AES_GCM_MAX_INPUT_LEN: u64 = super::max_input_len(BLOCK_LEN, 2);

#[cfg(test)]
mod tests {
    #[test]
    fn max_input_len_test() {
        // [NIST SP800-38D] Section 5.2.1.1. Note that [RFC 5116 Section 5.1] and
        // [RFC 5116 Section 5.2] have an off-by-one error in `P_MAX`.
        //
        // [NIST SP800-38D]:
        //    http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
        // [RFC 5116 Section 5.1]: https://tools.ietf.org/html/rfc5116#section-5.1
        // [RFC 5116 Section 5.2]: https://tools.ietf.org/html/rfc5116#section-5.2
        const NIST_SP800_38D_MAX_BITS: u64 = (1u64 << 39) - 256;
        assert_eq!(NIST_SP800_38D_MAX_BITS, 549_755_813_632u64);
        assert_eq!(
            super::AES_128_GCM.max_input_len * 8,
            NIST_SP800_38D_MAX_BITS
        );
        assert_eq!(
            super::AES_256_GCM.max_input_len * 8,
            NIST_SP800_38D_MAX_BITS
        );
    }
}
