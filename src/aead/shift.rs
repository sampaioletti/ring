// Copyright 2018 Brian Smith.
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

use super::inout::InOut;

#[cfg(target_arch = "x86")]
pub fn shift_full_blocks<'io, const BLOCK_LEN: usize>(
    mut in_out: super::inout::InOutBlocks<'io, BLOCK_LEN>,
    mut f: impl FnMut(&[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN],
) -> crate::polyfill::nonempty::Slice<'io, [u8; BLOCK_LEN]> {
    for i in 0..in_out.len().get() {
        let input: &[_] = in_out.input().into();
        let transformed = f(&input[i]);
        in_out.output_mut()[i].copy_from_slice(&transformed);
    }
    in_out.into_output()
}

pub fn shift_partial<const BLOCK_LEN: usize>(
    mut in_out: InOut<'_>,
    transform: impl FnOnce(&[u8]) -> [u8; BLOCK_LEN],
) {
    let in_out_len = in_out.len();
    debug_assert!(in_out_len < BLOCK_LEN);
    if in_out_len == 0 {
        return;
    }
    let block = transform(in_out.input());
    in_out.overwrite_at_start(&block);
}
