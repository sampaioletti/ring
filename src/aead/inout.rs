// Copyright 2024 Brian Smith.
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

use crate::error;
use crate::polyfill::{nonempty, slice};
use core::num::NonZeroUsize;
use core::ops::RangeFrom;

pub struct InOut<'io> {
    in_out: &'io mut [u8],
    src: RangeFrom<usize>,
}

impl<'io> InOut<'io> {
    pub fn new_in_place(in_out: &'io mut [u8]) -> Self {
        Self { in_out, src: 0.. }
    }

    pub fn new(in_out: &'io mut [u8], src: RangeFrom<usize>) -> Result<Self, Error> {
        match in_out.get(src.clone()) {
            Some(_) => Ok(Self { in_out, src }),
            None => Err(Error::Index),
        }
    }

    pub fn len(&self) -> usize {
        self.input().len()
    }

    pub fn input(&self) -> &[u8] {
        &self.in_out[self.src.clone()]
    }

    pub fn output_mut(&mut self) -> &mut [u8] {
        let len = self.len();
        &mut self.in_out[..len]
    }

    pub fn into_output(self) -> &'io mut [u8] {
        let len = self.len();
        &mut self.in_out[..len]
    }

    pub fn output_mut_ptr(&mut self) -> *mut u8 {
        self.output_mut().as_mut_ptr()
    }

    pub fn copy_within(self) -> &'io mut [u8] {
        if self.src.start != 0 {
            self.in_out.copy_within(self.src.clone(), 0);
        }
        self.into_output()
    }

    pub fn overwrite_at_start(&mut self, to_copy: &[u8]) {
        self.output_mut()
            .iter_mut()
            .zip(to_copy.iter())
            .for_each(|(o, i)| {
                *o = *i;
            });
    }

    #[cfg(target_arch = "aarch64")]
    pub fn all_chunks<const BLOCK_LEN: usize>(&mut self) -> Option<InOutBlocks<BLOCK_LEN>> {
        let len = self.len();
        let chunk_len = len - (len % BLOCK_LEN);
        let _: NonZeroUsize = NonZeroUsize::new(chunk_len / BLOCK_LEN)?;
        let in_out = InOut {
            in_out: &mut self.in_out[..(self.src.start + chunk_len)],
            src: self.src.clone(),
        };
        Some(InOutBlocks { in_out })
    }

    pub fn first_chunk<const STRIDE_BLOCKS: usize, const BLOCK_LEN: usize>(
        &mut self,
    ) -> Option<InOutBlocks<BLOCK_LEN>> {
        let chunk_len = self.chunk_len::<STRIDE_BLOCKS, BLOCK_LEN>();
        let _: NonZeroUsize = NonZeroUsize::new(chunk_len / BLOCK_LEN)?;
        let in_out = InOut {
            in_out: &mut self.in_out[..(self.src.start + chunk_len)],
            src: self.src.clone(),
        };
        Some(InOutBlocks { in_out })
    }

    pub fn after_first_chunk<const STRIDE_BLOCKS: usize, const BLOCK_LEN: usize>(self) -> Self {
        let chunk_len = self.chunk_len::<STRIDE_BLOCKS, BLOCK_LEN>();
        self.after(chunk_len)
    }

    fn chunk_len<const STRIDE_BLOCKS: usize, const BLOCK_LEN: usize>(&self) -> usize {
        let len = self.len() - (self.len() % BLOCK_LEN);
        core::cmp::min(len, STRIDE_BLOCKS * BLOCK_LEN)
    }

    pub fn after(self, chunk_len: usize) -> Self {
        let chunk_len = core::cmp::min(self.len(), chunk_len);
        Self {
            in_out: &mut self.in_out[chunk_len..],
            src: self.src,
        }
    }
}

/// Non-empty (non-zero-length) in-out of `BLOCK_LEN` chunks.
pub struct InOutBlocks<'io, const BLOCK_LEN: usize> {
    in_out: InOut<'io>,
}

impl<'io, const BLOCK_LEN: usize> InOutBlocks<'io, BLOCK_LEN> {
    pub fn len(&self) -> NonZeroUsize {
        self.input().len()
    }

    #[cfg(target_arch = "aarch64")]
    pub fn len_in_bytes(&self) -> NonZeroUsize {
        // The `unwrap` cannot fail; `self.len()` is a `NonZeroUsize`,
        // `BLOCK_LEN` cannot be zero since we divide by `BLOCK_LEN` to
        // construct `self`, and the multiplication cannot overflow
        // because `self` was constructed from an array of this size.
        NonZeroUsize::new(self.len().get() * BLOCK_LEN).unwrap()
    }

    pub fn input(&self) -> nonempty::Slice<[u8; BLOCK_LEN]> {
        let (full_blocks, leftover) = slice::as_chunks(self.in_out.input());
        debug_assert_eq!(leftover.len(), 0);
        // The unwrap won't fail because the constructor guarantees this.
        nonempty::Slice::new(full_blocks).unwrap()
    }

    pub fn into_output(self) -> nonempty::Slice<'io, [u8; BLOCK_LEN]> {
        let (full_blocks, leftover) = slice::as_chunks(self.in_out.into_output());
        debug_assert_eq!(leftover.len(), 0);
        // The unwrap won't fail because the constructor guarantees this.
        nonempty::Slice::new(full_blocks).unwrap()
    }

    #[cfg(target_arch = "x86")]
    pub fn output_mut(&mut self) -> &mut [[u8; BLOCK_LEN]] {
        let (full_blocks, leftover) = slice::as_chunks_mut(self.in_out.output_mut());
        debug_assert_eq!(leftover.len(), 0);
        full_blocks
    }

    pub fn output_mut_ptr(&mut self) -> *mut [u8; BLOCK_LEN] {
        self.in_out.output_mut_ptr().cast()
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Index,
}

impl From<Error> for error::Unspecified {
    fn from(_value: Error) -> Self {
        Self
    }
}
