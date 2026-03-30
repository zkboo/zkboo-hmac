// SPDX-License-Identifier: LGPL-3.0-or-later

//! HMAC (Hash-based Message Authentication Code) primitive for the [zkboo] crate.
//!
//! See <https://datatracker.ietf.org/doc/html/rfc2104> for details.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use zkboo::{
    backend::{Allocator, Backend, WordRef},
    word::Word,
};

/// Computes the HMAC for given key and message,
/// using the provided hash function and block size.
pub fn hmac<
    B: Backend,
    W: Word,
    const M: usize,
    H: FnMut(Allocator<B>, Vec<WordRef<B, u8>>) -> [WordRef<B, W>; M],
>(
    allocator: Allocator<B>,
    mut key: Vec<WordRef<B, u8>>,
    mut msg: Vec<WordRef<B, u8>>,
    mut hash_fn: H,
    block_size: usize,
) -> [WordRef<B, W>; M] {
    assert!(
        block_size * 8 >= M * W::WIDTH as usize,
        "blocksize must be at least output size"
    );
    if key.len() > block_size {
        let digest = hash_fn(allocator.clone(), key);
        key = digest
            .into_iter()
            .flat_map(WordRef::<B, W>::into_be_bytes)
            .collect();
    }
    if key.len() < block_size {
        // key.append(&mut allocator.alloc_vec(&vec![0u8; block_size - key.len()]));
        key.extend((0..block_size - key.len()).map(|_| allocator.alloc(0u8)));
    }
    let mut inner: Vec<WordRef<B, u8>> = key.iter().map(|w| w.clone() ^ 0x36).collect();
    let mut outer: Vec<WordRef<B, u8>> = key.into_iter().map(|w| w ^ 0x5c).collect();
    inner.append(&mut msg);
    let mut inner_digest: Vec<WordRef<B, u8>> = hash_fn(allocator.clone(), inner)
        .into_iter()
        .flat_map(WordRef::<B, W>::into_be_bytes)
        .collect();
    outer.append(&mut inner_digest);
    return hash_fn(allocator, outer);
}
