// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use salsa20::{
    SalsaCore,
    cipher::{Block, StreamCipherCore, consts::U4},
};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::Error;

pub(super) const DEFAULT_LOG_N: u8 = 18;
const MAX_LOG_N: u8 = 22;
const BLOCK_BYTES: usize = 128 * 8;

struct Scratch {
    memory: Zeroizing<Vec<u8>>,
    block: Zeroizing<[u8; BLOCK_BYTES]>,
    temp: Zeroizing<[u8; BLOCK_BYTES]>,
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.memory.as_mut_slice().zeroize();
        self.block.zeroize();
        self.temp.zeroize();

    }
}

pub(super) fn hkdf(key: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let (prk, expand) = Hkdf::<Sha256>::extract(Some(salt), key);
    let _prk = Zeroizing::new(prk);
    let mut output = Zeroizing::new([0; 32]);
    expand
        .expand(info, &mut *output)
        .expect("fixed HKDF output length");
    output
}

pub(super) fn parse_work_factor(text: &str) -> Result<u8, Error> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(Error::InvalidHeader);
    }
    let value: u8 = text.parse().map_err(|_| Error::WorkFactor)?;
    if !(1..=MAX_LOG_N).contains(&value) {
        return Err(Error::WorkFactor);
    }
    Ok(value)
}

pub(super) fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if !(1..=MAX_LOG_N).contains(&log_n) {
        return Err(Error::WorkFactor);
    }
    let n = 1usize
        .checked_shl(u32::from(log_n))
        .ok_or(Error::Allocation)?;
    let size = n.checked_mul(BLOCK_BYTES).ok_or(Error::Allocation)?;
    let mut memory = Zeroizing::new(Vec::new());
    memory
        .try_reserve_exact(size)
        .map_err(|_| Error::Allocation)?;
    memory.resize(size, 0);
    let mut scratch = Scratch {
        memory,
        block: Zeroizing::new([0; BLOCK_BYTES]),
        temp: Zeroizing::new([0; BLOCK_BYTES]),
    };
    let Scratch {
        memory,
        block,
        temp,
    } = &mut scratch;
    pbkdf2_hmac::<Sha256>(password, salt, 1, &mut **block);
    for saved in memory.chunks_exact_mut(BLOCK_BYTES) {
        saved.copy_from_slice(&**block);
        block_mix(block, temp);
        std::mem::swap(block, temp);
    }
    for _ in 0..n {
        let index = u32::from_le_bytes(
            block[BLOCK_BYTES - 64..BLOCK_BYTES - 60]
                .try_into()
                .expect("fixed block"),
        ) as usize
            & (n - 1);
        for (byte, saved) in block
            .iter_mut()
            .zip(&memory[index * BLOCK_BYTES..][..BLOCK_BYTES])
        {
            *byte ^= saved;
        }
        block_mix(block, temp);
        std::mem::swap(block, temp);
    }
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(password, &**block, 1, &mut *output);
    Ok(output)
}

fn block_mix(input: &[u8; BLOCK_BYTES], output: &mut [u8; BLOCK_BYTES]) {
    let mut words = Zeroizing::new([0u32; 16]);
    let mut mixed = Zeroizing::new(Block::<SalsaCore<U4>>::default());
    mixed.copy_from_slice(&input[BLOCK_BYTES - 64..]);
    for (i, part) in input.chunks_exact(64).enumerate() {
        for (word, (a, b)) in words
            .iter_mut()
            .zip(mixed.chunks_exact(4).zip(part.chunks_exact(4)))
        {
            *word = u32::from_le_bytes(a.try_into().expect("word"))
                ^ u32::from_le_bytes(b.try_into().expect("word"));
        }
        let mut core = SalsaCore::<U4>::from_raw_state(*words);
        core.write_keystream_block(&mut mixed);
        let offset = (i / 2 + (i % 2) * 8) * 64;
        output[offset..offset + 64].copy_from_slice(&mixed);
    }
}
