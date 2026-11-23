// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{Failure, Result, require};

const INPUT_CHUNK: usize = 65_536;
const WINDOW: usize = 32_768;
const OUTPUT: usize = 131_072;

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

pub(super) trait Source {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize>;
}

struct Bits<'a, S: Source> {
    source: &'a mut S,
    buffer: Vec<u8>,
    position: usize,
    filled: usize,
    finished: bool,
    accumulator: u64,
    count: u32,
    consumed: u64,
}

impl<S: Source> Bits<'_, S> {
    fn refill(&mut self) -> Result<bool> {
        if self.finished {
            return Ok(false);
        }
        let read = self.source.read(&mut self.buffer)?;
        if read == 0 {
            self.finished = true;
            return Ok(false);
        }
        self.consumed = self
            .consumed
            .checked_add(read as u64)
            .ok_or(Failure::Bound)?;
        self.position = 0;
        self.filled = read;
        Ok(true)
    }

    fn byte(&mut self) -> Result<Option<u8>> {
        if self.position == self.filled && !self.refill()? {
            return Ok(None);
        }
        let value = self.buffer[self.position];
        self.position += 1;
        Ok(Some(value))
    }

    fn need(&mut self, wanted: u32) -> Result<()> {
        while self.count < wanted {
            match self.byte()? {
                Some(value) => {
                    self.accumulator |= u64::from(value) << self.count;
                    self.count += 8;
                }
                None => return Ok(()),
            }
        }
        Ok(())
    }

    fn bits(&mut self, wanted: u32) -> Result<u32> {
        self.need(wanted)?;
        require(self.count >= wanted, Failure::Integrity)?;
        let value = (self.accumulator & ((1u64 << wanted) - 1)) as u32;
        self.accumulator >>= wanted;
        self.count -= wanted;
        Ok(value)
    }

    fn align(&mut self) {
        let drop = self.count % 8;
        self.accumulator >>= drop;
        self.count -= drop;
    }

    fn aligned_byte(&mut self) -> Result<u8> {
        self.align();
        Ok(self.bits(8)? as u8)
    }

    fn at_end(&mut self) -> Result<bool> {
        self.align();
        if self.count > 0 {
            return Ok(false);
        }
        if self.position < self.filled {
            return Ok(false);
        }
        Ok(!self.refill()?)
    }
}

struct Table {
    entries: Vec<u16>,
    bits: u32,
}

impl Table {
    fn build(lengths: &[u8], single: bool) -> Result<Self> {
        let bits = u32::from(lengths.iter().copied().max().unwrap_or(0));
        require(bits <= 15, Failure::Integrity)?;
        if bits == 0 {
            return Ok(Self {
                entries: Vec::new(),
                bits: 0,
            });
        }
        let mut counts = [0u32; 16];
        for &length in lengths {
            counts[usize::from(length)] += 1;
        }
        counts[0] = 0;
        let mut left = 1u32;
        for count in &counts[1..] {
            left = left.checked_shl(1).ok_or(Failure::Integrity)?;
            left = left.checked_sub(*count).ok_or(Failure::Integrity)?;
        }
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for length in 1..=15 {
            code = (code + counts[length - 1]) << 1;
            next[length] = code;
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(1usize << bits)
            .map_err(|_| Failure::Bound)?;
        entries.resize(1usize << bits, 0);
        for (symbol, &length) in lengths.iter().enumerate() {
            if length == 0 {
                continue;
            }
            let length = u32::from(length);
            let assigned = next[length as usize];
            next[length as usize] += 1;
            let mut reversed = 0u32;
            for index in 0..length {
                reversed |= ((assigned >> index) & 1) << (length - 1 - index);
            }
            let entry =
                u16::try_from((symbol << 4) | length as usize).map_err(|_| Failure::Integrity)?;
            let mut fill = reversed as usize;
            while fill < entries.len() {
                entries[fill] = entry;
                fill += 1usize << length;
            }
        }
        require(
            left == 0 || (single && bits == 1 && counts[1] == 1),
            Failure::Integrity,
        )?;
        Ok(Self { entries, bits })
    }

    fn decode<S: Source>(&self, bits: &mut Bits<'_, S>) -> Result<u16> {
        require(self.bits > 0, Failure::Integrity)?;
        bits.need(self.bits)?;
        let available = bits.count.min(self.bits);
        let index = (bits.accumulator & ((1u64 << self.bits) - 1)) as usize;
        let entry = self.entries[index];
        let length = u32::from(entry & 15);
        require(length > 0 && length <= available, Failure::Integrity)?;
        bits.accumulator >>= length;
        bits.count -= length;
        Ok(entry >> 4)
    }
}

struct Output<'a> {
    sink: &'a mut dyn FnMut(&[u8]) -> Result<()>,
    buffer: Vec<u8>,
    total: u64,
    limit: u64,
}

impl Output<'_> {
    fn push(&mut self, byte: u8) -> Result<()> {
        self.total = self.total.checked_add(1).ok_or(Failure::Bound)?;
        require(self.total <= self.limit, Failure::Bound)?;
        self.buffer.push(byte);
        if self.buffer.len() == OUTPUT {
            self.flush(false)?;
        }
        Ok(())
    }

    fn copy(&mut self, distance: usize, length: usize) -> Result<()> {
        require(
            distance >= 1 && distance <= self.buffer.len(),
            Failure::Integrity,
        )?;
        for _ in 0..length {
            let byte = self.buffer[self.buffer.len() - distance];
            self.push(byte)?;
        }
        Ok(())
    }

    fn flush(&mut self, all: bool) -> Result<()> {
        let keep = if all {
            0
        } else {
            WINDOW.min(self.buffer.len())
        };
        let emit = self.buffer.len() - keep;
        if emit > 0 {
            (self.sink)(&self.buffer[..emit])?;
            self.buffer.copy_within(emit.., 0);
            self.buffer.truncate(keep);
        }
        Ok(())
    }
}

fn crc32(table: &[u32; 256], crc: u32, bytes: &[u8]) -> u32 {
    let mut crc = !crc;
    for &byte in bytes {
        crc = table[usize::from((crc as u8) ^ byte)] ^ (crc >> 8);
    }
    !crc
}

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 == 1 {
                0xedb8_8320 ^ (value >> 1)
            } else {
                value >> 1
            };
        }
        *entry = value;
    }
    table
}

fn lengths<S: Source>(bits: &mut Bits<'_, S>) -> Result<(Table, Table)> {
    let literals = bits.bits(5)? as usize + 257;
    let distances = bits.bits(5)? as usize + 1;
    let codes = bits.bits(4)? as usize + 4;
    require(literals <= 286 && distances <= 30, Failure::Integrity)?;
    let mut code_lengths = [0u8; 19];
    for &index in CODE_LENGTH_ORDER.iter().take(codes) {
        code_lengths[index] = bits.bits(3)? as u8;
    }
    let code_table = Table::build(&code_lengths, false)?;
    let mut all = [0u8; 316];
    let mut filled = 0;
    while filled < literals + distances {
        let symbol = code_table.decode(bits)?;
        let (value, repeat) = match symbol {
            0..=15 => (symbol as u8, 1usize),
            16 => {
                require(filled > 0, Failure::Integrity)?;
                (all[filled - 1], 3 + bits.bits(2)? as usize)
            }
            17 => (0, 3 + bits.bits(3)? as usize),
            _ => (0, 11 + bits.bits(7)? as usize),
        };
        require(filled + repeat <= literals + distances, Failure::Integrity)?;
        for _ in 0..repeat {
            all[filled] = value;
            filled += 1;
        }
    }
    require(all[256] != 0, Failure::Integrity)?;
    Ok((
        Table::build(&all[..literals], true)?,
        Table::build(&all[literals..literals + distances], true)?,
    ))
}

fn fixed() -> Result<(Table, Table)> {
    let mut literal = [0u8; 288];
    for (symbol, length) in literal.iter_mut().enumerate() {
        *length = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    Ok((
        Table::build(&literal, true)?,
        Table::build(&[5u8; 32], true)?,
    ))
}

fn block<S: Source>(
    bits: &mut Bits<'_, S>,
    out: &mut Output<'_>,
    tables: &(Table, Table),
) -> Result<()> {
    loop {
        let symbol = tables.0.decode(bits)?;
        match symbol {
            0..=255 => out.push(symbol as u8)?,
            256 => return Ok(()),
            257..=285 => {
                let index = usize::from(symbol - 257);
                let length = usize::from(LENGTH_BASE[index])
                    + bits.bits(u32::from(LENGTH_EXTRA[index]))? as usize;
                let code = usize::from(tables.1.decode(bits)?);
                require(code < 30, Failure::Integrity)?;
                let distance = usize::from(DISTANCE_BASE[code])
                    + bits.bits(u32::from(DISTANCE_EXTRA[code]))? as usize;
                out.copy(distance, length)?;
            }
            _ => return Err(Failure::Integrity),
        }
    }
}

fn stored<S: Source>(bits: &mut Bits<'_, S>, out: &mut Output<'_>) -> Result<()> {
    bits.align();
    let length = bits.bits(16)?;
    let complement = bits.bits(16)?;
    require(length == !complement & 0xffff, Failure::Integrity)?;
    for _ in 0..length {
        out.push(bits.bits(8)? as u8)?;
    }
    Ok(())
}

pub(super) fn gunzip<S: Source>(
    source: &mut S,
    limit: u64,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<u64> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(INPUT_CHUNK)
        .map_err(|_| Failure::Bound)?;
    buffer.resize(INPUT_CHUNK, 0);
    let mut bits = Bits {
        source,
        buffer,
        position: 0,
        filled: 0,
        finished: false,
        accumulator: 0,
        count: 0,
        consumed: 0,
    };
    let table = crc_table();
    let mut crc = 0u32;
    let mut checked = |bytes: &[u8]| -> Result<()> {
        crc = crc32(&table, crc, bytes);
        sink(bytes)
    };
    let mut output = Vec::new();
    output
        .try_reserve_exact(OUTPUT)
        .map_err(|_| Failure::Bound)?;
    let mut out = Output {
        sink: &mut checked,
        buffer: output,
        total: 0,
        limit,
    };
    require(
        bits.aligned_byte()? == 0x1f && bits.aligned_byte()? == 0x8b && bits.aligned_byte()? == 8,
        Failure::Integrity,
    )?;
    let flags = bits.aligned_byte()?;
    require(flags & 0xe0 == 0, Failure::Integrity)?;
    for _ in 0..6 {
        bits.aligned_byte()?;
    }
    if flags & 4 != 0 {
        let length = u32::from(bits.aligned_byte()?) | (u32::from(bits.aligned_byte()?) << 8);
        for _ in 0..length {
            bits.aligned_byte()?;
        }
    }
    for flag in [8u8, 16] {
        if flags & flag != 0 {
            let mut count = 0u32;
            while bits.aligned_byte()? != 0 {
                count += 1;
                require(count <= 4096, Failure::Bound)?;
            }
        }
    }
    if flags & 2 != 0 {
        bits.aligned_byte()?;
        bits.aligned_byte()?;
    }
    loop {
        let last = bits.bits(1)? == 1;
        match bits.bits(2)? {
            0 => stored(&mut bits, &mut out)?,
            1 => block(&mut bits, &mut out, &fixed()?)?,
            2 => {
                let tables = lengths(&mut bits)?;
                block(&mut bits, &mut out, &tables)?;
            }
            _ => return Err(Failure::Integrity),
        }
        if last {
            break;
        }
    }
    out.flush(true)?;
    let total = out.total;
    drop(out);
    bits.align();
    let mut trailer = [0u8; 8];
    for byte in &mut trailer {
        *byte = bits.bits(8)? as u8;
    }
    require(
        u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]) == crc
            && u64::from(u32::from_le_bytes([
                trailer[4], trailer[5], trailer[6], trailer[7],
            ])) == total & 0xffff_ffff
            && bits.at_end()?,
        Failure::Integrity,
    )?;
    Ok(total)
}

