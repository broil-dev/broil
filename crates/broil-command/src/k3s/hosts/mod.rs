// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod archive;
pub(crate) mod index;
mod inflate;
pub(crate) mod local;
pub(crate) mod manifest;
mod upstream;

pub(crate) use super::state::{Failure, Result};

fn require(condition: bool, failure: Failure) -> Result<()> {
    if condition { Ok(()) } else { Err(failure) }
}

pub(crate) fn verify_archive(
    asset: &index::Asset,
    policy: Option<&index::Policy>,
    read: &mut dyn FnMut(&mut [u8]) -> Result<usize>,
) -> Result<()> {
    struct Reader<'a>(&'a mut dyn FnMut(&mut [u8]) -> Result<usize>);
    impl inflate::Source for Reader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize> {
            (self.0)(buffer)
        }
    }
    let mut walker = archive::Walker::new(asset)?;
    let mut encoded = 0u64;
    let mut sha = <sha2::Sha256 as sha2::Digest>::new();
    let mut counted = |buffer: &mut [u8]| -> Result<usize> {
        let count = read(buffer)?;
        encoded = encoded.checked_add(count as u64).ok_or(Failure::Bound)?;
        require(encoded <= asset.size, Failure::Integrity)?;
        sha2::Digest::update(&mut sha, &buffer[..count]);
        Ok(count)
    };
    match asset.format {
        index::Format::Raw => return Err(Failure::Configuration),
        index::Format::Tar => {
            let mut buffer = vec![0u8; 65_536];
            loop {
                let count = counted(&mut buffer)?;
                if count == 0 {
                    break;
                }
                walker.push(&buffer[..count])?;
            }
        }
        index::Format::TarGzip => {
            let mut sink = |bytes: &[u8]| walker.push(bytes);
            let decoded =
                inflate::gunzip(&mut Reader(&mut counted), asset.expanded_bytes, &mut sink)?;
            require(decoded == asset.expanded_bytes, Failure::Integrity)?;
        }
    }
    let digest: String = sha2::Digest::finalize(sha)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    require(
        encoded == asset.size && digest == asset.sha256,
        Failure::Integrity,
    )?;
    let walked = walker.finish()?;
    archive::verify(&walked, asset, policy)
}
