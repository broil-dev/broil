// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

use super::{decode_record, encode_record};
use crate::k3s::release::Refusal;
use serde_json::Value;

const KEYS: [&str; 7] = [
    "schema",
    "kind",
    "scope",
    "owner",
    "attempts_removed",
    "watermark_sequence",
    "chain_sha256",
];

pub fn encode(value: &Value) -> Result<Vec<u8>, Refusal> {
    encode_record(value, "host-history", &KEYS, 16_384)
}

pub fn decode(bytes: &[u8]) -> Result<Value, Refusal> {
    decode_record(bytes, encode)
}
