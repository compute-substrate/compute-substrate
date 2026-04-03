// src/codec/mod.rs
//
// Consensus serialization settings.
// One place to lock bincode options so they cannot drift between modules.
//
// WARNING: Changing these settings can split consensus or
// corrupt DB compatibility. Treat as consensus-critical.

use bincode::Options;
use serde::{de::DeserializeOwned, Serialize};

pub type ConsensusBincodeError = bincode::Error;

#[derive(Clone, Copy, Debug, Default)]
pub struct ConsensusBincode;

impl ConsensusBincode {
    #[inline]
    fn opts(self) -> impl bincode::Options {
        // Deterministic + stable:
        // - fixed-int encoding (no varint)
        // - little endian
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
    }

    #[inline]
    pub fn serialize<T: Serialize>(self, v: &T) -> Result<Vec<u8>, ConsensusBincodeError> {
        self.opts().serialize(v)
    }

    #[inline]
    pub fn deserialize<T: DeserializeOwned>(
        self,
        bytes: &[u8],
    ) -> Result<T, ConsensusBincodeError> {
        self.opts().deserialize(bytes)
    }

    #[inline]
    pub fn serialized_size<T: Serialize>(self, v: &T) -> Result<u64, ConsensusBincodeError> {
        self.opts().serialized_size(v)
    }
}

#[inline]
pub fn consensus_bincode() -> ConsensusBincode {
    ConsensusBincode
}
