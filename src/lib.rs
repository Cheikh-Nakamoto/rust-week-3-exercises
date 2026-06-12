use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        // TODO: Construct a CompactSize from a u64 value
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {

        // TODO: Encode according to Bitcoin's CompactSize format:
        // [0x00–0xFC] => 1 byte
        // [0xFDxxxx] => 0xFD + u16 (2 bytes)
        // [0xFExxxxxxxx] => 0xFE + u32 (4 bytes)
        // [0xFFxxxxxxxxxxxxxxxx] => 0xFF + u64 (8 bytes)
        let mut bytes = Vec::new();
        match self.value {
            0..=0xFC => bytes.push(self.value as u8),
            0xFD..=0xFFFF => {
                bytes.push(0xFD);
                bytes.extend_from_slice(&(self.value as u16).to_le_bytes());
            }
            0x10000..=0xFFFFFFFF => {
                bytes.push(0xFE);
                bytes.extend_from_slice(&(self.value as u32).to_le_bytes());
            }
            _ => {
                bytes.push(0xFF);
                bytes.extend_from_slice(&self.value.to_le_bytes());
            }
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Decode CompactSize, returning value and number of bytes consumed.
        // First check if bytes is empty.
        // Check that enough bytes are available based on prefix.
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }
        let first_byte = bytes[0];
        match first_byte {
            0x00..=0xFC => Ok((CompactSize { value: first_byte as u64 }, 1)),
            0xFD => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);    
                }
                let value = u16::from_le_bytes(bytes[1..3].try_into().unwrap()) as u64;
                Ok((CompactSize { value }, 3))
            }
            0xFE => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u32::from_le_bytes(bytes[1..5].try_into().unwrap()) as u64;
                Ok((CompactSize { value }, 5))
            }
            0xFF => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let value = u64::from_le_bytes(bytes[1..9].try_into().unwrap());
                Ok((CompactSize { value }, 9))
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO: Serialize as a hex-encoded string (32 bytes => 64 hex characters)
            let hex_string = hex::encode(self.0);
            serializer.serialize_str(&hex_string)
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // TODO: Parse hex string into 32-byte array
        // Use `hex::decode`, validate length = 32
        let hex_string = String::deserialize(deserializer)?;
        let byte = hex::decode(hex_string).map_err(|err | serde::de::Error::custom(format!("Invalid hex string for Txid: {}", err)))?;
        if byte.len() != 32 {
            return Err(serde::de::Error::custom("Invalid length for Txid"));
        }
        let mut txid = [0; 32];
        txid.copy_from_slice(&byte);
        Ok(Txid(txid))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        // TODO: Create an OutPoint from raw txid bytes and output index
        OutPoint { txid: Txid(txid), vout }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Serialize as: txid (32 bytes) + vout (4 bytes, little-endian)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.txid.0);
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Deserialize 36 bytes: txid[0..32], vout[32..36]
        // Return error if insufficient bytes
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let txid = Txid(bytes[0..32].try_into().unwrap());
        let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        Ok((OutPoint { txid, vout }, 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        // TODO: Simple constructor
        Script { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Prefix with CompactSize (length), then raw bytes
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CompactSize { value: self.bytes.len() as u64 }.to_bytes());
        bytes.extend_from_slice(&self.bytes);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Parse CompactSize prefix, then read that many bytes
        // Return error if not enough bytes
        let compacte_size = CompactSize::from_bytes(bytes).map_err(|_| BitcoinError::InsufficientBytes)?;
        let total_size = compacte_size.1 + compacte_size.0.value as usize;
        if bytes.len() < total_size {
            return Err(BitcoinError::InsufficientBytes);
        }
        let script_bytes = bytes[compacte_size.1..total_size].to_vec();
        Ok((Script { bytes: script_bytes }, total_size))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        // TODO: Allow &Script to be used as &[u8]
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        // TODO: Basic constructor
        TransactionInput { previous_output, script_sig, sequence }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Serialize: OutPoint + Script (with CompactSize) + sequence (4 bytes LE)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.previous_output.to_bytes());
        bytes.extend_from_slice(&self.script_sig.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Deserialize in order:
        // - OutPoint (36 bytes)
        // - Script (with CompactSize)
        // - Sequence (4 bytes)
        let (previous_output, outpoint_size) = OutPoint::from_bytes(bytes)?;
        let (script_sig, script_size) = Script::from_bytes(&bytes[outpoint_size..])?;
        let total_size = outpoint_size + script_size + 4;
        if bytes.len() < total_size {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence = u32::from_le_bytes(bytes[outpoint_size + script_size..total_size].try_into().unwrap());
        Ok((TransactionInput { previous_output, script_sig, sequence }, total_size))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        // TODO: Construct a transaction from parts
        BitcoinTransaction { version, inputs, lock_time }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        // TODO: Format:
        // - version (4 bytes LE)
        // - CompactSize (number of inputs)
        // - each input serialized
        // - lock_time (4 bytes LE)
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&CompactSize { value: self.inputs.len() as u64 }.to_bytes());
        for input in &self.inputs {
            bytes.extend_from_slice(&input.to_bytes());
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        // TODO: Read version, CompactSize for input count
        // Parse inputs one by one
        // Read final 4 bytes for lock_time
        if bytes.len() < 8 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let (input_count, input_count_size) = CompactSize::from_bytes(&bytes[4..])?;
        let mut inputs = Vec::new();
        let mut offset = 4 + input_count_size;
        for _ in 0..input_count.value {
            let (input, input_size) = TransactionInput::from_bytes(&bytes[offset..])?;
            inputs.push(input);
            offset += input_size;
        }
        let lock_time = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        Ok((BitcoinTransaction { version, inputs, lock_time }, offset + 4))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TODO: Format a user-friendly string showing version, inputs, lock_time
        // Display scriptSig length and bytes, and previous output info
        write!(f, "BitcoinTransaction {{ version: {}, lock_time: {}, inputs: [", self.version, self.lock_time)?;
        for input in &self.inputs {
            write!(f, "{{ previous_output: (txid: {}, vout: {}), script_sig: {} bytes, sequence: {} }}, ", hex::encode(input.previous_output.txid.0), input.previous_output.vout, input.script_sig.len(), input.sequence)?;
        }
        write!(f, "] }}")
    }
}