#![allow(non_snake_case)]
use serde::Deserialize;

use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
    pub supports_labels: bool,
    pub given: ReceivingDataGiven,
    pub expected: ReceivingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_pubkeys: Vec<String>,
    pub bip32_seed: String,
    pub scan_privkey: String,
    pub spend_privkey: String,
    pub labels: HashMap<String, String>,
    pub outputs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub addresses: Vec<String>,
    pub outputs: Vec<OutputWithSignature>,
}

#[derive(Debug, Deserialize)]
pub struct SendingData {
    pub given: SendingDataGiven,
    pub expected: SendingDataExpected,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataGiven {
    pub outpoints: Vec<(String, u32)>,
    pub input_privkeys: Vec<(String, bool)>,
    pub recipients: Vec<(String, f32)>,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: Vec<(String, f32)>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Clone)]
pub struct OutputWithSignature {
    pub pubkey: String,
    pub signature: String,
}
