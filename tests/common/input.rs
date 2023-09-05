#![allow(non_snake_case)]
use serde::Deserialize;
use serde_json::from_str;

use std::{collections::HashMap, fs::File, io::Read};

#[derive(Debug, Deserialize)]
pub struct TestData {
    pub comment: String,
    pub sending: Vec<SendingData>,
    pub receiving: Vec<ReceivingData>,
}

#[derive(Debug, Deserialize)]
pub struct ReceivingData {
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


#[derive(Debug, Deserialize, PartialEq)]
pub struct OutputWithSignature {
    pub pubkey: String,
    pub signature: String

}

#[derive(Debug, Deserialize)]
pub struct ReceivingDataExpected {
    pub outputs: HashMap<String, Vec<OutputWithSignature>>,
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
    pub recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendingDataExpected {
    pub outputs: HashMap<String, Vec<String>>,
}

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("tests/resources/send_and_receive_test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}
