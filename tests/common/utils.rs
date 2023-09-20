use std::collections::BTreeSet;
use std::{io::Write, io::Read, str::FromStr, fs::File};

use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey, Parity, Secp256k1, Scalar};
use bitcoin::{OutPoint, Txid};
use serde_json::from_str;

use super::structs::TestData;

pub fn read_file() -> Vec<TestData> {
    let mut file = File::open("tests/resources/test_vectors.json").unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).unwrap();
    from_str(&contents).unwrap()
}

pub fn decode_outpoints(outpoints: &Vec<(String, u32)>) -> BTreeSet<OutPoint> {
    outpoints
        .iter()
        .map(|(txid_str, vout)| OutPoint {
            txid: Txid::from_str(txid_str).unwrap(),
            vout: *vout,
        })
        .collect()
}

pub fn decode_priv_keys(input_priv_keys: &Vec<(String, bool)>) -> Vec<(SecretKey, bool)> {
    input_priv_keys
        .iter()
        .map(|(keystr, x_only)| {
            (SecretKey::from_str(keystr).unwrap(), *x_only)
        })
        .collect()
}

pub fn decode_input_pub_keys(input_pub_keys: &Vec<String>) -> Vec<PublicKey> {
    input_pub_keys
        .iter()
        .map(|x| match PublicKey::from_str(&x) {
            Ok(key) => key,
            Err(_) => {
                // we always assume even pairing for input public keys if they are omitted
                let x_only_public_key = XOnlyPublicKey::from_str(&x).unwrap();
                PublicKey::from_x_only_public_key(x_only_public_key, Parity::Even)
            }
        })
        .collect()
}

pub fn decode_outputs_to_check(outputs: &Vec<String>) -> Vec<XOnlyPublicKey> {
    outputs
        .iter()
        .map(|x| XOnlyPublicKey::from_str(x).unwrap())
        .collect()
}

pub fn decode_recipients(recipients: &Vec<(String, f32)>) -> Vec<String> {
    recipients
        .iter()
        .map(|(sp_addr_str, _)| sp_addr_str.to_owned())
        .collect()
}

pub fn get_a_sum_secret_keys(input: &Vec<(SecretKey, bool)>) -> SecretKey {
    let secp = Secp256k1::new();

    let mut negated_keys: Vec<SecretKey> = vec![];

    for (key, is_xonly) in input {
        let (_, parity) = key.x_only_public_key(&secp);

        if *is_xonly && parity == Parity::Odd {
            negated_keys.push(key.negate());
        } else {
            negated_keys.push(key.clone());
        }
    }

    let (head, tail) = negated_keys.split_first().unwrap();

    let result: SecretKey = tail
        .iter()
        .fold(*head, |acc, &item| acc.add_tweak(&item.into()).unwrap());

    result
}

pub fn get_A_sum_public_keys(input: &Vec<PublicKey>) -> PublicKey {
    let keys_refs: &Vec<&PublicKey> = &input.iter().collect();

    PublicKey::combine_keys(keys_refs).unwrap()
}

fn get_outpoints_hash(outpoints: BTreeSet<OutPoint>) -> [u8;32] {
    let mut engine = sha256::HashEngine::default();
    let mut bytes = [0u8;36];

    for outpoint in outpoints {
        let txid: [u8;32] = outpoint.txid.into_inner();
        let vout: [u8;4] = outpoint.vout.to_le_bytes();

        bytes[..32].copy_from_slice(&txid);
        bytes[32..].copy_from_slice(&vout);
        engine.write_all(&bytes);
    }


    sha256::Hash::from_engine(engine).into_inner()
}

pub fn calculate_tweak_data_for_recipient(
    input_pub_keys: &Vec<PublicKey>,
    outpoints: &BTreeSet<OutPoint>,
) -> PublicKey {
    let secp = Secp256k1::new();
    let A_sum = get_A_sum_public_keys(input_pub_keys);
    let outpoints_hash = Scalar::from_be_bytes(get_outpoints_hash(outpoints.clone())).unwrap();

    A_sum.mul_tweak(&secp, &outpoints_hash).unwrap()
}
