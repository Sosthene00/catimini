#![allow(non_snake_case)]
mod common;

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, HashMap};
    use std::str::FromStr;

    use bitcoin::Network;

    use bitcoin::util::bip32::ExtendedPrivKey;

    use bitcoin::hashes::hex::FromHex;

    use bitcoin::secp256k1::{SecretKey, Secp256k1};

    use catimini::{CatiminiSender, SilentPaymentSender, CatiminiAddress, SilentPaymentReceiver, CatiminiReceiver};
    use silentpayments::receiving::NULL_LABEL;
    use silentpayments::sending::SilentPaymentAddress;

    use crate::{
        common::{input, utils::decode_input_pub_keys},
        common::{Signer, utils::{calculate_tweak_data_for_recipient, decode_outputs_to_check}},
        common::utils::{decode_outpoints, decode_priv_keys},
    };

    const IS_TESTNET: bool = false;

    #[test]
    fn test_with_test_vectors() {
        let testdata = input::read_file();

        for test in testdata {
            process_test_case(test);
        }
    }

    fn process_test_case(test_case: input::TestData) {
        let mut got_outputs: HashMap<String, Vec<String>> = HashMap::new();
        // let mut outpoints: Vec<OutPoint> = vec![];
        println!("\n\ntest.comment = {:?}", test_case.comment);
        for sendingtest in test_case.sending {
            let given = sendingtest.given;

            let expected = sendingtest.expected;

            let silent_addresses: Vec<CatiminiAddress> = given.recipients.iter().map(|a| {
                CatiminiAddress::try_from(a.as_str()).unwrap()
            })
            .collect();

            // let mut fren = CatiminiFren::new(1, "bob".to_owned());

            // for (i, address) in silent_addresses.iter().enumerate() {
            //     let address_label = format!("silent address #{}", i);
            //     fren.add_address(address_label, address.to_string()).expect("Failed to add address to fren");
            // }

            let network = Network::Bitcoin;
            let mut new_silent_payment = SilentPaymentSender::new(network);

            let signer = Signer::new(decode_priv_keys(&given.input_privkeys), HashMap::new());

            let outpoints = decode_outpoints(&given.outpoints);

            new_silent_payment.add_outpoints(outpoints.into_iter().collect());

            new_silent_payment.add_addresses(silent_addresses).unwrap();

            let scan_pubkeys = new_silent_payment.get_scanpubkeys();

            let ecdh_keys = signer.compute_ecdh_shared_secret(scan_pubkeys.into_iter().collect()); // This is implemented by the signer

            new_silent_payment.add_ecdh_keys(ecdh_keys).unwrap();

            // check that there's no recipients without secret
            assert!(new_silent_payment.get_empty_scanpubkeys().len() == 0);

            let alice = CatiminiSender::new_sp(new_silent_payment).unwrap(); 

            let outputs = alice.silent_payment_derive_send_keys().unwrap();

            got_outputs = 
                outputs
                .into_iter()
                .map(|(a, ps)| {
                    let mut pubkeys: Vec<String> = vec![];
                    for p in ps {
                        pubkeys.push(p.to_string());
                    }
                    let recipient: String = a.into();
                    (recipient, pubkeys)
                })
                .collect();

            for (address, keys) in got_outputs {
                let expected = expected.outputs.get(&address).expect("Unexpected address in the output");
                assert_eq!(keys, *expected, "wrong keys for {}", address);
            }
        }

        for receivingtest in test_case.receiving {
            let given = receivingtest.given;
            let mut expected = receivingtest.expected;

            // 1. Create a new silent payment receiver
            let xprv = ExtendedPrivKey::new_master(Network::Bitcoin, &Vec::from_hex(&given.bip32_seed).unwrap()).unwrap();
            let mut sp_receiver = SilentPaymentReceiver::new(xprv.clone(), false).unwrap();

            // 2. Register labels and create the catimi receiver for those labels
            let labels: Vec<String> = given.labels.iter().map(|(_, label)| label.to_owned()).collect();

            sp_receiver.add_labels(labels).unwrap();

            let mut catimi_receiver = CatiminiReceiver::new_sp(sp_receiver);

            // 3. get the silent addresses
            let mut receiving_addresses = catimi_receiver.silent_payment_get_addresses().unwrap();
            receiving_addresses.insert(NULL_LABEL.as_string(), catimi_receiver.silent_payment_get_address_no_label().unwrap());

            let set1: HashSet<_> = receiving_addresses.iter().map(|r| r.1).collect();
            let set2: HashSet<_> = expected.outputs.keys().collect();

            assert_eq!(set1, set2);

            // 4. Check a tweak with some pubkeys from a transaction
            // First get the outpoints and keys
            let outpoints = decode_outpoints(&given.outpoints);
            let input_pubkeys = decode_input_pub_keys(&given.input_pubkeys);
            let output_keys = decode_outputs_to_check(&given.outputs);
            let no_label_address: SilentPaymentAddress = receiving_addresses.get(&NULL_LABEL.as_string()).unwrap().to_owned().try_into().unwrap();

            // then the tweak
            let tweak_data = calculate_tweak_data_for_recipient(&input_pubkeys, &outpoints);

            // now check the provided keys for matches
            let got_outputs = catimi_receiver.silent_payment_derive_receive_keys(tweak_data, output_keys).unwrap();

            // 3. check a transaction for outputs that belong to us
            // We obtain a map of labels to 1 or n private keys
            // It is easy to derive the pubkey and map each returned private key to an output
            let privkeys: HashMap<SilentPaymentAddress, Vec<SecretKey>> = got_outputs
                .iter()
                .flat_map(|(label, list)| {
                    let privkeys: Vec<SecretKey> = list
                        .into_iter()
                        .map(|l| *l)
                        .collect();
                    let address: SilentPaymentAddress = receiving_addresses.get(&label.as_string()).unwrap().as_str().try_into().unwrap();
                    let mut map = HashMap::new();
                    map.insert(address, privkeys);
                    map
                })
                .collect();

            let signer = Signer::new(vec![], privkeys);
            let msg = "message".to_owned();

            let res = signer.sign_msg(&msg).unwrap();

            for (address, sigs) in res.iter() {
                for s in sigs {
                    match Signer::verify_sig(&s.signature, &msg, &s.pubkey) {
                        true => continue,
                        false => {
                            let e = format!("Wrong signature for {}", address);
                            panic!("{}", e);
                        }
                    }
                }
            }

            assert_eq!(res, expected.outputs);
        }
    }
}
