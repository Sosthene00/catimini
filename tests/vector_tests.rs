#![allow(non_snake_case)]
mod common;

#[cfg(test)]
mod tests {
    use std::collections::{HashSet, HashMap};
    use std::str::FromStr;
    use std::vec;

    use bitcoin::Network;

    use bitcoin::secp256k1::{SecretKey, Secp256k1, Scalar};

    use catimini::{CatiminiSender, SilentPaymentSender, CatiminiAddress, CatiminiReceiver};
    use silentpayments::receiving::{NULL_LABEL, Receiver, Label};
    use silentpayments::sending::SilentPaymentAddress;

    use crate::common::structs::{TestData, SendingData, ReceivingData};
    use crate::{
        common::Signer,
        common::utils::{read_file, decode_input_pub_keys, decode_outpoints, decode_priv_keys, calculate_tweak_data_for_recipient, decode_outputs_to_check},
    };

    pub fn get_test_vectors() -> Vec<TestData> {
        read_file()
    }

    fn test_sending(sending_cases: Vec<&SendingData>) {
        for sendingtest in sending_cases {
            let given = &sendingtest.given;

            let expected = &sendingtest.expected;

            let silent_addresses: Vec<CatiminiAddress> = given.recipients
                .iter()
                .map(|(a, _)| {
                CatiminiAddress::try_from(a.as_str()).unwrap()
                })
                .collect();

            let network = Network::Bitcoin;
            let mut new_silent_payment = SilentPaymentSender::new(network);

            let signer = Signer::new(decode_priv_keys(&given.input_privkeys), HashMap::new());

            let outpoints = decode_outpoints(&given.outpoints);

            new_silent_payment.add_outpoints(outpoints.into_iter().collect());

            new_silent_payment.add_addresses(silent_addresses).unwrap();

            let tweak = new_silent_payment.get_outpoints_hash().unwrap();

            let tweak_data = signer.tweak_aggregated_keys(&tweak); // This is implemented by the signer

            new_silent_payment.add_tweak_data(tweak_data);

            let alice = CatiminiSender::new_sp(new_silent_payment).unwrap(); 

            let outputs = alice.silent_payment_derive_send_keys().unwrap();

            let got_outputs: HashMap<String, Vec<String>> = 
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

            let expected_outputs: Vec<String> = expected.outputs
                .iter()
                .map(|(a, _)| {
                    a.to_owned()
                })
                .collect();

            for (_, keys) in got_outputs {
                assert!(keys.iter().all(|k| expected_outputs.contains(k)));
            }
        }
    }

    fn test_receiving(receiving_cases: Vec<&ReceivingData>) {
        for receivingtest in receiving_cases {
            let given = &receivingtest.given;
            let expected = &receivingtest.expected;

            let secp = Secp256k1::new();

            // 1. Create a new silent payment receiver
            let scan_privkey = SecretKey::from_str(&given.scan_privkey).unwrap();
            let spend_privkey = SecretKey::from_str(&given.spend_privkey).unwrap();

            let mut signer = Signer::new(vec![(scan_privkey, false), (spend_privkey, false)], HashMap::new());

            let mut sp_receiver = Receiver::new(0, scan_privkey.public_key(&secp), spend_privkey.public_key(&secp), false).unwrap();

            // 2. Register labels and create the catimi receiver for those labels
            let labels: Vec<String> = given.labels.iter().map(|(_, label)| label.to_owned()).collect();

            for label in labels {
                sp_receiver.add_label(label.try_into().unwrap()).unwrap();
            }

            let mut catimini_receiver = CatiminiReceiver::new_sp(sp_receiver);

            // 3. get the silent addresses
            let mut receiving_addresses = catimini_receiver.silent_payment_get_addresses().unwrap();
            receiving_addresses.insert(NULL_LABEL.as_string(), catimini_receiver.silent_payment_get_address_no_label().unwrap());

            let set1: HashSet<_> = receiving_addresses.iter().map(|r| r.1).collect();
            let set2: HashSet<_> = expected.addresses.iter().collect();

            assert_eq!(set1, set2);

            // 4. Check a tweak with some pubkeys from a transaction
            // First get the outpoints and keys
            let outpoints = decode_outpoints(&given.outpoints);
            let input_pubkeys = decode_input_pub_keys(&given.input_pubkeys);
            let output_keys = decode_outputs_to_check(&given.outputs);

            // then the tweak
            let tweak_data = calculate_tweak_data_for_recipient(&input_pubkeys, &outpoints);

            let ecdh_shared_secret = signer.tweak_with_scan_key(tweak_data);

            // now check the provided keys for matches
            let got_outputs: HashMap<Label, Vec<Scalar>> = catimini_receiver.silent_payment_derive_receive_keys(ecdh_shared_secret, output_keys).unwrap();

            let addr_tweaks: HashMap<SilentPaymentAddress, Vec<Scalar>> = got_outputs
                .into_iter()
                .flat_map(|(l, s)| {
                    let address = catimini_receiver
                        .silent_payment_get_address_with_label(&l.as_string())
                        .expect("This can't happen");
                    let address = SilentPaymentAddress::try_from(address).unwrap();
                    std::iter::once((address, s))
                })
                .collect();

            signer.add_tweaks(addr_tweaks);

            // 3. check a transaction for outputs that belong to us
            // We obtain a map of labels to 1 or n tweaks
            // It is easy to derive the pubkey and map each returned private key to an output
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

            let expected_outputs: Vec<String> = expected.outputs
                .iter()
                .map(|o| o.pubkey.to_owned())
                .collect();

            for (_, outputs) in res {
                assert!(outputs.iter().all(|x| expected_outputs.contains(&x.pubkey)));
            }
        }
    }

    #[test]
    fn process_test_case() {
        let test_cases = get_test_vectors();

        for case in &test_cases {
            eprintln!("test.comment = {:?}", case.comment);
            test_sending(case.sending.iter().collect());
        }

        for case in &test_cases {
            eprintln!("test.comment = {:?}", case.comment);
            test_receiving(case.receiving.iter().collect());
        }
    }
}
