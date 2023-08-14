#![allow(non_snake_case)]
mod common;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bitcoin::{OutPoint, Network};

    use catimini::{CatiminiSender, SilentPaymentSender, CatiminiAddress, SilentPaymentReceiver};

    use crate::{
        common::input,
        common::Signer,
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

            let signer = Signer::new(decode_priv_keys(&given.input_privkeys));

            let outpoints = decode_outpoints(&given.outpoints);

            new_silent_payment.add_outpoints(outpoints);

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

        // for receivingtest in test_case.receiving {
        //     let given = receivingtest.given;
        //     let mut expected = receivingtest.expected;

        //     let (b_scan, b_spend, _, B_spend) =
        //         get_testing_silent_payment_key_pair(&given.bip32_seed);

        //     // 1. Create a new receiver
        //     // let mut sp_receiver = SilentPayment::new(0, b_scan, b_spend, IS_TESTNET).unwrap();
        //     let sp = SilentPayment::new(0, b_scan, b_spend, IS_TESTNET).unwrap();

        //     let mut sp_receiver = SilentPaymentReceiver::new_from_sp(sp);


        //     let labels = given.labels.iter().map(|l| l.1.to_owned()).collect();

        //     // 2. Register labels and take silent addresses
        //     let receiving_addresses = sp_receiver.0.get_receiving_addresses(labels).unwrap();

        //     let set1: HashSet<_> = receiving_addresses.iter().map(|r| r.1).collect();
        //     let set2: HashSet<_> = expected.addresses.iter().collect();

        //     assert_eq!(set1, set2);

        //     // can be even or odd !
        //     assert_eq!(got_outputs, given.outputs); // Actually I think this is kind of redundant, we already checked that the outputs were ok sender side

            // 3. check a transaction for outputs that belong to us
            // We obtain a map of labels to 1 or n private keys
            // let add_to_wallet = sp_receiver.scan_for_outputs(
            //     outpoints.clone(),
            //     given.input_pub_keys,
            //     outputs_to_check,
            // ).unwrap();

            // // It is easy to derive the pubkey and map each returned private key to an output
            // let privkeys: Vec<SecretKey> = add_to_wallet.iter().flat_map(|(_, list)| {
            //     let mut ret: Vec<SecretKey> = vec![];
            //     for l in list {
            //         ret.push(SecretKey::from_str(l).unwrap());
            //     }
            //     ret
            // })
            // .collect();

            // let mut res = verify_and_calculate_signatures(privkeys, b_spend).unwrap();

            // res.sort_by_key(|output| output.pub_key.clone());
            // expected.outputs.sort_by_key(|output| output.pub_key.clone());

            // assert_eq!(res, expected.outputs);
        // }
    }
}
