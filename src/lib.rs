pub mod error;
pub mod address;
pub mod sender;

use std::collections::HashMap;
use std::vec;
use std::str::FromStr;

use bitcoin::{OutPoint, Network};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey, Scalar};

use silentpayments::receiving::{Receiver, Label, NULL_LABEL};

use error::Error;
pub use address::CatiminiAddress;
pub use sender::{SilentPaymentSender, CatiminiSender};

pub struct CatiminiFren {
    id: u32,
    name: String,
    received_from: Vec<OutPoint>,
    sent_to: Vec<OutPoint>,
    addresses: HashMap<String, CatiminiAddress>
}

impl CatiminiFren {
    fn new(id: u32, name: String) -> Self {
        Self { 
            id, 
            name, 
            received_from: vec![],
            sent_to: vec![],
            addresses: HashMap::new()
        }
    }

    fn add_address(&mut self, label: String, address: String) -> Result<(), Error>{
        self.addresses.insert(label, address.try_into()?);
        Ok(())
    }

    fn get_addresses(&self) -> HashMap<String, CatiminiAddress> {
        self.addresses.clone()
    }

    fn get_address_by_label(&self, label: String) -> Option<CatiminiAddress> {
        self.addresses.get(&label).cloned()
    }
}

pub struct Bip47Receiver;

pub struct PrivatePaymentReceiver;

pub struct SilentPaymentReceiver(Receiver);

impl SilentPaymentReceiver {
    pub fn new(xprv: ExtendedPrivKey, is_testnet: bool) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        if xprv.network == Network::Bitcoin && is_testnet {
            let e = format!("Can't create receiver, xprv network is {} and is_testnet {}", xprv.network, is_testnet);
            return Err(Error::InvalidNetwork(e));
        }

        let scan_path = DerivationPath::from_str("m/352'/0'/0'/1'/0")?;
        let spend_path = DerivationPath::from_str("m/352'/0'/0'/0'/0")?;

        let scan_key = xprv.derive_priv(&secp, &scan_path)?;
        let spend_key = xprv.derive_priv(&secp, &spend_path)?;

        Ok(Self {
            0: Receiver::new(
                0, 
                scan_key.private_key.public_key(&secp), 
                spend_key.private_key.public_key(&secp), 
                is_testnet
            ).expect("Couldn't create SilentPayment")
        })
    }

    pub fn add_labels(&mut self, labels: Vec<String>) -> Result<Vec<String>, Error> {
        let mut result: Vec<String> = vec![];
        for label in labels {
            let added = self.0.add_label(label.clone().try_into()?)?;
            if added {
                result.push(label);
            }
        }

        Ok(result)
    }

    pub fn list_labels(&self) -> Vec<String> {
        self.0.list_labels()
            .into_iter()
            .map(|l| l.as_string())
            .collect()
    }
}

pub enum CatiminiReceiver {
    Bip47(Bip47Receiver),
    PrivatePayment(PrivatePaymentReceiver),
    SilentPayment(Receiver),
}

impl CatiminiReceiver {
    pub fn new_sp(sp: Receiver) -> Self {
        Self::SilentPayment(sp)
    }

    pub fn get_protocol(&self) -> &str {
        match self {
            CatiminiReceiver::Bip47(_) => "bip47",
            CatiminiReceiver::PrivatePayment(_) => "private payment",
            CatiminiReceiver::SilentPayment(_) => "silent payment"
        }
    }

    pub fn silent_payment_get_address_no_label(&self) -> Result<String, Error> {
        match self {
            CatiminiReceiver::SilentPayment(b) => {
                Ok(b.get_receiving_address())
            },
            _ => { 
                Err(Error::InvalidProtocol(format!("Expected Silent Payment, got {}", self.get_protocol()))) 
            }
        }
    }

    pub fn silent_payment_get_addresses(&mut self) -> Result<HashMap<String, String>, Error> {
        match self {
            CatiminiReceiver::SilentPayment(b) => {
                let labels = b.list_labels();
                let mut result: HashMap<String, String> = HashMap::new();

                for label in labels {
                    // Fetch the address for the label.
                    match b.get_receiving_address_for_label(&label) {
                        Ok(address) => {
                            result.insert(label.as_string(), address);
                        },
                        Err(_) => {
                            result.insert(label.as_string(), "No valid keys for this label".to_owned());
                        }
                    }
                }

                Ok(result)
            }
            _ => { 
                Err(Error::InvalidProtocol(format!("Expected Silent Payment, got {}", self.get_protocol()))) 
            }
        }
    }

    pub fn silent_payment_get_address_with_label(&mut self, label: &str) -> Result<String, Error> {
        match self {
            CatiminiReceiver::SilentPayment(b) => {
                if label == NULL_LABEL.as_string() {
                    Ok(b.get_receiving_address())
                } else {
                    Ok(b.get_receiving_address_for_label(&Label::try_from(label)?)?)
                }
            },
            _ => Err(Error::InvalidProtocol(format!("Expected Silent Payment, got {}", self.get_protocol()))) 
        }
    }

    pub fn silent_payment_derive_receive_keys(&mut self, tweak_data: PublicKey, candidate_pubkeys: Vec<XOnlyPublicKey>) -> Result<HashMap<Label, Vec<Scalar>>, Error> 
    {
        match self {
            CatiminiReceiver::SilentPayment(b) => {
                let key_map = b.scan_transaction_with_labels(&tweak_data, candidate_pubkeys)?;
                Ok(key_map)
            }
            _ => { 
                return Err(Error::InvalidProtocol(format!("Expected Silent Payment, got {}", self.get_protocol())));
            }
        }
    }

    pub fn bip47_derive_receive_keys(self, start: u32, end: u32) -> Box<dyn Fn(u32, u32) -> Result<PublicKey, Error>> {
        unimplemented!();
    }

    pub fn private_payment_derive_receive_keys(self, start: u32, end: u32) -> Box<dyn Fn(u32, u32) -> Result<PublicKey, Error>> {
        unimplemented!();
    }
}
#[cfg(test)]
mod tests {
    use std::{str::FromStr, collections::{HashSet, HashMap}};

    use bitcoin::{util::bip32::{ExtendedPrivKey, Error as Bip32Error}, Network, OutPoint, secp256k1::{SecretKey, PublicKey, Secp256k1}};
    use bitcoin::hashes::hex::FromHex;

    use crate::{CatiminiSender, CatiminiFren, CatiminiAddress, SilentPaymentSender, SilentPaymentReceiver};

    fn new_master_from_seed(seed: &str) -> Result<ExtendedPrivKey, Bip32Error> {
        println!("seed: {}", seed);
        let s: Vec<u8> = Vec::from_hex(seed).unwrap();
        
        ExtendedPrivKey::new_master(Network::Bitcoin, &s)
    }

    /// Alias Alice
    fn new_sender() -> Result<ExtendedPrivKey, Bip32Error> {
        // From the bip47 test vectors
        new_master_from_seed("64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a")
    }

    /// Alias Bob
    fn new_receiver() -> Result<ExtendedPrivKey, Bip32Error> {
        // From the bip47 test vectors
        new_master_from_seed("87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110")
    }

    #[test]
    fn new_sp_receiver() {
        // wpkh(tprv8ZgxMBicQKsPdFqK4WfjWAFWHwB8PcAeoUvw3ELgLBXuaW4H1R2Ryd2Wsn237ouWxaTRHfakZor9cvQGu9zf6krEgjjPZCUvRkLhYR8DH3x/84'/1'/0'/0/*)#0xggqz9c
        let bob_xprv = new_receiver().unwrap();
        let mut bob_silent = SilentPaymentReceiver::new(bob_xprv, true).unwrap();

        let label = format!("{:064x}", 1);
        let bob_address = bob_silent.0.get_receiving_address_for_label(&label.try_into().unwrap()).unwrap();
        println!("{:?}", bob_address);

        // Alice sends Bob money from whatever transaction
        // Bob only has the transaction and knows nothing else, but must be able to find his ouputs
        // I need tests with multiple outputs to Bob and none to Bob
    }

    #[test]
    fn new_fren() {
        let id = 1;
        let name = "bob".to_owned();

        let mut fren = CatiminiFren::new(id, name);

        fren.add_address("bob's silent address".to_owned(), "tsp1qq26w2fwvkd526kvu573gp7xrwd497uuc6masqy787jknkfmhq3f6uqakak4dtkx3zj9mp4xa75uxvdalwa8jmljytgyvl2tl5f8j4e0a9yx9qpds".to_owned()).expect("Failed to add address to fren");

        fren.add_address("bob's channel donation".to_owned(), "tsp1qq26w2fwvkd526kvu573gp7xrwd497uuc6masqy787jknkfmhq3f6uq5nnaqg0729e902terdq8me0z2ylw7jfs5m8syk0sq6slqh2wwafcgnz3jg".to_owned()).expect("Failed to add address to fren");

        let bob_nyms = fren.get_addresses();
        for (l, n) in bob_nyms {
            println!("{}: {}", l, n);
        }
    }

    #[test]
    fn new_sp_address() {
        let a = CatiminiAddress::SilentPayment("tsp1qq26w2fwvkd526kvu573gp7xrwd497uuc6masqy787jknkfmhq3f6uq5nnaqg0729e902terdq8me0z2ylw7jfs5m8syk0sq6slqh2wwafcgnz3jg".try_into().unwrap());

        println!("{}", a);
    }

    fn ecdh(scan_pubkeys: HashSet<PublicKey>) -> HashMap<PublicKey, PublicKey> {
        let secp = Secp256k1::new();

        let pk1 = SecretKey::from_str("7bab8a488a13ed393e28650c3f117558ef62bb2e41e98bd1a38e8e37536305b7").unwrap();
        let pk2 = SecretKey::from_str("0f4d9bcdd344a335145c4b0145f30ae3f382583049a1e5c43ace74059cece6a8").unwrap();

        let combined_keys = pk1.add_tweak(&pk2.into()).unwrap();

        let mut res: HashMap<PublicKey, PublicKey> = HashMap::new();
        for s in scan_pubkeys {
            res.insert(s, s.mul_tweak(&secp, &combined_keys.into()).unwrap());
        }
        res
    }

    #[test]
    fn new_sp_sender() {
        use bitcoin::Txid;

        // Our story begin with Bob creating a sp wallet
        let bob_xprv = new_master_from_seed(&format!("{}", "f00dbabe")).unwrap(); 
        let mut bob_silent = SilentPaymentReceiver::new(bob_xprv, false).unwrap();

        // He gets his default address
        let bob_address = bob_silent.0.get_receiving_address();

        // And send it to Alice so that she can pay him
        // Alice registers Bob as a fren
        let mut bob = CatiminiFren::new(1, "bob".to_owned());

        // And adds his address
        let alice_label_for_bob = "bob's silent address";
        bob.add_address(alice_label_for_bob.to_owned(), bob_address).unwrap();

        // Alice now wants to pay Bob
        // She first create a builder with the right network
        let network = Network::Bitcoin;
        let mut new_silent_payment = SilentPaymentSender::new(network);

        // She picks up 2 utxos that she controls (or let her wallet do it)
        let txid1 = Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16").unwrap();
        let txid2 = Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d").unwrap();

        let outpoints = vec![OutPoint {txid: txid1, vout: 0}, OutPoint {txid: txid2, vout: 0}];

        // And add them to the builder
        new_silent_payment.add_outpoints(outpoints);

        // Alice now needs to add the addresses she wants to pay Bob to
        // She can see all the addresses she has for Bob or pick one with a label
        let bob_address = bob.get_address_by_label(alice_label_for_bob.to_owned()).unwrap();
        new_silent_payment.add_addresses(vec![bob_address.clone()]).unwrap();

        // Next step is to get the ECDH for all the keys that she controls and Bob's scan key
        // Alice calls her signer, that can be a piece of software or hardware.
        // The requirements are that it can do keys combination and ECDH computation
        let scan_pubkeys = new_silent_payment.get_scanpubkeys();

        let ecdh_keys = ecdh(scan_pubkeys); // This is implemented by the signer

        // Now let's finalize the sender to generate keys
        // CatiminiSender takes ownership of the builder and consume it
        // but we can clone so that we still have the builder around to be modified
        let alice = CatiminiSender::new_sp(new_silent_payment.clone()).unwrap(); 

        let result = alice.silent_payment_derive_send_keys().unwrap();

        for (silent_address, pubkeys) in result {
            let expected_address: String = bob_address.clone().into();
            assert_eq!(silent_address, expected_address);
            for p in pubkeys {
                println!("\t{}", p);
                let expected = "39a1e5ff6206cd316151b9b34cee4f80bb48ce61adee0a12ce7ff05ea436a1d9";
                assert_eq!(expected, format!("{:x}", p));
            }
        }
    }
}
