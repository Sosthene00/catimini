use core::fmt;
use std::collections::{HashSet, HashMap, BTreeSet};
use std::vec;
use std::str::FromStr;
use std::io::Write;

use bitcoin::{OutPoint, Network};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey};
use bitcoin::secp256k1::{Secp256k1, PublicKey, XOnlyPublicKey, Scalar};
use bitcoin::hashes::{sha256, Hash};

use silentpayments::sending::{SilentPaymentAddress, generate_recipient_pubkeys};
use silentpayments::receiving::{SilentPayment, Label, NULL_LABEL};

#[derive(Debug)]
pub enum Error {
    GenericError(String),
    InvalidNetwork(String),
    SilentPaymentError(silentpayments::Error),
    SilentPaymentSendingError(String),
    InvalidProtocol(String),
    IOError(std::io::Error),
}

impl From<silentpayments::Error> for Error {
    fn from(e: silentpayments::Error) -> Self {
        Error::SilentPaymentError(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IOError(e)
    }
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum CatiminiAddress {
    Bip47,
    PrivatePayment,
    SilentPayment(SilentPaymentAddress),
}

impl CatiminiAddress {
    pub fn get_protocol(&self) -> &'static str {
        match self {
            Self::Bip47 => "bip47",
            Self::PrivatePayment => "private payment",
            Self::SilentPayment(_) => "silent payment"
        }
    }

    pub fn is_testnet(&self) -> bool {
        match self {
            Self::SilentPayment(a) => a.is_testnet(),
            _ => unimplemented!()
        }
    }

    pub fn test_protocol(candidate: &str) -> Result<&'static str, Error> {
        if let Ok(res) = Self::try_from(candidate) {
            return Ok(res.get_protocol());
        } else {
            return Err(Error::InvalidProtocol(format!("Unknown protocol for address {}", candidate)));
        }
    }
}

impl TryInto<SilentPaymentAddress> for CatiminiAddress {
    type Error = Error;

    fn try_into(self) -> Result<SilentPaymentAddress, Self::Error> {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_address) => {
                Ok(silent_payment_address)
            },
            _ => Err(Error::InvalidProtocol(format!("Expected silent payment, got {}", self.get_protocol())))
        }
    }
}

impl Into<String> for CatiminiAddress {
    fn into(self) -> String {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_recipient) => {
                silent_payment_recipient.into()
            },
            _ => unimplemented!()
        }
    }
}

impl TryFrom<String> for CatiminiAddress {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Ok(sp) = SilentPaymentAddress::try_from(value.clone()) {
            return Ok(Self::SilentPayment(sp));
        } else {
            return Err(Error::GenericError("Unknown address".to_owned()));
        }
    }
}

impl TryFrom<&str> for CatiminiAddress {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Ok(sp) = SilentPaymentAddress::try_from(value.clone()) {
            return Ok(Self::SilentPayment(sp));
        } else {
            return Err(Error::GenericError("Unknown address".to_owned()));
        }
    }
}

impl fmt::Display for CatiminiAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CatiminiAddress::SilentPayment(silent_payment_recipient) => {
                write!(f, "{}", silent_payment_recipient)
            },
            _ => unimplemented!()
        }
    }
}

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

pub struct Bip47Sender;

pub struct PrivatePaymentSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SilentPaymentRecipient {
    address: SilentPaymentAddress,
    ecdh_shared_secret: Option<PublicKey>,
    nb_outputs: u32,
}

impl SilentPaymentRecipient {
    fn new(address: SilentPaymentAddress) -> Self {
        Self {
            address,
            ecdh_shared_secret: None,
            nb_outputs: 1
        }
    }

    fn get_scan_key(&self) -> PublicKey {
        self.address.get_scan_key()
    }

    fn update_secret(&mut self, new_secret: PublicKey) {
        self.ecdh_shared_secret = Some(new_secret);
    }

    fn update_nb_outputs(&mut self, nb_outputs: u32) -> Result<(), Error> {
        if nb_outputs == 0 {
            return Err(Error::GenericError(format!("Can't have 0 output")));
        }

        self.nb_outputs = nb_outputs;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SilentPaymentSender {
    outpoints: BTreeSet<OutPoint>,
    recipients: Vec<SilentPaymentRecipient>,
    network: Network,
}

impl fmt::Display for SilentPaymentSender {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Sender on network {}: \n", self.network)?;
        write!(f, "Sender has {} outpoints: \n", self.outpoints.len())?;
        for (i, o) in self.outpoints.iter().enumerate() {
            write!(f, "\t#{}: {}\n", i, o)?;
        }
        write!(f, "Sender has {} recipients: \n", self.recipients.len())?;
        for (i, r) in self.recipients.iter().enumerate() {
            write!(f, "\t#{}: {}\n", i, r.address)?;
            write!(f, "\twith secret: {:?}\n", r.ecdh_shared_secret)?;
            write!(f, "\tand {} outputs\n", r.nb_outputs)?;
        }

        Ok(())
    }
}

impl SilentPaymentSender {
    pub fn new(network: Network) -> Self {
        Self { 
            outpoints: BTreeSet::new(), 
            recipients: vec![],
            network,
        }
    }

    /// Do some basics sanity check over our list of recipients before computing the keys
    fn is_valid(&self) -> Result<(), Error> {
        // if any of the recipients lacks a secret
        if let Some(r) = self.recipients.iter().find(|r| r.ecdh_shared_secret.is_none()) {
            return Err(Error::SilentPaymentSendingError(format!("Silent payment: Missing shared secret for recipients {}", r.address.to_string())));
        }

        // if we don't have any outpoints
        if self.outpoints.is_empty() {
            return Err(Error::SilentPaymentSendingError(format!("Silent payment: No outpoints")));
        }

        // All clear
        Ok(())
    }

    pub fn add_outpoints(&mut self, outpoints: Vec<OutPoint>) {
        self.outpoints.extend(outpoints.iter());
    }

    pub fn remove_outpoints(&mut self, outpoints: Vec<OutPoint>) {
        for o in outpoints {
            self.outpoints.remove(&o);
        }
    }

    pub fn add_addresses(&mut self, addresses: Vec<CatiminiAddress>) -> Result<(), Error> {
        for address in addresses {
            let silent_address: SilentPaymentAddress = address.try_into()?;
            
            // Is there already a recipient with this address?
            if let Some(mut recipient) = self.get_recipient_from_address(silent_address) {
                // we update the counter for this recipient
                // TODO: This can be improve
                let new_nb_outputs = recipient.nb_outputs + 1;
                let old_recipient = recipient.clone();
                recipient.update_nb_outputs(new_nb_outputs)?;
                let index = self.recipients.iter().position(|r| *r == old_recipient).unwrap();
                self.recipients.remove(index);
                self.recipients.insert(index, recipient);
            } else {
                if (self.network != Network::Bitcoin) != silent_address.is_testnet() {
                    return Err(Error::GenericError(format!("Wrong network for address: {}", silent_address)));
                }

                self.recipients.push(SilentPaymentRecipient::new(silent_address));
            }
        }

        Ok(())
    }

    fn get_recipient_from_address(& self, address: SilentPaymentAddress) -> Option<SilentPaymentRecipient> {
        self.recipients.iter().find(|r| r.address == address).copied()
    }

    pub fn get_scanpubkeys(&self) -> HashSet<PublicKey> {
        self.recipients.iter()
        .map(|r| r.address.get_scan_key())
        .collect()
    }

    pub fn get_empty_scanpubkeys(&self) -> HashSet<PublicKey> {
        self.recipients.iter().filter(|r| {
            r.ecdh_shared_secret.is_none()
        })
        .map(|r| r.address.get_scan_key())
        .collect()
    }

    pub fn add_ecdh_keys(&mut self, ecdh_keys: HashMap<PublicKey, PublicKey>) -> Result<(), Error> {
        for recipient in self.recipients.clone() {
            if let Some(new_secret) = ecdh_keys.get(&recipient.get_scan_key()) {
                let mut recipient_with_new_secret = recipient.clone();
                recipient_with_new_secret.update_secret(*new_secret);
                let index = self.recipients.iter().position(|r| *r == recipient).unwrap();
                self.recipients.remove(index);
                self.recipients.insert(index, recipient_with_new_secret);
            }
        }

        Ok(())
    }
}

pub enum CatiminiSender {
    Bip47(Bip47Sender),
    PrivatePayment(PrivatePaymentSender),
    SilentPayment(SilentPaymentSender),
}

impl CatiminiSender {
    pub fn new_sp(sp: SilentPaymentSender) -> Result<Self, Error> {
        sp.is_valid()?;
        
        Ok(Self::SilentPayment(sp))
    }

    pub fn get_protocol(&self) -> &str {
        match self {
            CatiminiSender::Bip47(_) => "bip47",
            CatiminiSender::PrivatePayment(_) => "private payment",
            CatiminiSender::SilentPayment(_) => "silent payment"
        }
    }

    pub fn silent_payment_derive_send_keys(self) -> Result<HashMap<String, Vec<XOnlyPublicKey>>, Error> {
        fn get_outpoints_hash(outpoints: BTreeSet<OutPoint>) -> Result<[u8;32], Error> {
            let mut engine = sha256::HashEngine::default();
            let mut bytes = [0u8;36];

            for outpoint in outpoints {
                let txid: [u8;32] = outpoint.txid.into_inner();
                let vout: [u8;4] = outpoint.vout.to_le_bytes();

                bytes[..32].copy_from_slice(&txid);
                bytes[32..].copy_from_slice(&vout);
                engine.write_all(&bytes)?;
            }


            Ok(sha256::Hash::from_engine(engine).into_inner())
        }

        match self {
            CatiminiSender::SilentPayment(b) => {
                let secp = Secp256k1::new();
                let recipients: Vec<String> = b.recipients.iter().flat_map(|r| {
                    let mut to_add: Vec<String> = vec![];
                    for _ in 0..r.nb_outputs {
                        to_add.push(r.address.into());
                    }
                    to_add
                })
                .collect();
                let outpoints_hash = get_outpoints_hash(b.outpoints)?;
                let secrets = b.recipients
                    .into_iter()
                    .map(|r| -> Result<(PublicKey, PublicKey), silentpayments::Error> {
                        // tweak the secret with the outpoints hash
                        let tweak = Scalar::from_be_bytes(outpoints_hash)?;
                        if let Some(secret) = r.ecdh_shared_secret {
                            let tweaked_secret = secret.mul_tweak(&secp, &tweak)?;
                            Ok((r.address.get_scan_key(), tweaked_secret))
                        } else {
                            return Err(silentpayments::Error::InvalidSharedSecret(format!("Missing shared secret!"))); // This should never happen
                        }
                    });

                let secrets: HashMap<PublicKey, PublicKey> = secrets
                    .into_iter()
                    .map(|r| r.unwrap())
                    .collect();

                let res = generate_recipient_pubkeys(recipients, secrets)?;
                Ok(res)
            },
            _ => {
                let e = format!(
                    "Tried to create a sender out of the wrong protocol: expected SilentPayment, got {}", 
                    self.get_protocol()
                );
                Err(Error::InvalidProtocol(e))
            }
        }
    }

    pub fn bip47_derive_send_keys(self, start: u32, end: u32) -> Box<dyn Fn(u32, u32) -> Result<PublicKey, Error>> {
        unimplemented!();
    }

    pub fn private_payment_derive_send_keys(self, start: u32, end: u32) -> Box<dyn Fn(u32, u32) -> Result<PublicKey, Error>> {
        unimplemented!();
    }
}

pub struct Bip47Receiver;

pub struct PrivatePaymentReceiver;

pub struct SilentPaymentReceiver(SilentPayment);

impl SilentPaymentReceiver {
    pub fn new(xprv: ExtendedPrivKey, is_testnet: bool) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        if xprv.network == Network::Bitcoin && is_testnet {
            return Err(Error::InvalidNetwork(format!("Can't create receiver, xprv network is {} and is_testnet {}", xprv.network, is_testnet)));
        }

        let scan_path = DerivationPath::from_str("m/352'/0'/0'/1'/0").expect("This shouldn't ever happen");
        let spend_path = DerivationPath::from_str("m/352'/0'/0'/0'/0").expect("This shouldn't ever happen");

        let scan_key = xprv.derive_priv(&secp, &scan_path).expect("This shouldn't ever happen");
        let spend_key = xprv.derive_priv(&secp, &spend_path).expect("This shouldn't ever happen");

        Ok(Self {
            0: SilentPayment::new(
                0, 
                scan_key.private_key, 
                spend_key.private_key, 
                is_testnet
            ).expect("Couldn't create SilentPayment")
        }
    }
}

pub enum CatiminiReceiver {
    Bip47(Bip47Receiver),
    PrivatePayment(PrivatePaymentReceiver),
    SilentPayment(SilentPaymentReceiver),
}

impl CatiminiReceiver {
    pub fn get_protocol(&self) -> &str {
        match self {
            CatiminiReceiver::Bip47(_) => "bip47",
            CatiminiReceiver::PrivatePayment(_) => "private payment",
            CatiminiReceiver::SilentPayment(_) => "silent payment"
        }
    }

    // pub fn silent_payment_derive_receive_keys(self) -> Result<HashMap<Label, Vec<SecretKey>>, Error> {
        // match self {
        //     CatiminiReceiver::SilentPayment(b) => {
        //         let res = create_outputs(b.outpoints, b.recipients)?;
        //         Ok(res)
        //     },
        //     _ => {
        //         let e = format!(
        //             "Tried to create a sender out of the wrong protocol: expected SilentPayment, got {}", 
        //             self.get_protocol()
        //         );
        //         Err(Error::InvalidProtocol(e))
        //     }
        // }
    //     unimplemented!();
    // }

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

    use crate::{CatiminiSender, CatiminiReceiver, CatiminiFren, CatiminiAddress, SilentPaymentSender, SilentPaymentReceiver};

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
        let mut bob_silent = SilentPaymentReceiver::new(bob_xprv, true);

        let label = format!("{:064x}", 1);
        let bob_address = bob_silent.0.get_receiving_address(Some(&label.try_into().unwrap())).unwrap();
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
        let mut bob_silent = SilentPaymentReceiver::new(bob_xprv, false);

        // He gets his default address
        let bob_address = bob_silent.0.get_receiving_address(None).unwrap();

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

        // then we must add the ecdh keys to the builder
        new_silent_payment.add_ecdh_keys(ecdh_keys).unwrap();

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
