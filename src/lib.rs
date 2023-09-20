pub mod error;
pub mod address;
pub mod sender;
pub mod receiver;

use std::collections::HashMap;
use std::vec;

use bitcoin::OutPoint;

use error::Error;
pub use address::CatiminiAddress;
pub use sender::{SilentPaymentSender, CatiminiSender};
pub use receiver::CatiminiReceiver;

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

#[cfg(test)]
mod tests {
    use bitcoin::{util::bip32::{ExtendedPrivKey, Error as Bip32Error}, Network};
    use bitcoin::hashes::hex::FromHex;

    use crate::{CatiminiFren, CatiminiAddress};

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
}
