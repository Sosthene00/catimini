use std::collections::HashMap;

use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey, Scalar};

use silentpayments::receiving::{Receiver, Label, NULL_LABEL};

use crate::Error;

pub struct Bip47Receiver;

pub struct PrivatePaymentReceiver;

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