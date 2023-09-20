use std::collections::{HashSet, HashMap, BTreeSet};
use std::vec;
use core::fmt;

use bitcoin::{OutPoint, Network};
use bitcoin::secp256k1::{PublicKey, SecretKey, XOnlyPublicKey, Scalar};

use silentpayments::sending::{SilentPaymentAddress, generate_multiple_recipient_pubkeys};
use silentpayments::utils::hash_outpoints;

use crate::{Error, CatiminiAddress};

pub struct Bip47Sender;

pub struct PrivatePaymentSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SilentPaymentRecipient {
    address: SilentPaymentAddress,
    nb_outputs: u32,
}

impl SilentPaymentRecipient {
    fn new(address: SilentPaymentAddress) -> Self {
        Self {
            address,
            nb_outputs: 1
        }
    }
}

#[derive(Debug, Clone)]
pub struct SilentPaymentSender {
    outpoints: BTreeSet<OutPoint>,
    tweak_data: Option<SecretKey>,
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
            write!(f, "\tand {} outputs\n", r.nb_outputs)?;
        }

        Ok(())
    }
}

impl SilentPaymentSender {
    pub fn new(network: Network) -> Self {
        Self { 
            outpoints: BTreeSet::new(), 
            tweak_data: None,
            recipients: vec![],
            network,
        }
    }

    /// Do some basics sanity check over our list of recipients before computing the keys
    fn is_valid(&self) -> Result<(), Error> {
        // if we don't have any outpoints
        if self.outpoints.is_empty() {
            return Err(Error::SilentPaymentSendingError(format!("Silent payment: No outpoints")));
        }

        // if we don't have the tweak_data
        if self.tweak_data.is_none() {
            return Err(Error::SilentPaymentSendingError(format!("Silent payment: no tweak data")));
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

    pub fn get_outpoints_hash(&self) -> Result<Scalar, Error> {
        let outpoints: Vec<[u8;36]> = self.outpoints
            .iter()
            .map(|o| {
                let mut bytes = [0u8;36];
                bytes[..32].copy_from_slice(&o.txid);
                bytes[32..].copy_from_slice(&o.vout.to_le_bytes());
                bytes 
            })
            .collect();
        Ok(hash_outpoints(&outpoints)?)
    }

    pub fn add_tweak_data(&mut self, tweak: SecretKey) {
        self.tweak_data = Some(tweak);
    }

    pub fn add_addresses(&mut self, addresses: Vec<CatiminiAddress>) -> Result<(), Error> {
        for address in addresses {
            let silent_address: SilentPaymentAddress = address.try_into()?;

            if let Some(pos) = self.recipients.iter().position(|r| r.address == silent_address) {
                // we update the counter for this recipient
                self.recipients[pos].nb_outputs = self.recipients[pos].nb_outputs.saturating_add(1);
            } else {
                if (self.network != Network::Bitcoin) != silent_address.is_testnet() {
                    return Err(Error::GenericError(format!("Wrong network for address: {}", silent_address)));
                }
                self.recipients.push(SilentPaymentRecipient::new(silent_address));
            }
        }
        Ok(())
    }

    pub fn get_scanpubkeys(&self) -> HashSet<PublicKey> {
        self.recipients.iter()
        .map(|r| r.address.get_scan_key())
        .collect()
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
        match self {
            CatiminiSender::SilentPayment(b) => {
                let recipients: Vec<String> = b.recipients.iter().flat_map(|r| {
                    let mut to_add: Vec<String> = vec![];
                    for _ in 0..r.nb_outputs {
                        to_add.push(r.address.into());
                    }
                    to_add
                })
                .collect();

                let res = if let Some(tweak) = b.tweak_data {
                    generate_multiple_recipient_pubkeys(recipients, tweak)?
                } else {
                    return Err(Error::SilentPaymentSendingError(format!("Missing tweak data")));
                };

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
