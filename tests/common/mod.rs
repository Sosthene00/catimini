use std::collections::HashMap;
use std::str::FromStr;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{SecretKey, PublicKey, Message, hashes, Scalar, Secp256k1, Error, Parity};
use bitcoin::secp256k1::schnorr::Signature;
use silentpayments::sending::SilentPaymentAddress;
use crate::common::structs::OutputWithSignature;

pub mod utils;
pub mod structs;

pub struct Signer {
    privkeys: Vec<(SecretKey, bool)>,
    sp_tweaks: HashMap<SilentPaymentAddress, Vec<Scalar>>
}

impl Signer {
    pub fn new(privkeys: Vec<(SecretKey, bool)>, sp_tweaks: HashMap<SilentPaymentAddress, Vec<Scalar>>) -> Self {
        Self {
            privkeys,
            sp_tweaks
        }
    }

    pub fn add_tweaks(&mut self, tweaks: HashMap<SilentPaymentAddress, Vec<Scalar>>) {
        self.sp_tweaks.extend(tweaks.into_iter());
    }

    pub fn aggregate_privkeys(&self) -> SecretKey {
        let secp = Secp256k1::new();
        let mut to_add: Vec<SecretKey> = Vec::with_capacity(self.privkeys.len());

        for (p, is_xonly) in &self.privkeys {
            let (_, parity) = p.x_only_public_key(&secp);
            if parity == Parity::Odd && *is_xonly {
                to_add.push(p.negate());
            } else {
                to_add.push(p.clone());
            }
        }

        let combined_key = to_add.pop().unwrap();
        let combined_key: SecretKey = to_add.into_iter().fold(combined_key, |combined_key, k| {
            combined_key.add_tweak(&k.into()).unwrap()
        });
        combined_key
    }
    
    pub fn tweak_aggregated_keys(&self, tweak: &Scalar) -> SecretKey {
        let agg_key = self.aggregate_privkeys();
        agg_key.mul_tweak(tweak).unwrap()
    }

    pub fn tweak_with_scan_key(&self, tweak_data: PublicKey) -> PublicKey {
        let secp = Secp256k1::new();
        let (scan_key, _) = self.privkeys[0];
        tweak_data.mul_tweak(&secp, &Scalar::from(scan_key)).unwrap()
    }

    pub fn sign_msg(
        &self,
        msg: &str
    ) -> Result<HashMap<String, Vec<OutputWithSignature>>, Error> {
        let secp = Secp256k1::new();

        let msg_hash = Message::from_hashed_data::<hashes::sha256::Hash>(msg.as_bytes());
        let aux = hashes::sha256::Hash::hash(b"random auxiliary data").into_inner();

        let mut res: HashMap<String, Vec<OutputWithSignature>> = HashMap::new();

        for (sp_address, v) in self.sp_tweaks.iter() {
            let mut signatures: Vec<OutputWithSignature> = vec![];
            for tweak in v {
                let (spend_key, _) = self.privkeys[1].clone();
                let privkey = spend_key.add_tweak(&tweak).unwrap();
                let (P, _) = privkey.x_only_public_key(&secp);

                let sig = secp.sign_schnorr_with_aux_rand(&msg_hash, &privkey.keypair(&secp), &aux);

                signatures.push(OutputWithSignature {
                    pubkey: P.to_string(),
                    signature: sig.to_string(), 
                });
            }
            let address = sp_address.clone();
            res.insert(address.into(), signatures);
        }
        Ok(res)
    }

    pub fn verify_sig(sig: &str, msg: &str, pubkey: &str) -> bool {
        let secp = Secp256k1::new();

        let xpubkey = XOnlyPublicKey::from_str(pubkey).unwrap();
        let msg_hash = Message::from_hashed_data::<hashes::sha256::Hash>(msg.as_bytes());

        match secp.verify_schnorr(&Signature::from_str(sig).unwrap(), &msg_hash, &xpubkey) {
            Ok(_) => true,
            Err(_) => false
        }
    }
}
