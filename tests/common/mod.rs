use std::collections::HashMap;
use std::str::FromStr;
use bitcoin::XOnlyPublicKey;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{SecretKey, PublicKey, Message, hashes, Scalar, Secp256k1, Error, Parity};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::util::bip32::ExtendedPrivKey;
use silentpayments::receiving::{SilentPayment, NULL_LABEL};
use silentpayments::sending::SilentPaymentAddress;
use crate::common::input::OutputWithSignature;

pub mod utils;
pub mod input;

pub struct Signer {
    privkeys: Vec<SecretKey>,
    sp_privkeys: HashMap<SilentPaymentAddress, Vec<SecretKey>>
}

impl Signer {
    pub fn new(privkeys: Vec<SecretKey>, sp_privkeys: HashMap<SilentPaymentAddress, Vec<SecretKey>>) -> Self {
        Self {
            privkeys,
            sp_privkeys
        }
    }

    pub fn compute_ecdh_shared_secret(&self, B_scan: Vec<PublicKey>) -> HashMap<PublicKey, PublicKey> {
        let secp = Secp256k1::new();

        let mut to_add = self.privkeys.clone();
        let combined_key = to_add.pop().unwrap();
        let combined_key: SecretKey = to_add.into_iter().fold(combined_key, |combined_key, k| {
            combined_key.add_tweak(&k.into()).unwrap()
        });

        let mut dh: HashMap<PublicKey, PublicKey> = HashMap::new();
        for B in B_scan {
            dh.insert(B, B.mul_tweak(&secp, &combined_key.into()).unwrap());
        }

        dh
    }

    pub fn sign_msg(
        &self,
        // xprv: ExtendedPrivKey,
        msg: &str
    ) -> Result<HashMap<String, Vec<OutputWithSignature>>, Error> {
        fn get_silent_payment(xprv: ExtendedPrivKey) -> (SilentPayment, SecretKey, SecretKey) {
            let secp = Secp256k1::new();

            let scan_path = bitcoin::util::bip32::DerivationPath::from_str("m/352'/0'/0'/1'/0").expect("This shouldn't ever happen");
            let spend_path = bitcoin::util::bip32::DerivationPath::from_str("m/352'/0'/0'/0'/0").expect("This shouldn't ever happen");

            let scan_key = xprv.derive_priv(&secp, &scan_path).expect("This shouldn't ever happen");
            let spend_key = xprv.derive_priv(&secp, &spend_path).expect("This shouldn't ever happen");

            (SilentPayment::new(
                0, 
                scan_key.private_key, 
                spend_key.private_key, 
                false
            ).expect("Couldn't create SilentPayment"), scan_key.private_key, spend_key.private_key)
        }

        let secp = Secp256k1::new();

        let msg_hash = Message::from_hashed_data::<hashes::sha256::Hash>(msg.as_bytes());
        let aux = hashes::sha256::Hash::hash(b"random auxiliary data").into_inner();

        // let (sp, scan_key, spend_key) = get_silent_payment(xprv);

        let mut res: HashMap<String, Vec<OutputWithSignature>> = HashMap::new();

        for (sp_address, v) in self.sp_privkeys.iter() {
            let mut signatures: Vec<OutputWithSignature> = vec![];
            for privkey in v {
                let (P, parity) = privkey.x_only_public_key(&secp);

                let mut negated_privkey = privkey.clone();
                if parity == Parity::Odd {
                    negated_privkey = negated_privkey.negate();
                }

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
        let aux = hashes::sha256::Hash::hash(b"random auxiliary data").into_inner();

        match secp.verify_schnorr(&Signature::from_str(sig).unwrap(), &msg_hash, &xpubkey) {
            Ok(_) => true,
            Err(_) => false
        }
    }
}
