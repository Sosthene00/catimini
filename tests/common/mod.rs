use std::collections::HashMap;
use secp256k1::{SecretKey, PublicKey, Message, hashes::Hash, Scalar};
use silentpayments::structs::OutputWithSignature;

pub mod utils;
pub mod input;

pub struct Signer {
    privkeys: Vec<SecretKey>
}

impl Signer {
    pub fn new(privkeys: Vec<SecretKey>) -> Self {
        Self {
            privkeys
        }
    }

    pub fn compute_ecdh_shared_secret(&self, B_scan: Vec<PublicKey>) -> HashMap<PublicKey, PublicKey> {
        let secp = secp256k1::Secp256k1::new();

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

    pub fn verify_and_calculate_signatures(
        privkeys: Vec<SecretKey>,
        b_spend: SecretKey,
    ) -> Result<Vec<OutputWithSignature>, secp256k1::Error> {
        let secp = secp256k1::Secp256k1::new();

        let msg = Message::from_hashed_data::<secp256k1::hashes::sha256::Hash>(b"message");
        let aux = secp256k1::hashes::sha256::Hash::hash(b"random auxiliary data").to_byte_array();

        let mut res: Vec<OutputWithSignature> = vec![];
        for mut k in privkeys {
            let (P, parity) = k.x_only_public_key(&secp);
            let tweak = k.add_tweak(&Scalar::from_be_bytes(b_spend.negate().secret_bytes()).unwrap())?;

            if parity == secp256k1::Parity::Odd {
                k = k.negate();
            }

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &k.keypair(&secp), &aux);

            secp.verify_schnorr(&sig, &msg, &P)?;


            res.push(OutputWithSignature {
                pub_key: P.to_string(),
                priv_key_tweak: format!("{}", tweak.display_secret()),
                signature: sig.to_string(),
            });
        }
        Ok(res)
    }

}
