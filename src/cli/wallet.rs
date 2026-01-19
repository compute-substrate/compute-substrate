use anyhow::Result;
use rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey};

use crate::crypto::hash160;

pub fn wallet_new() -> Result<()> {
    let secp = Secp256k1::new();
    let sk = SecretKey::new(&mut OsRng);
    let pk = PublicKey::from_secret_key(&secp, &sk);
    let pk33 = pk.serialize();
    let addr = hash160(&pk33);

    println!("privkey: 0x{}", hex::encode(sk.secret_bytes()));
    println!("pubkey:  0x{}", hex::encode(pk33));
    println!("addr20:  0x{}", hex::encode(addr));
    Ok(())
}
