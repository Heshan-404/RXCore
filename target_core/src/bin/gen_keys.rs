use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);

    let secret_b64 = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, seed);
    let public_b64 = base64::Engine::encode(&base64::prelude::BASE64_STANDARD, public.to_bytes());
    let short_id = {
        let mut id = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut id);
        hex::encode(id)
    };

    println!("Private Key (Base64): {}", secret_b64);
    println!("Public Key (Base64):  {}", public_b64);
    println!("Short ID (Hex):       {}", short_id);
}
