use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use sha1::Sha1;
use base64ct::{Base64, Encoding};
use aes_gcm::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use rsa::pkcs8::{ EncodePrivateKey, DecodePrivateKey };
use pkcs8::LineEnding;
// Questions:
// 1. Do we want to AES-KW for key wrapping, or just AES-GCM?
// 2. What's up with this padding stuff?

fn main() {
    // TODO: Types for config
    let bits = 3072;
    let padding: Oaep = Oaep::new::<Sha256>();
    let padding_1: Oaep = Oaep::new::<Sha256>();

    println!("Generating {}-bit RSA key pair...", bits);
    // Generate key pair
    // let priv_key = RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate a key");
    // let pub_key = RsaPublicKey::from(&priv_key);

    // priv_key.write_pkcs8_pem_file("private_key.pem", LineEnding::LF).expect("failed to write private key");

    let priv_key = RsaPrivateKey::read_pkcs8_pem_file("private_key.pem").expect("failed to read private key");
    let pub_key = RsaPublicKey::from(&priv_key);

    println!("Generating test key...");
    // Generate an AES-GCM key
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    println!("Encrypting test data with key...");
    // Convert AES-GCM key to bytes
    let msg = b"this is what we're encrypting"; 
    let mut cipher_buffer: Vec<u8> = Vec::new(); // Note: buffer needs 16-bytes overhead for auth tag
    cipher_buffer.extend_from_slice(msg);
    cipher.encrypt_in_place(&nonce, b"", &mut cipher_buffer).expect("encryption failure!");

    println!("Encrypting test key with RSA public key...");
    // Encrypt the AES-GCM key with the RSA public key
    let aes_key_bytes: &[u8] = key.as_ref();
    let enc_aes_key = pub_key.encrypt(&mut OsRng, padding, &aes_key_bytes[..]).expect("failed to encrypt");

    println!("Decrypting test key with RSA private key...");
    // Decrypt the AES-GCM key with the RSA private key
    let dec_aes_key = priv_key.decrypt(padding_1, &enc_aes_key).expect("failed to decrypt");

    println!("Decrypting test data with key...");
    // Convert the decrypted AES-GCM key to a usable type
    let dec_cipher = Aes256Gcm::new_from_slice(&dec_aes_key).expect("failed to convert key");
    dec_cipher.decrypt_in_place(&nonce, b"", &mut cipher_buffer).expect("decryption failure!");

    println!("Decrypted data: {}", std::str::from_utf8(&cipher_buffer[..msg.len()]).unwrap());
    // Assert that the decrypted ciphertext matches the original plaintext
    assert_eq!(&cipher_buffer[..msg.len()], msg);
}
