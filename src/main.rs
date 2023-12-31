use wnfs::private::keys::exchange::{ ExchangeKey, PrivateKey, RsaPrivateKey, RsaPublicKey };
use wnfs::private::keys::aes::AesKey;
use wnfs::private::TemporalKey;
use wnfs::common::utils::get_random_bytes;
use base64::{Engine as _, engine::general_purpose};
use std::fs;

// Some test keys I generated using `tomb-www`:
const SPKI_STRING: &str = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEApgs5TkpXDqjye2KoU1ERu8QRs8lHkJb/YULlnPR3JuAUfdpj6TwifLZTFF3Duh5CRUXEa0p37EzRaA3rXCfBSldD4sm1uZ8xpc+wlNT0ZufRHY2PaFreXECDo1HtFMsaB6eGKF2KY3RhYlqUrmUYomm3M/G8qBG1TnvICZJxFuCpzE7Wrh3Bxw5BRzuclaatpa3bnJ/6NDmBqFsZvanlrKKoSdKsa/t274UXoWuAFtjRumbJYnu7o3QkVwFjCREXd2oDVu9EnrqRHr11zE9KH8wh2qk0dbliPXvB9BlwBZHLhWd7bhCtdhf8T+tWVfprkM74h91SRfZTLa66B4PUcphte4gw4hCaboZIedLG0En45shMl3/rYh+YEYoJJ18qBziFUMq+CrWzTPuvdMyWBrbimy8TEkzR83UXwpncPkDh1qJJHyw6PGhhXyiYPtNwXnrkr5Bl1NRs3rfbi7Rk4mbTZJ92LFtbDNAoZnZXNmrq+ZQZ/lLJUqd1G2xt1yaFAgMBAAE=";
const PKCS8_STRING: &str = "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";

#[async_std::main]
async fn main() {
    println!("Parsing base 64 encoded key strings...");
    let spki_der_bytes = general_purpose::STANDARD.decode(SPKI_STRING).unwrap();
    let pkcs8_der_bytes = general_purpose::STANDARD.decode(PKCS8_STRING).unwrap();
    RsaPublicKey::from_der(&spki_der_bytes).unwrap().to_pem_file("public_key.pem").unwrap();
    RsaPrivateKey::from_der(&pkcs8_der_bytes).unwrap().to_pem_file("private_key.pem").unwrap();

    println!("Attemting to read private key from file...");
    let priv_key_result = RsaPrivateKey::from_pem_file("private_key.pem");
    let priv_key = match priv_key_result {
        Ok(x) => x,
        Err(_) => {
            panic!("Failed to read private key from file!")
        },
    };
    let pub_key = priv_key.get_public_key();

    fs::remove_file("private_key.pem").unwrap();
    fs::remove_file("public_key.pem").unwrap();

    println!("Generating test key...");
    let aes_key = AesKey::new(get_random_bytes(&mut rand_core::OsRng));
    let temporal_key = TemporalKey(aes_key);

    println!("Encrypting test data with key...");
    let msg = b"this is what we're encrypting";
    println!("Encrypting message: {:?}", std::str::from_utf8(msg).unwrap());
    let ciphertext = temporal_key.key_wrap_encrypt(msg).unwrap();

    println!("Encrypting test key with RSA public key...");
    let enc_temporal_key = pub_key.encrypt(&temporal_key.0.as_bytes()).await.unwrap();

    println!("Decrypting test key with RSA private key...");
    let dec_temporal_key_vec = priv_key.decrypt(&enc_temporal_key).await.unwrap();
    
    println!("Decrypting test data with key...");
    let dec_temporal_key = TemporalKey(AesKey::new(dec_temporal_key_vec.try_into().unwrap()));
    let decrypted = dec_temporal_key.key_wrap_decrypt(&ciphertext).unwrap();

    assert_eq!(msg, &decrypted[..]);
    println!("Decrypted message: {:?}", std::str::from_utf8(&decrypted).unwrap());
}
