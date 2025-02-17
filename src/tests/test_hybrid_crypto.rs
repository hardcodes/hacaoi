use crate::hybrid_crypto::HybridCryptoFunctions;
use crate::rsa::RsaKeysFunctions;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::env;
use std::path::Path;

const MIN_PLAINTEXT_LENGTH: usize = 14;
const MAX_PLAINTEXT_LENGTH: usize = 8192;
// (insecure) password of the rsa private keys in resources/tests/rsa
const RSA_PASSPHRASE: &str = "12345678901234";
const PLAINTEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";

#[test]
fn hybrid_crypto_openssl_rustcrypto() {
    let openssl_hybrid_crypto = crate::openssl::hybrid_crypto::HybridCrypto::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs1.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();
    let rust_hybrid_crypto = crate::rust_crypto::hybrid_crypto::HybridCrypto::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs8.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();

    let mut iterations: usize = 0;
    loop {
        iterations += 1;
        let plaintext_length = MIN_PLAINTEXT_LENGTH
            + thread_rng().gen_range(0..MAX_PLAINTEXT_LENGTH - MIN_PLAINTEXT_LENGTH);
        let random_plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_length + 1)
            .map(char::from)
            .collect();

        let openssl_hybrid_encrypted = openssl_hybrid_crypto
            .hybrid_encrypt_str(&random_plaintext)
            .unwrap();
        let rust_hybrid_encrypted = rust_hybrid_crypto
            .hybrid_encrypt_str(&random_plaintext)
            .unwrap();
        let openssl_hybrid_decrypted = openssl_hybrid_crypto
            .hybrid_decrypt_str(&rust_hybrid_encrypted)
            .unwrap();
        let rust_hybrid_decrypted = openssl_hybrid_crypto
            .hybrid_decrypt_str(&openssl_hybrid_encrypted)
            .unwrap();
        assert_eq!(rust_hybrid_decrypted, random_plaintext);
        assert_eq!(openssl_hybrid_decrypted, random_plaintext);

        if iterations > 500 {
            break;
        }
    }
}

#[test]
fn hybrid_crypto_openssl_deref() {
    let openssl_hybrid_crypto = crate::openssl::hybrid_crypto::HybridCrypto::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs1.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();

    let rsa_encrypted_b64 = openssl_hybrid_crypto
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = openssl_hybrid_crypto
        .decrypt_b64_pkcs1v15_padding_to_string(&rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}

#[test]
fn hybrid_crypto_rust_crypto_deref() {
    let rust_hybrid_crypto = crate::rust_crypto::hybrid_crypto::HybridCrypto::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs8.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();

    let rsa_encrypted_b64 = rust_hybrid_crypto
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = rust_hybrid_crypto
        .decrypt_b64_pkcs1v15_padding_to_string(&rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}
