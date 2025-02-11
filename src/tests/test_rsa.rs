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
fn rsa_pkcs1v15_openssl_random_1024bit() {
    let openssl_rsa_keys =
        crate::openssl::rsa::RsaKeys::random(crate::rsa::KeySize::Bit1024).unwrap();
    let openssl_rsa_encrypted_b64 = openssl_rsa_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = openssl_rsa_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&openssl_rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}

#[test]
fn rsa_pkcs1v15_rustcrypto_random_1024bit() {
    let rust_crypto_keys =
        crate::rust_crypto::rsa::RsaKeys::random(crate::rsa::KeySize::Bit1024).unwrap();

    let rust_crypto_encrypted_b64 = rust_crypto_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let rust_crypto_decryped = rust_crypto_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&rust_crypto_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &rust_crypto_decryped);
}

#[test]
fn rsa_pkcs1v15_openssl_random_2048bit() {
    let openssl_rsa_keys =
        crate::openssl::rsa::RsaKeys::random(crate::rsa::KeySize::Bit2048).unwrap();
    let openssl_rsa_encrypted_b64 = openssl_rsa_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = openssl_rsa_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&openssl_rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}

#[test]
fn rsa_pkcs1v15_rustcrypto_random_2048bit() {
    let rust_crypto_keys =
        crate::rust_crypto::rsa::RsaKeys::random(crate::rsa::KeySize::Bit2048).unwrap();

    let rust_crypto_encrypted_b64 = rust_crypto_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let rust_crypto_decryped = rust_crypto_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&rust_crypto_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &rust_crypto_decryped);
}

#[test]
fn rsa_pkcs1v15_openssl_random_3072bit() {
    let openssl_rsa_keys =
        crate::openssl::rsa::RsaKeys::random(crate::rsa::KeySize::Bit3072).unwrap();
    let openssl_rsa_encrypted_b64 = openssl_rsa_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = openssl_rsa_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&openssl_rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}

#[test]
fn rsa_pkcs1v15_rustcrypto_random_3072bit() {
    let rust_crypto_keys =
        crate::rust_crypto::rsa::RsaKeys::random(crate::rsa::KeySize::Bit3072).unwrap();

    let rust_crypto_encrypted_b64 = rust_crypto_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let rust_crypto_decryped = rust_crypto_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&rust_crypto_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &rust_crypto_decryped);
}

#[test]
fn rsa_pkcs1v15_openssl_random_4096bit() {
    let openssl_rsa_keys =
        crate::openssl::rsa::RsaKeys::random(crate::rsa::KeySize::Bit4096).unwrap();
    let openssl_rsa_encrypted_b64 = openssl_rsa_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let openssl_decrypted = openssl_rsa_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&openssl_rsa_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &openssl_decrypted);
}

#[test]
fn rsa_pkcs1v15_rustcrypto_random_4096bit() {
    let rust_crypto_keys =
        crate::rust_crypto::rsa::RsaKeys::random(crate::rsa::KeySize::Bit4096).unwrap();

    let rust_crypto_encrypted_b64 = rust_crypto_keys
        .encrypt_str_pkcs1v15_padding_to_b64(PLAINTEXT)
        .unwrap();
    let rust_crypto_decryped = rust_crypto_keys
        .decrypt_b64_pkcs1v15_padding_to_string(&rust_crypto_encrypted_b64)
        .unwrap();
    assert_eq!(PLAINTEXT, &rust_crypto_decryped);
}

#[test]
fn rsa_pkcs1v15_openssl_rustcrypto() {
    let openssl_rsa_keys = crate::openssl::rsa::RsaKeys::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs1.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();
    let rust_crypto_keys = crate::rust_crypto::rsa::RsaKeys::from_file(
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
        let plaintext_length =
            MIN_PLAINTEXT_LENGTH + thread_rng().gen_range(0..MIN_PLAINTEXT_LENGTH);
        let random_plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_length + 1)
            .map(char::from)
            .collect();
        let openssl_rsa_encrypted_b64 = openssl_rsa_keys
            .encrypt_str_pkcs1v15_padding_to_b64(&random_plaintext)
            .unwrap();
        let rust_crypto_encrypted_b64 = rust_crypto_keys
            .encrypt_str_pkcs1v15_padding_to_b64(&random_plaintext)
            .unwrap();
        let openssl_decrypted_rust_crypto = openssl_rsa_keys
            .decrypt_b64_pkcs1v15_padding_to_string(&rust_crypto_encrypted_b64)
            .unwrap();
        let rust_crypto_decryped_openssl = rust_crypto_keys
            .decrypt_b64_pkcs1v15_padding_to_string(&openssl_rsa_encrypted_b64)
            .unwrap();
        assert_eq!(&random_plaintext, &openssl_decrypted_rust_crypto);
        assert_eq!(&random_plaintext, &rust_crypto_decryped_openssl);
        if iterations > 100 {
            break;
        }
    }
}

#[test]
fn rsa_sha512_signature_openssl_rustcrypto() {
    let openssl_rsa_keys = crate::openssl::rsa::RsaKeys::from_file(
        Path::new(
            &env::current_dir()
                .unwrap()
                .join("resources/tests/rsa/rsa_private.pkcs1.key"),
        ),
        RSA_PASSPHRASE,
    )
    .unwrap();
    let rust_rsa_keys = crate::rust_crypto::rsa::RsaKeys::from_file(
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
        let openssl_signature_b64 = openssl_rsa_keys
            .sign_str_sha512_b64(&random_plaintext)
            .unwrap();
        let rust_signature_b64 = rust_rsa_keys
            .sign_str_sha512_b64(&random_plaintext)
            .unwrap();
        let openssl_validation_result =
            openssl_rsa_keys.validate_sha512_b64_signature(&random_plaintext, &rust_signature_b64);
        let rust_validation_result =
            rust_rsa_keys.validate_sha512_b64_signature(&random_plaintext, &openssl_signature_b64);
        assert!(openssl_validation_result.is_ok());
        assert!(rust_validation_result.is_ok());
        if iterations > 100 {
            break;
        }
    }
}
