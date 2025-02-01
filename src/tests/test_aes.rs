use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
const MIN_PLAINTEXT_LENGTH: usize = 14;
const MAX_PLAINTEXT_LENGTH: usize = 8192;
use crate::aes::{Aes256CbcFunctions, AesOpenSslScope, AesRustCryptoScope};

const AES_KEY: [u8; 32] = [42; 32];
const AES_IV: [u8; 16] = [84; 16];
const PLAINTEXT: &str = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
static ENCRYPTED: &[u8] = &[
    183, 143, 190, 91, 143, 235, 216, 171, 191, 35, 123, 0, 2, 53, 115, 226, 45, 204, 169, 232,
    183, 115, 209, 235, 172, 218, 255, 99, 202, 255, 146, 75, 159, 30, 178, 215, 162, 133, 124,
    113, 165, 30, 211, 170, 0, 207, 200, 177, 82, 62, 37, 104, 113, 15, 105, 67, 35, 195, 121, 100,
    207, 18, 11, 166,
];

#[test]
fn aes_openssl_rustcryptp() {
    let mut iterations: usize = 0;
    // validate that both implementations prodvide equal results.
    loop {
        iterations += 1;
        let plaintext_length = MIN_PLAINTEXT_LENGTH
            + thread_rng().gen_range(0..MAX_PLAINTEXT_LENGTH - MIN_PLAINTEXT_LENGTH);
        let random_plaintext: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(plaintext_length + 1)
            .map(char::from)
            .collect();
        println!("pt_len = {}", &plaintext_length);
        let openssl_aes = crate::aes::Aes256Cbc::<AesOpenSslScope>::random();
        // use same key and IV
        let aes_key_iv = openssl_aes.key_iv_as_vec();
        let rust_aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::from_vec(aes_key_iv).unwrap();
        let openssl_enrypted = openssl_aes.encrypt_str_to_vec(&random_plaintext).unwrap();
        let rust_encrypted = rust_aes.encrypt_str_to_vec(&random_plaintext).unwrap();
        let openssl_decrypted = openssl_aes
            .decrypt_bytes_to_string(&rust_encrypted)
            .unwrap();
        let rust_decrypted = rust_aes.decrypt_bytes_to_string(&openssl_enrypted).unwrap();
        assert_eq!(openssl_decrypted, rust_decrypted);
        if iterations > 1000 {
            break;
        }
    }
}

#[test]
fn encrypt_aes_openssl() {
    let aes = crate::aes::Aes256Cbc::<AesOpenSslScope>::from_key_iv(AES_KEY, AES_IV);
    let enrypted = aes.encrypt_str_to_vec(PLAINTEXT).unwrap();
    assert_eq!(enrypted, ENCRYPTED)
}

#[test]
fn decrypt_aes_openssl() {
    let aes = crate::aes::Aes256Cbc::<AesOpenSslScope>::from_key_iv(AES_KEY, AES_IV);
    let decrypted = aes.decrypt_bytes_to_string(ENCRYPTED).unwrap();
    assert_eq!(decrypted, PLAINTEXT)
}

#[test]
fn encrypt_aes_rustcrypto() {
    let rustcrypto_aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::from_key_iv(AES_KEY, AES_IV);
    let enrypted = rustcrypto_aes.encrypt_str_to_vec(PLAINTEXT).unwrap();
    assert_eq!(enrypted, ENCRYPTED)
}

#[test]
fn decrypt_aes_rustcrypto() {
    let aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::from_key_iv(AES_KEY, AES_IV);
    let decrypted = aes.decrypt_bytes_to_string(ENCRYPTED).unwrap();
    assert_eq!(decrypted, PLAINTEXT)
}
