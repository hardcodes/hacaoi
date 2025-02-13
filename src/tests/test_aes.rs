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
const ENCRYPTED_B64: &str =
    "t4--W4_r2Ku_I3sAAjVz4i3Mqei3c9HrrNr_Y8r_kkufHrLXooV8caUe06oAz8ixUj4laHEPaUMjw3lkzxILpg==";

#[test]
fn aes_openssl_random() {
    let openssl_aes = crate::aes::Aes256Cbc::<AesOpenSslScope>::random();
    let mut iterations: usize = 0;
    loop {
        iterations += 1;
        let random_openssl_aes_in_loop = crate::aes::Aes256Cbc::<AesOpenSslScope>::random();
        // Those assertions may fail but it shouldn't happen too often!
        assert_ne!(openssl_aes.iv(), random_openssl_aes_in_loop.iv());
        assert_ne!(openssl_aes.key(), random_openssl_aes_in_loop.key());
        assert_ne!(
            openssl_aes.key_iv_as_vec(),
            random_openssl_aes_in_loop.key_iv_as_vec()
        );
        if iterations > 1000 {
            break;
        }
    }
}

#[test]
fn aes_rustcrypto_random() {
    let rustcrypto_aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::random();
    let mut iterations: usize = 0;
    loop {
        iterations += 1;
        let random_rustcrypto_aes_in_loop = crate::aes::Aes256Cbc::<AesOpenSslScope>::random();
        // Those assertions may fail but it shouldn't happen too often!
        assert_ne!(rustcrypto_aes.iv(), random_rustcrypto_aes_in_loop.iv());
        assert_ne!(rustcrypto_aes.key(), random_rustcrypto_aes_in_loop.key());
        assert_ne!(
            rustcrypto_aes.key_iv_as_vec(),
            random_rustcrypto_aes_in_loop.key_iv_as_vec()
        );
        if iterations > 1000 {
            break;
        }
    }
}

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
    assert_eq!(enrypted, ENCRYPTED);

    #[cfg(feature = "b64")]
    {
        let encrypted_b64 = aes.encrypt_str_to_b64(PLAINTEXT).unwrap();
        assert_eq!(encrypted_b64, ENCRYPTED_B64);
    }
}

#[test]
fn decrypt_aes_openssl() {
    let aes = crate::aes::Aes256Cbc::<AesOpenSslScope>::from_key_iv(AES_KEY, AES_IV);
    let decrypted = aes.decrypt_bytes_to_string(ENCRYPTED).unwrap();
    assert_eq!(decrypted, PLAINTEXT);

    #[cfg(feature = "b64")]
    {
        let decrypted = aes.decrypt_b64_to_string(ENCRYPTED_B64).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }
}

#[test]
fn encrypt_aes_rustcrypto() {
    let aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::from_key_iv(AES_KEY, AES_IV);
    let enrypted = aes.encrypt_str_to_vec(PLAINTEXT).unwrap();
    assert_eq!(enrypted, ENCRYPTED);

    #[cfg(feature = "b64")]
    {
        let encrypted_b64 = aes.encrypt_str_to_b64(PLAINTEXT).unwrap();
        assert_eq!(encrypted_b64, ENCRYPTED_B64);
    }
}

#[test]
fn decrypt_aes_rustcrypto() {
    let aes = crate::aes::Aes256Cbc::<AesRustCryptoScope>::from_key_iv(AES_KEY, AES_IV);
    let decrypted = aes.decrypt_bytes_to_string(ENCRYPTED).unwrap();
    assert_eq!(decrypted, PLAINTEXT);

    #[cfg(feature = "b64")]
    {
        let decrypted = aes.decrypt_b64_to_string(ENCRYPTED_B64).unwrap();
        assert_eq!(decrypted, PLAINTEXT);
    }
}
