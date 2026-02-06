//!# Examples
//!
//! ## PKCS#1 v1.5 encryption - RustCrypto
//!
//! Note: features `rust-crypto` and `b64` must be enabled.
//!
//! ⚠️ **Security Warning**
//!
//! The Rust-Crypto RSA crate that is used here under the hood is vulnerable to the [Marvin Attack](https://people.redhat.com/~hkario/marvin/) which could enable private key recovery by a network attacker (see [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)).
//!
//! You can follow the work of the Rust-Crypto developers on mitigating this issue in [#390](https://github.com/RustCrypto/RSA/issues/390).
//!
//!
#![cfg_attr(all(feature = "rust-crypto", feature = "b64"), doc = "```")]
#![cfg_attr(not(any(feature = "rust-crypto", feature = "b64")), doc = "```ignore")]
//! use hacaoi::rsa::{RsaKeysFunctions, KeySize};
//!
//! fn main() {
//!     let rsa = hacaoi::rust_crypto::rsa::RsaKeys::random(KeySize::Bit2048).unwrap();
//!     let encrypted_b64 = rsa.encrypt_str_pkcs1v15_padding_to_b64("plaintext").unwrap();
//!     let decrypted = rsa.decrypt_b64_pkcs1v15_padding_to_string(&encrypted_b64).unwrap();
//!     assert_eq!("plaintext", &decrypted);
//! }
//! ```

use crate::error::HacaoiError;
use crate::rsa::{KeySize, RsaKeysFunctions};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8;
use rsa::sha2::Sha512;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use std::path::Path;

use rsa::sha2::Sha256;
use rsa::Oaep;
use sha1::Sha1;

// min bit size of the modulus (modulus * 8 = rsa key bits)
const MIN_RSA_MODULUS_SIZE: u32 = 256;

/// Holds the RSA private and public key for
/// encryption and decryption
pub struct RsaKeys {
    // RSA seems to zeroize the private key on drop().
    // ```ignore
    // impl ZeroizeOnDrop for RsaPrivateKey {}
    // ```
    private_key: rsa::RsaPrivateKey,
    public_key: rsa::RsaPublicKey,
}

impl RsaKeysFunctions for RsaKeys {
    /// Build a new random RSA key pair.
    #[inline(always)]
    fn random(key_size: KeySize) -> Result<Self, HacaoiError> {
        let mut rng = rand::thread_rng();
        let rsa_private_key = RsaPrivateKey::new(&mut rng, key_size as usize)?;
        let rsa_public_key = rsa_private_key.to_public_key();
        Ok(RsaKeys {
            private_key: rsa_private_key,
            public_key: rsa_public_key,
        })
    }

    /// Loads an encryped RSA private key file from
    /// the given path, hence the passphrase is needed.
    /// The private key is expected to be PKCS#8 encoded!
    /// The RSA public key is derived from the RSA private key.
    #[inline(always)]
    fn from_file<P: AsRef<Path>>(
        rsa_private_key_path: P,
        rsa_private_key_password: &str,
    ) -> Result<Self, HacaoiError> {
        let rsa_private_key_file = std::fs::read_to_string(rsa_private_key_path)?;
        let rsa_private_key: RsaPrivateKey = match pkcs8::DecodePrivateKey::from_pkcs8_encrypted_pem(
            &rsa_private_key_file,
            rsa_private_key_password.as_bytes(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return Err(format!("cannot load rsa private key: {}", e).into());
            }
        };
        let rsa_public_key = rsa_private_key.to_public_key();
        if rsa_public_key.n() < &rsa::BigUint::from_slice(&[MIN_RSA_MODULUS_SIZE]) {
            return Err(format!("modulus is < {} bytes", MIN_RSA_MODULUS_SIZE).into());
        }
        Ok(RsaKeys {
            private_key: rsa_private_key,
            public_key: rsa_public_key,
        })
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Encrypt a String slice with stored RSA public key
    /// using PKCS#1 v1.5 padding and return it as `Vec<u8>`.
    #[inline(always)]
    fn encrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        unencrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError> {
        let mut rng = rand::thread_rng();
        match self
            .public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, unencrypted_bytes)
        {
            Err(e) => Err(format!("Could not rsa encrypt given value: {}", &e).into()),
            Ok(buf) => Ok(buf),
        }
    }

    /// Encrypt a String slice with stored RSA public key
    /// using OAEP padding and return it as `Vec<u8>`.
    ///
    /// Optimal Asymmetric Encryption Padding (OAEP) is defined
    /// in PKCS#1 v2.2. Unlike the older PKCS#1 v1.5 padding
    /// (vulnerable to padding oracle attacks), OAEP provides
    /// provable security under rigorous cryptographic assumptions.
    ///
    /// The Java people refer to it as
    ///
    /// `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
    #[inline(always)]
    fn encrypt_bytes_oaep_padding_to_vec(
        &self,
        unencrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError>
    where
        Self: Sized,
    {
        let mut rng = rand::thread_rng();
        let oaep_padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
        match self
            .public_key
            .encrypt(&mut rng, oaep_padding, unencrypted_bytes)
        {
            Err(e) => Err(format!("Could not rsa encrypt given value: {}", &e).into()),
            Ok(buf) => Ok(buf),
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Decryption
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    #[inline(always)]
    fn decrypt_bytes_pkcs1v15_padding_to_vec(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError> {
        match self.private_key.decrypt(Pkcs1v15Encrypt, encrypted_bytes) {
            Err(e) => Err(format!("Could not rsa decrypt given value: {}", &e).into()),
            Ok(buf) => Ok(buf),
        }
    }

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// OAEP padding using the stored RSA private key
    /// and return it as plaintext String.
    ///
    /// Optimal Asymmetric Encryption Padding (OAEP) is defined
    /// in PKCS#1 v2.2. Unlike the older PKCS#1 v1.5 padding
    /// (vulnerable to padding oracle attacks), OAEP provides
    /// provable security under rigorous cryptographic assumptions.
    ///
    /// The Java people refer to it as
    ///
    /// `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
    #[inline(always)]
    fn decrypt_bytes_oaep_padding_to_vec(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<Vec<u8>, HacaoiError> {
        let oaep_padding = Oaep::new_with_mgf_hash::<Sha256, Sha1>();
        match self.private_key.decrypt(oaep_padding, encrypted_bytes) {
            Err(e) => Err(format!("Could not rsa decrypt given value: {}", &e).into()),
            Ok(buf) => Ok(buf),
        }
    }

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    #[inline(always)]
    fn decrypt_bytes_pkcs1v15_padding_to_string(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<String, HacaoiError> {
        let decrypted_bytes = self.decrypt_bytes_pkcs1v15_padding_to_vec(encrypted_bytes)?;
        let decrypted_data = match String::from_utf8(decrypted_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(HacaoiError::FromUtf8Error(e));
            }
        };
        Ok(decrypted_data.trim_matches(char::from(0)).to_string())
    }

    /// Decrypt `&[u8]` with RSA encrypted data and
    /// PKCS#1 v1.5 padding using the stored RSA private key
    /// and return it as plaintext String.
    ///
    /// Optimal Asymmetric Encryption Padding (OAEP) is defined
    /// in PKCS#1 v2.2. Unlike the older PKCS#1 v1.5 padding
    /// (vulnerable to padding oracle attacks), OAEP provides
    /// provable security under rigorous cryptographic assumptions.
    ///
    /// The Java people refer to it as
    ///
    /// `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`.
    #[inline(always)]
    fn decrypt_bytes_oaep_padding_to_string(
        &self,
        encrypted_bytes: &[u8],
    ) -> Result<String, HacaoiError> {
        let decrypted_bytes = self.decrypt_bytes_oaep_padding_to_vec(encrypted_bytes)?;
        let decrypted_data = match String::from_utf8(decrypted_bytes) {
            Ok(s) => s,
            Err(e) => {
                return Err(HacaoiError::FromUtf8Error(e));
            }
        };
        Ok(decrypted_data.trim_matches(char::from(0)).to_string())
    }

    ////////////////////////////////////////////////////////////////////////////////////////////
    // Signature
    ////////////////////////////////////////////////////////////////////////////////////////////

    /// Create a sha512 signature for the given
    /// string slice using the rsa private key.
    #[inline(always)]
    fn sign_str_sha512(&self, data_to_sign: &str) -> Result<Vec<u8>, HacaoiError> {
        let signing_key = SigningKey::<Sha512>::new(self.private_key.clone());
        let mut rng = rand::thread_rng();
        let signature: rsa::pkcs1v15::Signature =
            signing_key.sign_with_rng(&mut rng, data_to_sign.as_bytes());
        Ok(signature.to_vec())
    }

    /// Validate a `&[u8]` signature that was created using
    /// the corresponding rsa private key.
    #[inline(always)]
    fn validate_sha512_bytes_signature(
        &self,
        signed_data: &str,
        signature_bytes: &[u8],
    ) -> Result<(), HacaoiError> {
        let signing_key = SigningKey::<Sha512>::new(self.private_key.clone());
        let verifying_key = signing_key.verifying_key();
        let signature = match rsa::pkcs1v15::Signature::try_from(signature_bytes) {
            Err(e) => {
                return Err(format!("Could not convert signature: {}", &e).into());
            }
            Ok(s) => s,
        };
        match verifying_key.verify(signed_data.as_bytes(), &signature) {
            Err(e) => Err(format!("Invalid signature: {}", &e).into()),
            Ok(_) => Ok(()),
        }
    }
}
