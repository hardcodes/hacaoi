/// Combines all error types in one enum to ease
/// error propagation. A finger exercise in trying
/// to avoid anyhow (nothing bad about it).
#[derive(Debug)]
pub enum HacaoiError {
    /// [`Error`](std::io::Error) for I/O operations of the [`Read`](std::io::Read), [`Write`](std::io::Write), [`Seek`](std::io::Seek), and
    /// associated traits.
    IoError(std::io::Error),
    /// Possible [`FromUtf8Error`](std::string::FromUtf8Error)s when converting a `String` from a UTF-8 byte vector.
    FromUtf8Error(std::string::FromUtf8Error),
    /// [`Utf8Error`](std::str::Utf8Error)s which can occur when attempting to interpret a sequence of [`u8`]
    /// as a string.
    Utf8Error(std::str::Utf8Error),
    /// Collection of [`Error`](openssl::error::Error)s from OpenSSL.
    #[cfg(feature = "openssl")]
    OpenSslErrorStack(openssl::error::ErrorStack),
    /// [`Error`](rsa::Error) from the Rust Crypto RSA crate.
    #[cfg(feature = "rust-crypto")]
    RsaError(rsa::Error),
    /// Plaintext error messages as [`String`]
    StringError(std::string::String),
    /// [`DecodeError`](base64::DecodeError)s that can occur while decoding bae64.
    #[cfg(feature = "b64")]
    Base64DecodeError(base64::DecodeError),
}

impl std::fmt::Display for HacaoiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HacaoiError::IoError(e) => write!(f, "{}", e),
            HacaoiError::FromUtf8Error(e) => write!(f, "{}", e),
            HacaoiError::Utf8Error(e) => write!(f, "{}", e),
            #[cfg(feature = "openssl")]
            HacaoiError::OpenSslErrorStack(e) => write!(f, "{:?}", e),
            #[cfg(feature = "rust-crypto")]
            HacaoiError::RsaError(e) => write!(f, "{}", e),
            HacaoiError::StringError(e) => write!(f, "{}", e),
            #[cfg(feature = "b64")]
            HacaoiError::Base64DecodeError(e) => write!(f, "{}", e),
        }
    }
}

// Make it an error!
impl std::error::Error for HacaoiError {}

impl From<std::io::Error> for HacaoiError {
    fn from(err: std::io::Error) -> Self {
        HacaoiError::IoError(err)
    }
}

impl From<std::string::FromUtf8Error> for HacaoiError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        HacaoiError::FromUtf8Error(err)
    }
}

impl From<std::str::Utf8Error> for HacaoiError {
    fn from(err: std::str::Utf8Error) -> Self {
        HacaoiError::Utf8Error(err)
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for HacaoiError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        HacaoiError::OpenSslErrorStack(err)
    }
}

#[cfg(feature = "rust-crypto")]
impl From<rsa::Error> for HacaoiError {
    fn from(err: rsa::Error) -> Self {
        HacaoiError::RsaError(err)
    }
}

impl From<std::string::String> for HacaoiError {
    fn from(err: std::string::String) -> Self {
        HacaoiError::StringError(err)
    }
}

#[cfg(feature = "b64")]
impl From<base64::DecodeError> for HacaoiError {
    fn from(err: base64::DecodeError) -> Self {
        HacaoiError::Base64DecodeError(err)
    }
}
