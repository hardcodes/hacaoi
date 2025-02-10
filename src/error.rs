/// Combines all error types in one enum to ease
/// error propagation. A finger exercise in trying
/// to avoid anyhow (nothing bad about it).
#[derive(Debug)]
pub enum HacaoiError {
    /// The error type for I/O operations of the [`Read`], [`Write`], [`Seek`], and
    /// associated traits.
    IoError(std::io::Error),
    /// A possible error value when converting a `String` from a UTF-8 byte vector.
    FromUtf8Error(std::string::FromUtf8Error),
    /// Collection of [`Error`]s from OpenSSL.
    /// #[cfg(feature = "openssl")]
    OpenSslErrorStack(openssl::error::ErrorStack),
    /// Plaintext error messages as [`String`]
    StringError(std::string::String),
}

impl std::fmt::Display for HacaoiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HacaoiError::IoError(e) => write!(f, "{}", e),
            HacaoiError::FromUtf8Error(e) => write!(f, "{}", e),
            #[cfg(feature = "openssl")]
            HacaoiError::OpenSslErrorStack(e) => write!(f, "{:?}", e),
            HacaoiError::StringError(e) => write!(f, "{}", e),
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

#[cfg(feature = "openssl")]
impl From<openssl::error::ErrorStack> for HacaoiError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        HacaoiError::OpenSslErrorStack(err)
    }
}

impl From<std::string::String> for HacaoiError {
    fn from(err: std::string::String) -> Self {
        HacaoiError::StringError(err)
    }
}
