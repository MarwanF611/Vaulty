//! Errors from OS integration.
//!
//! None of these carry user data: this crate never sees a decrypted secret. It
//! handles the *captured selection*, which is the user's own text on its way
//! into the vault, and even that is held as `Zeroizing` and never formatted
//! into an error.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The OS refused, or silently ignored, a synthetic keystroke. On macOS
    /// this is what an un-granted Accessibility permission looks like.
    #[error("the system did not accept a synthetic keystroke")]
    KeystrokeRejected,

    /// Accessibility (macOS) has not been granted.
    #[error("accessibility permission has not been granted")]
    PermissionDenied,

    /// Selection capture is not implemented for this platform.
    #[error("selection capture is not supported on this platform")]
    Unsupported,

    /// A system call returned something unusable.
    #[error("os call failed: {0}")]
    Os(&'static str),
}

pub type Result<T> = std::result::Result<T, PlatformError>;
