//! Operating-system integrations: credential store, agent endpoint directory, and caller identity.
//! Everything outside this module is portable Unix code.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::KeyStore;
#[cfg(target_os = "linux")]
pub use linux::{runtime_dir, same_user_peer};

#[cfg(all(unix, not(target_os = "linux")))]
mod unsupported;
#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) use unsupported::KeyStore;
#[cfg(all(unix, not(target_os = "linux")))]
pub use unsupported::{runtime_dir, same_user_peer};

/// Whether this platform's credential store and agent transport are qualified. When false, the
/// broker reports `Unavailable` and the desktop does not listen for agents.
pub const QUALIFIED: bool = cfg!(target_os = "linux");
