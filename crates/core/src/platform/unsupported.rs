//! Unix targets without a qualified credential store. Every operation fails closed.
use crate::{broker::BrokerError, process::PeerIdentity, vault::DeviceKey};
use std::{os::unix::net::UnixStream, path::PathBuf};

pub(crate) struct KeyStore;

impl KeyStore {
    pub(crate) fn connect() -> Result<Self, BrokerError> {
        Err(BrokerError::KeyStoreUnavailable)
    }

    pub(crate) fn put(&self, _id: &[u8], _key: &DeviceKey) -> Result<(), BrokerError> {
        Err(BrokerError::KeyStoreUnavailable)
    }

    pub(crate) fn get(&self, _id: &[u8]) -> Result<DeviceKey, BrokerError> {
        Err(BrokerError::KeyStoreUnavailable)
    }

    pub(crate) fn remove(&self, _id: &[u8]) -> Result<(), BrokerError> {
        Err(BrokerError::KeyStoreUnavailable)
    }
}

/// No qualified agent endpoint directory.
pub fn runtime_dir() -> Option<PathBuf> {
    None
}

/// No qualified caller identity; every connection is refused.
pub fn same_user_peer(_stream: &UnixStream) -> Option<PeerIdentity> {
    None
}
