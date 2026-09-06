//! Explicit GNOME login collection adapter. Never creates or unlocks collections.
use crate::{broker::BrokerError, vault::DeviceKey};
use secret_service::{EncryptionType, blocking::SecretService};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    time::Duration,
};
use zeroize::Zeroizing;

pub(crate) struct KeyStore {
    service: SecretService<'static>,
}

impl KeyStore {
    pub(crate) fn connect() -> Result<Self, BrokerError> {
        let conn = zbus::blocking::connection::Builder::session()
            .map_err(|_| BrokerError::KeyStoreUnavailable)?
            .method_timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let bus = zbus::blocking::Proxy::new(
            &conn,
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
        )
        .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let pid: u32 = bus
            .call("GetConnectionUnixProcessID", &("org.freedesktop.secrets",))
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let executable = fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if executable != std::path::Path::new("/usr/bin/gnome-keyring-daemon")
            || fs::metadata(&executable)
                .map_err(|_| BrokerError::KeyStoreUnavailable)?
                .uid()
                != 0
        {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        Self::protected_file()?;
        let service = SecretService::connect_with_existing(EncryptionType::Dh, conn)
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let store = Self { service };
        store.collection()?;
        Ok(store)
    }

    fn protected_file() -> Result<(), BrokerError> {
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
            .ok_or(BrokerError::KeyStoreUnavailable)?;
        if !base.is_absolute() {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        let path = base.join("keyrings/login.keyring");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let meta = file
            .metadata()
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if !meta.is_file()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        let mut header = [0; 16];
        file.read_exact(&mut header)
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if header != *b"GnomeKeyring\n\r\0\n" {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        Ok(())
    }

    fn collection(&self) -> Result<secret_service::blocking::Collection<'_>, BrokerError> {
        Self::protected_file()?;
        let collection = self
            .service
            .get_collection_by_alias("login")
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if collection.collection_path.as_str() != "/org/freedesktop/secrets/collection/login"
            || collection
                .is_locked()
                .map_err(|_| BrokerError::KeyStoreUnavailable)?
        {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        Ok(collection)
    }

    pub(crate) fn put(&self, id: &[u8], key: &DeviceKey) -> Result<(), BrokerError> {
        let id = hex(id);
        let collection = self.collection()?;
        let attributes = HashMap::from([
            ("application", "local.latch.development"),
            ("device_id", id.as_str()),
        ]);
        if !collection
            .search_items(attributes.clone())
            .map_err(|_| BrokerError::KeyStoreUnavailable)?
            .is_empty()
        {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        let item = collection
            .create_item(
                "Latch development vault key",
                attributes,
                key.for_store(),
                false,
                "application/octet-stream",
            )
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        let verify = Zeroizing::new(
            item.get_secret()
                .map_err(|_| BrokerError::KeyStoreUnavailable)?,
        );
        if verify.as_slice() != key.for_store() {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        Self::protected_file()?;
        Ok(())
    }

    pub(crate) fn get(&self, id: &[u8]) -> Result<DeviceKey, BrokerError> {
        let id = hex(id);
        let collection = self.collection()?;
        let items = collection
            .search_items(HashMap::from([
                ("application", "local.latch.development"),
                ("device_id", id.as_str()),
            ]))
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if items.len() != 1 {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        let bytes = Zeroizing::new(
            items[0]
                .get_secret()
                .map_err(|_| BrokerError::KeyStoreUnavailable)?,
        );
        DeviceKey::from_store(bytes).map_err(|_| BrokerError::KeyStoreUnavailable)
    }

    // Used only for the current setup attempt whose item this process created.
    pub(crate) fn remove(&self, id: &[u8]) -> Result<(), BrokerError> {
        let id = hex(id);
        let collection = self.collection()?;
        let items = collection
            .search_items(HashMap::from([
                ("application", "local.latch.development"),
                ("device_id", id.as_str()),
            ]))
            .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        if items.len() > 1 {
            return Err(BrokerError::KeyStoreUnavailable);
        }
        for item in items {
            item.delete()
                .map_err(|_| BrokerError::KeyStoreUnavailable)?;
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
