//! At-rest identity storage (DESIGN.md ADR-005). Behind the `storage` feature.
//!
//! Persists the BIP39 mnemonic so a device keeps a stable identity across runs,
//! without leaving it in plaintext. Two backends:
//!
//! - **Keyring (primary):** the OS keychain (macOS Keychain, Windows Credential
//!   Manager, Linux Secret Service). Seamless, no passphrase. Used when available.
//! - **age file (fallback):** an `age` scrypt/passphrase-encrypted file at
//!   `<dir>/identity.age`, for headless/server hosts with no keychain. The
//!   passphrase comes from `LATTICE_PASSPHRASE` or an interactive prompt.
//!
//! The chosen backend is recorded in `<dir>/config.toml`. A legacy plaintext
//! `<dir>/identity` file (from earlier versions) is migrated on first load:
//! re-encrypted under the new scheme, with the plaintext renamed to
//! `identity.legacy.bak` (not deleted) so nothing is lost.
//!
//! Env overrides: `LATTICE_DIR` (storage dir, default `~/.lattice`),
//! `LATTICE_PASSPHRASE` (age passphrase, skips the prompt),
//! `LATTICE_STORAGE=age` (force the age backend, skip the keychain entirely).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Keypair;
use lattice_core::{CryptoSuite, Error, Result};

const KEYRING_SERVICE: &str = "lattice";
const KEYRING_USER: &str = "identity-mnemonic";

/// Which backend an identity is stored under.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum StorageBackend {
    /// OS keychain (Secret Service / Keychain / Credential Manager).
    Keyring,
    /// `age` passphrase-encrypted file.
    AgeFile,
}

/// Result of [`IdentityStore::load_or_create`].
pub struct LoadedIdentity {
    /// The recovered or freshly-generated identity.
    pub keypair: Keypair,
    /// Where the mnemonic is stored.
    pub backend: StorageBackend,
    /// True if a new identity was generated this call.
    pub created: bool,
    /// True if migrated from a legacy plaintext file this call.
    pub migrated: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    backend: Option<StorageBackend>,
}

/// A per-directory identity store.
pub struct IdentityStore {
    dir: PathBuf,
}

impl IdentityStore {
    /// Open the default store (`$LATTICE_DIR` or `~/.lattice`).
    pub fn open_default() -> Self {
        let dir = std::env::var("LATTICE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".lattice")
            });
        Self { dir }
    }

    /// Open a store rooted at `dir`.
    pub fn with_dir(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("config.toml")
    }
    fn age_path(&self) -> PathBuf {
        self.dir.join("identity.age")
    }
    fn legacy_path(&self) -> PathBuf {
        self.dir.join("identity")
    }

    /// Load the stored identity, migrating a legacy plaintext file if present,
    /// or generate and persist a fresh one on first use.
    pub fn load_or_create(&self, suite: CryptoSuite) -> Result<LoadedIdentity> {
        std::fs::create_dir_all(&self.dir).map_err(|e| io("create dir", e))?;
        let cfg = self.read_config();

        // Migrate a legacy plaintext mnemonic (only if nothing is stored yet).
        let legacy = self.legacy_path();
        if cfg.backend.is_none() && legacy.exists() {
            let phrase = Zeroizing::new(
                std::fs::read_to_string(&legacy)
                    .map_err(|e| io("read legacy identity", e))?
                    .trim()
                    .to_string(),
            );
            let keypair = Keypair::from_mnemonic(suite, &phrase)?;
            let backend = self.persist(&phrase)?;
            let bak = self.dir.join("identity.legacy.bak");
            let _ = std::fs::rename(&legacy, &bak);
            return Ok(LoadedIdentity { keypair, backend, created: false, migrated: true });
        }

        // Load an existing identity.
        if let Some(phrase) = self.try_load(&cfg)? {
            let keypair = Keypair::from_mnemonic(suite, &phrase)?;
            let backend = cfg.backend.unwrap_or(StorageBackend::Keyring);
            return Ok(LoadedIdentity { keypair, backend, created: false, migrated: false });
        }

        // First run: generate and persist.
        let keypair = Keypair::generate(suite)?;
        let phrase = Zeroizing::new(keypair.mnemonic().to_string());
        let backend = self.persist(&phrase)?;
        Ok(LoadedIdentity { keypair, backend, created: true, migrated: false })
    }

    fn try_load(&self, cfg: &Config) -> Result<Option<Zeroizing<String>>> {
        match cfg.backend {
            Some(StorageBackend::Keyring) => Ok(keyring_load()),
            Some(StorageBackend::AgeFile) => {
                if self.age_path().exists() {
                    Ok(Some(self.age_load()?))
                } else {
                    Ok(None)
                }
            }
            None => {
                // No recorded backend: probe keychain, then an age file.
                if keyring_enabled() {
                    if let Some(p) = keyring_load() {
                        return Ok(Some(p));
                    }
                }
                if self.age_path().exists() {
                    return Ok(Some(self.age_load()?));
                }
                Ok(None)
            }
        }
    }

    /// Store the mnemonic via the keychain if available, else the age file.
    fn persist(&self, mnemonic: &str) -> Result<StorageBackend> {
        if keyring_enabled() && keyring_save(mnemonic) {
            self.write_config(StorageBackend::Keyring)?;
            Ok(StorageBackend::Keyring)
        } else {
            self.age_save(mnemonic)?;
            self.write_config(StorageBackend::AgeFile)?;
            Ok(StorageBackend::AgeFile)
        }
    }

    fn age_save(&self, mnemonic: &str) -> Result<()> {
        let pass = passphrase(true)?;
        let recipient = age::scrypt::Recipient::new(secret(&pass));
        let ct = age::encrypt(&recipient, mnemonic.as_bytes())
            .map_err(|e| Error::Crypto(format!("age encrypt: {e}")))?;
        write_file_0600(&self.age_path(), &ct)?;
        Ok(())
    }

    fn age_load(&self) -> Result<Zeroizing<String>> {
        let ct = std::fs::read(self.age_path()).map_err(|e| io("read identity.age", e))?;
        let pass = passphrase(false)?;
        let identity = age::scrypt::Identity::new(secret(&pass));
        let pt = age::decrypt(&identity, &ct)
            .map_err(|e| Error::Crypto(format!("age decrypt (wrong passphrase?): {e}")))?;
        String::from_utf8(pt)
            .map(Zeroizing::new)
            .map_err(|_| Error::Crypto("stored identity is not valid UTF-8".into()))
    }

    fn read_config(&self) -> Config {
        std::fs::read_to_string(self.config_path())
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn write_config(&self, backend: StorageBackend) -> Result<()> {
        let cfg = Config { backend: Some(backend) };
        let s = toml::to_string(&cfg).map_err(|e| Error::Other(format!("config encode: {e}")))?;
        std::fs::write(self.config_path(), s).map_err(|e| io("write config", e))
    }
}

// --- backends --------------------------------------------------------------

/// Whether to try the OS keychain (disabled by `LATTICE_STORAGE=age`).
fn keyring_enabled() -> bool {
    std::env::var("LATTICE_STORAGE").map(|v| v != "age").unwrap_or(true)
}

fn keyring_save(mnemonic: &str) -> bool {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .and_then(|e| e.set_password(mnemonic))
        .is_ok()
}

fn keyring_load() -> Option<Zeroizing<String>> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .and_then(|e| e.get_password())
        .ok()
        .map(Zeroizing::new)
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("LATTICE_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    let p = rpassword::prompt_password("Lattice identity passphrase: ")
        .map_err(|e| io("read passphrase", e))?;
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| io("read passphrase", e))?;
        if p != again {
            return Err(Error::Other("passphrases do not match".into()));
        }
    }
    Ok(Zeroizing::new(p))
}

fn secret(p: &Zeroizing<String>) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(p.as_str().to_owned())
}

fn io(ctx: &str, e: std::io::Error) -> Error {
    Error::Other(format!("{ctx}: {e}"))
}

fn write_file_0600(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| io("create file", e))?;
        f.write_all(bytes).map_err(|e| io("write file", e))
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).map_err(|e| io("write file", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_core::Identity; // for Keypair::peer_id in assertions

    // Force the age backend so tests never touch the OS keychain / dbus.
    fn with_age_env(dir: &std::path::Path) {
        std::env::set_var("LATTICE_STORAGE", "age");
        std::env::set_var("LATTICE_PASSPHRASE", "correct horse battery staple");
        std::env::set_var("LATTICE_DIR", dir);
    }

    #[test]
    fn age_roundtrip_persists_identity() {
        let tmp = std::env::temp_dir().join(format!("lattice-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        with_age_env(&tmp);
        let store = IdentityStore::with_dir(tmp.clone());

        let first = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(first.created);
        assert_eq!(first.backend, StorageBackend::AgeFile);
        assert!(tmp.join("identity.age").exists());

        let again = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(!again.created);
        assert_eq!(first.keypair.peer_id(), again.keypair.peer_id(), "stable identity");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn migrates_legacy_plaintext() {
        let tmp = std::env::temp_dir().join(format!("lattice-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        with_age_env(&tmp);

        // Seed a legacy plaintext mnemonic from a throwaway identity.
        let original = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        std::fs::write(tmp.join("identity"), original.mnemonic()).unwrap();

        let store = IdentityStore::with_dir(tmp.clone());
        let loaded = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(loaded.migrated);
        assert_eq!(loaded.keypair.peer_id(), original.peer_id(), "migration preserves identity");
        assert!(tmp.join("identity.age").exists(), "re-encrypted");
        assert!(tmp.join("identity.legacy.bak").exists(), "plaintext backed up, not deleted");
        assert!(!tmp.join("identity").exists(), "plaintext removed from active path");

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
