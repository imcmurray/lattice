//! At-rest identity storage (DESIGN.md ADR-005, ADR-013). Behind the `storage`
//! feature.
//!
//! Persists BIP39 mnemonics so a device keeps a stable identity across runs,
//! without leaving them in plaintext. A store holds two secret slots:
//!
//! - **root** — the recoverable root identity (account `identity-mnemonic` /
//!   `identity.age`). Needed only to issue/renew device certs and revocation
//!   lists; it can be removed from the store with [`IdentityStore::forget_root`]
//!   and restored from its phrase with [`IdentityStore::import_root`].
//! - **device** — the everyday Hybrid key (account `device-mnemonic` /
//!   `device.age`) plus its root-signed [`DeviceCert`] (`device.cert`) and the
//!   root's public identity (`root.pub`). The device mnemonic is never shown.
//!
//! Two backends, recorded in `<dir>/config.toml` and shared by both slots:
//!
//! - **Keyring (primary):** the OS keychain (macOS Keychain, Windows Credential
//!   Manager, Linux Secret Service), service `lattice`. Seamless, no passphrase.
//! - **age file (fallback):** an `age` scrypt/passphrase-encrypted file
//!   (`<dir>/identity.age`, `<dir>/device.age`, mode 0600), for headless hosts.
//!   The passphrase comes from `LATTICE_PASSPHRASE` or an interactive prompt.
//!
//! Other files: `device.cert`, `root.pub`, `revocation.bin` (this root's latest
//! [`RevocationList`]) and `peers/<root peer id hex>.rev` (a bounded cache of
//! other roots' lists, at most [`MAX_PEER_REVOCATIONS`]).
//!
//! A legacy plaintext `<dir>/identity` file is migrated on first load:
//! re-encrypted under the new scheme, then deleted (no `.bak` copy).
//!
//! Keyring errors other than "no entry" are fatal (fail closed): nothing is
//! generated or written. With a recorded keyring backend a failure to save a
//! secret is an error, never a silent fallback to a file. On hosts without a
//! working keychain set `LATTICE_STORAGE=age`.
//!
//! `load_or_create` never regenerates a forgotten root: if `root.pub` exists
//! but no root secret does, it fails and points at `import-root`.
//!
//! Env overrides: `LATTICE_DIR` (storage dir, default `~/.lattice`),
//! `LATTICE_PASSPHRASE` (age passphrase, skips the prompt),
//! `LATTICE_STORAGE=age` (force the age backend, skip the keychain entirely).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{DeviceCert, Keypair, PublicIdentity, RevocationList, MAX_REVOCATION_LIST_LEN};
use lattice_core::{CryptoSuite, Error, Identity, Result, Verify};

const KEYRING_SERVICE: &str = "lattice";
const KEYRING_USER: &str = "identity-mnemonic";
const KEYRING_DEVICE_USER: &str = "device-mnemonic";

/// Max number of per-root peer revocation files under `<dir>/peers/`.
pub const MAX_PEER_REVOCATIONS: usize = 256;

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

/// Result of [`IdentityStore::load_device`].
pub struct LoadedDevice {
    /// The device keypair (Hybrid).
    pub keypair: Keypair,
    /// Root-signed certificate for the device key.
    pub cert: DeviceCert,
    /// The root's public identity (from `root.pub`; no secret touched).
    pub root: PublicIdentity,
    /// Where the device mnemonic is stored.
    pub backend: StorageBackend,
}

#[derive(Serialize, Deserialize, Default)]
struct Config {
    backend: Option<StorageBackend>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Root,
    Device,
}

impl Slot {
    fn account(self) -> &'static str {
        match self {
            Slot::Root => KEYRING_USER,
            Slot::Device => KEYRING_DEVICE_USER,
        }
    }
    fn age_name(self) -> &'static str {
        match self {
            Slot::Root => "identity.age",
            Slot::Device => "device.age",
        }
    }
}

/// Keychain operations, injectable so fail-closed behaviour is testable
/// without a keychain. All take the keyring account name.
struct Kr<'a> {
    load: &'a dyn Fn(&str) -> Result<Option<Zeroizing<String>>>,
    save: &'a dyn Fn(&str, &str) -> bool,
    delete: &'a dyn Fn(&str) -> Result<()>,
}

fn real_kr() -> Kr<'static> {
    Kr {
        load: &keyring_load,
        save: &keyring_save,
        delete: &keyring_delete,
    }
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
    fn age_path(&self, slot: Slot) -> PathBuf {
        self.dir.join(slot.age_name())
    }
    fn legacy_path(&self) -> PathBuf {
        self.dir.join("identity")
    }
    fn cert_path(&self) -> PathBuf {
        self.dir.join("device.cert")
    }
    fn root_pub_path(&self) -> PathBuf {
        self.dir.join("root.pub")
    }
    fn revocation_path(&self) -> PathBuf {
        self.dir.join("revocation.bin")
    }
    fn peers_dir(&self) -> PathBuf {
        self.dir.join("peers")
    }

    // --- root ---------------------------------------------------------------

    /// Load the stored root identity, migrating a legacy plaintext file if
    /// present, or generate and persist a fresh one on first use.
    ///
    /// Never regenerates a forgotten root: if `root.pub` exists but no root
    /// secret is stored this fails (run `lattice-net import-root`).
    pub fn load_or_create(&self, suite: CryptoSuite) -> Result<LoadedIdentity> {
        self.load_or_create_with(suite, &real_kr())
    }

    fn load_or_create_with(&self, suite: CryptoSuite, kr: &Kr) -> Result<LoadedIdentity> {
        std::fs::create_dir_all(&self.dir).map_err(|e| io("create dir", e))?;
        if let Some(loaded) = self.load_existing_root(suite, kr)? {
            return Ok(loaded);
        }
        if self.root_pub_path().exists() {
            return Err(Error::Other(
                "the root identity is not in this store (it was forgotten); refusing to \
                 generate a new one — run `lattice-net import-root` to restore it"
                    .into(),
            ));
        }

        // First run: generate and persist.
        let keypair = Keypair::generate(suite)?;
        let phrase = Zeroizing::new(keypair.mnemonic().to_string());
        let backend = self.persist_slot(Slot::Root, &phrase, kr)?;
        self.ensure_root_pub(keypair.public())?;
        Ok(LoadedIdentity {
            keypair,
            backend,
            created: true,
            migrated: false,
        })
    }

    /// Load the root if one is stored (migrating a legacy plaintext file),
    /// else `Ok(None)`. Never generates.
    pub fn load_root(&self, suite: CryptoSuite) -> Result<Option<LoadedIdentity>> {
        self.load_root_with(suite, &real_kr())
    }

    fn load_root_with(&self, suite: CryptoSuite, kr: &Kr) -> Result<Option<LoadedIdentity>> {
        self.load_existing_root(suite, kr)
    }

    fn load_existing_root(&self, suite: CryptoSuite, kr: &Kr) -> Result<Option<LoadedIdentity>> {
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
            self.check_root_pub(keypair.public())?;
            let backend = self.persist_slot(Slot::Root, &phrase, kr)?;
            std::fs::remove_file(&legacy).map_err(|e| {
                Error::Other(format!(
                    "remove legacy plaintext identity {}: {e}",
                    legacy.display()
                ))
            })?;
            self.ensure_root_pub(keypair.public())?;
            return Ok(Some(LoadedIdentity {
                keypair,
                backend,
                created: false,
                migrated: true,
            }));
        }

        // Load an existing identity.
        if let Some(phrase) = self.try_load_slot(Slot::Root, &cfg, kr)? {
            let keypair = Keypair::from_mnemonic(suite, &phrase)?;
            self.check_root_pub(keypair.public())?;
            self.ensure_root_pub(keypair.public())?;
            let backend = self.backend_of(Slot::Root, &cfg);
            return Ok(Some(LoadedIdentity {
                keypair,
                backend,
                created: false,
                migrated: false,
            }));
        }
        Ok(None)
    }

    /// Whether a root secret is stored. Age backend: whether `identity.age`
    /// exists (no passphrase). Keyring: reads the entry (non-NoEntry errors
    /// are fatal). No recorded backend: legacy file or probe.
    pub fn has_root(&self) -> Result<bool> {
        self.has_root_with(&real_kr())
    }

    fn has_root_with(&self, kr: &Kr) -> Result<bool> {
        let cfg = self.read_config();
        if cfg.backend.is_none() && self.legacy_path().exists() {
            return Ok(true);
        }
        self.slot_present(Slot::Root, &cfg, kr)
    }

    /// The root's public identity from `root.pub`, if the file exists.
    pub fn root_public(&self) -> Result<Option<PublicIdentity>> {
        match std::fs::read(self.root_pub_path()) {
            Ok(b) => Ok(Some(PublicIdentity::from_bytes(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("read root.pub", e)),
        }
    }

    /// Delete the root secret (and any legacy plaintext file) from this store.
    /// Requires a stored device (secret, `device.cert`, `root.pub`). Leaves the
    /// device, cert, `root.pub`, revocation files and `config.toml` intact.
    /// Back up the recovery phrase first: this is irreversible.
    pub fn forget_root(&self) -> Result<()> {
        self.forget_root_with(&real_kr())
    }

    fn forget_root_with(&self, kr: &Kr) -> Result<()> {
        let cfg = self.read_config();
        let device_ok = self.slot_present(Slot::Device, &cfg, kr)?
            && self.cert_path().exists()
            && self.root_pub_path().exists();
        if !device_ok {
            return Err(Error::Other(
                "refusing to forget the root: no complete device (key, certificate and \
                 root.pub) is stored here"
                    .into(),
            ));
        }
        if cfg.backend == Some(StorageBackend::Keyring)
            || (cfg.backend.is_none() && keyring_enabled())
        {
            (kr.delete)(Slot::Root.account())?;
        }
        remove_if_exists(&self.age_path(Slot::Root))?;
        remove_if_exists(&self.legacy_path())?;
        Ok(())
    }

    /// Restore the root from its recovery phrase. Errors on an invalid phrase,
    /// or if this store belongs to / holds a different root. Importing the same
    /// root twice is fine.
    pub fn import_root(&self, suite: CryptoSuite, phrase: &str) -> Result<LoadedIdentity> {
        self.import_root_with(suite, phrase, &real_kr())
    }

    fn import_root_with(
        &self,
        suite: CryptoSuite,
        phrase: &str,
        kr: &Kr,
    ) -> Result<LoadedIdentity> {
        let keypair = Keypair::from_mnemonic(suite, phrase)?;
        let pid = keypair.peer_id();
        if let Some(existing) = self.root_public()? {
            if existing.peer_id() != pid {
                return Err(Error::Other(format!(
                    "this store belongs to root {}",
                    existing.peer_id().fingerprint()
                )));
            }
        }
        std::fs::create_dir_all(&self.dir).map_err(|e| io("create dir", e))?;
        let cfg = self.read_config();
        let backend = if let Some(stored) = self.try_load_slot(Slot::Root, &cfg, kr)? {
            if Keypair::from_mnemonic(suite, &stored)?.peer_id() != pid {
                return Err(Error::Other(
                    "a different root identity is already stored here".into(),
                ));
            }
            self.backend_of(Slot::Root, &cfg)
        } else {
            self.persist_slot(Slot::Root, keypair.mnemonic(), kr)?
        };
        self.ensure_root_pub(keypair.public())?;
        Ok(LoadedIdentity {
            keypair,
            backend,
            created: false,
            migrated: false,
        })
    }

    // --- device -------------------------------------------------------------

    /// Load the device key, cert and root public identity. Never touches the
    /// root secret. `Ok(None)` if no device secret is stored; `Err` if one is
    /// but the cert / `root.pub` are missing, unparsable or inconsistent.
    /// Expiry is not checked (the caller decides).
    pub fn load_device(&self, suite: CryptoSuite) -> Result<Option<LoadedDevice>> {
        self.load_device_with(suite, &real_kr())
    }

    fn load_device_with(&self, suite: CryptoSuite, kr: &Kr) -> Result<Option<LoadedDevice>> {
        let cfg = self.read_config();
        let Some(phrase) = self.try_load_slot(Slot::Device, &cfg, kr)? else {
            return Ok(None);
        };
        let keypair = Keypair::from_mnemonic(suite, &phrase)?;
        let cert_bytes = std::fs::read(self.cert_path()).map_err(|e| io("read device.cert", e))?;
        let cert = DeviceCert::from_bytes(&cert_bytes)?;
        let root = self
            .root_public()?
            .ok_or_else(|| Error::Other("device key present but root.pub is missing".into()))?;
        check_device_consistency(&keypair, &cert, &root)?;
        Ok(Some(LoadedDevice {
            keypair,
            cert,
            root,
            backend: self.backend_of(Slot::Device, &cfg),
        }))
    }

    /// Persist a device key with its cert and the root's public identity.
    /// Validates consistency first (nothing is written on error). Replacing the
    /// device key with a different one is allowed.
    pub fn store_device(
        &self,
        device: &Keypair,
        cert: &DeviceCert,
        root: &PublicIdentity,
    ) -> Result<StorageBackend> {
        self.store_device_with(device, cert, root, &real_kr())
    }

    fn store_device_with(
        &self,
        device: &Keypair,
        cert: &DeviceCert,
        root: &PublicIdentity,
        kr: &Kr,
    ) -> Result<StorageBackend> {
        check_device_consistency(device, cert, root)?;
        std::fs::create_dir_all(&self.dir).map_err(|e| io("create dir", e))?;
        let cfg = self.read_config();
        let same = match self.try_load_slot(Slot::Device, &cfg, kr)? {
            Some(stored) => *stored == device.mnemonic(),
            None => false,
        };
        let backend = if same {
            self.backend_of(Slot::Device, &cfg)
        } else {
            self.persist_slot(Slot::Device, device.mnemonic(), kr)?
        };
        write_atomic(&self.cert_path(), &cert.to_bytes())?;
        write_atomic(&self.root_pub_path(), &root.to_bytes())?;
        Ok(backend)
    }

    /// Generate a fresh device key under `suite`, have `root` certify it until
    /// `not_after` (Unix seconds), and persist everything.
    pub fn provision_device(
        &self,
        root: &Keypair,
        suite: CryptoSuite,
        not_after: u64,
    ) -> Result<LoadedDevice> {
        self.provision_device_with(root, suite, not_after, &real_kr())
    }

    fn provision_device_with(
        &self,
        root: &Keypair,
        suite: CryptoSuite,
        not_after: u64,
        kr: &Kr,
    ) -> Result<LoadedDevice> {
        let device = Keypair::generate(suite)?;
        let cert = root.authorize_device(device.public(), not_after)?;
        let backend = self.store_device_with(&device, &cert, root.public(), kr)?;
        Ok(LoadedDevice {
            keypair: device,
            cert,
            root: root.public().clone(),
            backend,
        })
    }

    // --- revocation ---------------------------------------------------------

    /// This root's latest list (`revocation.bin`). `None` if absent, `Err` if
    /// it does not parse.
    pub fn load_revocation(&self) -> Result<Option<RevocationList>> {
        read_revocation(&self.revocation_path())
    }

    /// Persist this root's list to `revocation.bin`.
    pub fn store_revocation(&self, list: &RevocationList) -> Result<()> {
        std::fs::create_dir_all(&self.dir).map_err(|e| io("create dir", e))?;
        write_atomic(&self.revocation_path(), &list.to_bytes())
    }

    /// Cached lists of other roots (`peers/*.rev`), at most
    /// [`MAX_PEER_REVOCATIONS`]. Skips unparsable, oversized or misnamed files.
    /// The local store is trusted: lists were verified before being stored.
    pub fn load_peer_revocations(&self) -> Result<Vec<RevocationList>> {
        let mut names: Vec<PathBuf> = match std::fs::read_dir(self.peers_dir()) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "rev"))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io("read peers dir", e)),
        };
        names.sort();
        names.truncate(MAX_PEER_REVOCATIONS);
        let mut out = Vec::new();
        for p in names {
            let Ok(Some(list)) = read_revocation(&p) else {
                continue;
            };
            let want = format!("{}.rev", list.root());
            if p.file_name().and_then(|n| n.to_str()) != Some(want.as_str()) {
                continue;
            }
            out.push(list);
        }
        Ok(out)
    }

    /// Cache a (caller-verified) list for another root. Overwrites only if the
    /// new list supersedes the stored one. `Ok(false)` = not stored (not
    /// newer, or the cap of [`MAX_PEER_REVOCATIONS`] roots is reached).
    pub fn store_peer_revocation(&self, list: &RevocationList) -> Result<bool> {
        let dir = self.peers_dir();
        std::fs::create_dir_all(&dir).map_err(|e| io("create peers dir", e))?;
        let path = dir.join(format!("{}.rev", list.root()));
        if path.exists() {
            if let Ok(Some(old)) = read_revocation(&path) {
                if !list.supersedes(&old) {
                    return Ok(false);
                }
            }
        } else {
            let count = std::fs::read_dir(&dir)
                .map_err(|e| io("read peers dir", e))?
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "rev"))
                .count();
            if count >= MAX_PEER_REVOCATIONS {
                return Ok(false);
            }
        }
        write_atomic(&path, &list.to_bytes())?;
        Ok(true)
    }

    // --- internals ----------------------------------------------------------

    /// Error if `root.pub` exists and names a different root.
    fn check_root_pub(&self, root: &PublicIdentity) -> Result<()> {
        if let Some(existing) = self.root_public()? {
            if existing.peer_id() != root.peer_id() {
                return Err(Error::Other(format!(
                    "the stored root differs from root.pub (this store belongs to root {})",
                    existing.peer_id().fingerprint()
                )));
            }
        }
        Ok(())
    }

    fn ensure_root_pub(&self, root: &PublicIdentity) -> Result<()> {
        if !self.root_pub_path().exists() {
            write_atomic(&self.root_pub_path(), &root.to_bytes())?;
        }
        Ok(())
    }

    fn backend_of(&self, slot: Slot, cfg: &Config) -> StorageBackend {
        cfg.backend.unwrap_or(if self.age_path(slot).exists() {
            StorageBackend::AgeFile
        } else {
            StorageBackend::Keyring
        })
    }

    fn try_load_slot(
        &self,
        slot: Slot,
        cfg: &Config,
        kr: &Kr,
    ) -> Result<Option<Zeroizing<String>>> {
        match cfg.backend {
            Some(StorageBackend::Keyring) => (kr.load)(slot.account()),
            Some(StorageBackend::AgeFile) => {
                if self.age_path(slot).exists() {
                    Ok(Some(self.age_load(slot)?))
                } else {
                    Ok(None)
                }
            }
            None => {
                // No recorded backend: probe keychain, then an age file.
                if keyring_enabled() {
                    if let Some(p) = (kr.load)(slot.account())? {
                        return Ok(Some(p));
                    }
                }
                if self.age_path(slot).exists() {
                    return Ok(Some(self.age_load(slot)?));
                }
                Ok(None)
            }
        }
    }

    /// Like `try_load_slot` but never decrypts (no passphrase).
    fn slot_present(&self, slot: Slot, cfg: &Config, kr: &Kr) -> Result<bool> {
        match cfg.backend {
            Some(StorageBackend::Keyring) => Ok((kr.load)(slot.account())?.is_some()),
            Some(StorageBackend::AgeFile) => Ok(self.age_path(slot).exists()),
            None => {
                if keyring_enabled() && (kr.load)(slot.account())?.is_some() {
                    return Ok(true);
                }
                Ok(self.age_path(slot).exists())
            }
        }
    }

    /// Store a slot's mnemonic under the recorded backend (failing closed), or
    /// choose one (keychain if available, else age file) and record it.
    fn persist_slot(&self, slot: Slot, mnemonic: &str, kr: &Kr) -> Result<StorageBackend> {
        match self.read_config().backend {
            Some(StorageBackend::Keyring) => {
                if (kr.save)(slot.account(), mnemonic) {
                    Ok(StorageBackend::Keyring)
                } else {
                    Err(Error::Other(
                        "could not save the secret to the OS keychain (the recorded backend); \
                         not falling back to a file"
                            .into(),
                    ))
                }
            }
            Some(StorageBackend::AgeFile) => {
                self.age_save(slot, mnemonic)?;
                Ok(StorageBackend::AgeFile)
            }
            None => {
                if keyring_enabled() && (kr.save)(slot.account(), mnemonic) {
                    self.write_config(StorageBackend::Keyring)?;
                    Ok(StorageBackend::Keyring)
                } else {
                    self.age_save(slot, mnemonic)?;
                    self.write_config(StorageBackend::AgeFile)?;
                    Ok(StorageBackend::AgeFile)
                }
            }
        }
    }

    fn age_save(&self, slot: Slot, mnemonic: &str) -> Result<()> {
        let pass = passphrase(true)?;
        let recipient = age::scrypt::Recipient::new(secret(&pass));
        let ct = age::encrypt(&recipient, mnemonic.as_bytes())
            .map_err(|e| Error::Crypto(format!("age encrypt: {e}")))?;
        write_file_0600(&self.age_path(slot), &ct)?;
        Ok(())
    }

    fn age_load(&self, slot: Slot) -> Result<Zeroizing<String>> {
        let ct = std::fs::read(self.age_path(slot))
            .map_err(|e| io(&format!("read {}", slot.age_name()), e))?;
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
        let cfg = Config {
            backend: Some(backend),
        };
        let s = toml::to_string(&cfg).map_err(|e| Error::Other(format!("config encode: {e}")))?;
        std::fs::write(self.config_path(), s).map_err(|e| io("write config", e))
    }
}

/// The cert must be for this device, issued by `root`, with a valid signature
/// (expiry ignored: `not_after >= 1`, so `now = 0` never trips it).
fn check_device_consistency(
    device: &Keypair,
    cert: &DeviceCert,
    root: &PublicIdentity,
) -> Result<()> {
    if cert.device().peer_id() != device.peer_id() {
        return Err(Error::Crypto(
            "device.cert is for a different device key".into(),
        ));
    }
    if *cert.root() != root.peer_id() {
        return Err(Error::Crypto(
            "device.cert was not issued by the stored root".into(),
        ));
    }
    if !cert.verify(root, 0) {
        return Err(Error::Crypto("device.cert signature is invalid".into()));
    }
    Ok(())
}

/// Read a revocation file: `None` if absent; `Err` if oversized/unparsable.
fn read_revocation(path: &Path) -> Result<Option<RevocationList>> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io("stat revocation file", e)),
    };
    if meta.len() > MAX_REVOCATION_LIST_LEN as u64 {
        return Err(Error::Crypto("revocation file too large".into()));
    }
    let b = std::fs::read(path).map_err(|e| io("read revocation file", e))?;
    RevocationList::from_bytes(&b).map(Some)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io(&format!("remove {}", path.display()), e)),
    }
}

/// Write via a temp file in the same directory, then rename into place.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    write_file_0600(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| io("rename into place", e))
}

// --- backends --------------------------------------------------------------

/// Whether to try the OS keychain (disabled by `LATTICE_STORAGE=age`).
fn keyring_enabled() -> bool {
    std::env::var("LATTICE_STORAGE")
        .map(|v| v != "age")
        .unwrap_or(true)
}

fn keyring_save(account: &str, mnemonic: &str) -> bool {
    keyring::Entry::new(KEYRING_SERVICE, account)
        .and_then(|e| e.set_password(mnemonic))
        .is_ok()
}

fn keyring_err(e: keyring::Error) -> Error {
    Error::Other(format!(
        "keyring access failed: {e} (set LATTICE_STORAGE=age to use the encrypted-file backend)"
    ))
}

fn keyring_load(account: &str) -> Result<Option<Zeroizing<String>>> {
    match keyring::Entry::new(KEYRING_SERVICE, account) {
        Ok(e) => map_keyring_get(e.get_password()),
        Err(e) => Err(keyring_err(e)),
    }
}

/// Delete a keyring entry; "no entry" is success, other errors are fatal.
fn keyring_delete(account: &str) -> Result<()> {
    match keyring::Entry::new(KEYRING_SERVICE, account) {
        Ok(e) => map_keyring_delete(e.delete_credential()),
        Err(e) => Err(keyring_err(e)),
    }
}

fn map_keyring_delete(r: std::result::Result<(), keyring::Error>) -> Result<()> {
    match r {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(keyring_err(e)),
    }
}

/// Map a keyring read: only "no entry" is `None`; every other error is fatal.
fn map_keyring_get(
    r: std::result::Result<String, keyring::Error>,
) -> Result<Option<Zeroizing<String>>> {
    match r {
        Ok(s) => Ok(Some(Zeroizing::new(s))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keyring_err(e)),
    }
}

fn validate_passphrase(p: Zeroizing<String>) -> Result<Zeroizing<String>> {
    if p.trim().is_empty() {
        return Err(Error::Other("empty passphrase is not allowed".into()));
    }
    Ok(p)
}

fn passphrase(confirm: bool) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("LATTICE_PASSPHRASE") {
        return validate_passphrase(Zeroizing::new(p));
    }
    let p = validate_passphrase(Zeroizing::new(
        rpassword::prompt_password("Lattice identity passphrase: ")
            .map_err(|e| io("read passphrase", e))?,
    ))?;
    if confirm {
        let again = rpassword::prompt_password("Confirm passphrase: ")
            .map_err(|e| io("read passphrase", e))?;
        if *p != again {
            return Err(Error::Other("passphrases do not match".into()));
        }
    }
    Ok(p)
}

fn secret(p: &Zeroizing<String>) -> age::secrecy::SecretString {
    age::secrecy::SecretString::from(p.as_str().to_owned())
}

fn io(ctx: &str, e: std::io::Error) -> Error {
    Error::Other(format!("{ctx}: {e}"))
}

fn write_file_0600(path: &Path, bytes: &[u8]) -> Result<()> {
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
    use lattice_core::PeerId;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Force the age backend so tests never touch the OS keychain / dbus.
    fn with_age_env(dir: &Path) {
        std::env::set_var("LATTICE_STORAGE", "age");
        std::env::set_var("LATTICE_PASSPHRASE", "correct horse battery staple");
        std::env::set_var("LATTICE_DIR", dir);
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        static N: AtomicUsize = AtomicUsize::new(0);
        let d = std::env::temp_dir().join(format!(
            "lattice-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        with_age_env(&d);
        d
    }

    fn pid(n: u8) -> PeerId {
        PeerId([n; 32])
    }

    #[test]
    fn age_roundtrip_persists_identity() {
        let tmp = tmp_dir("store");
        let store = IdentityStore::with_dir(tmp.clone());

        let first = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(first.created);
        assert_eq!(first.backend, StorageBackend::AgeFile);
        assert!(tmp.join("identity.age").exists());
        assert!(tmp.join("root.pub").exists());

        let again = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(!again.created);
        assert_eq!(
            first.keypair.peer_id(),
            again.keypair.peer_id(),
            "stable identity"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn migrates_legacy_plaintext() {
        let tmp = tmp_dir("migrate");
        std::fs::create_dir_all(&tmp).unwrap();

        // Seed a legacy plaintext mnemonic from a throwaway identity.
        let original = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        std::fs::write(tmp.join("identity"), original.mnemonic()).unwrap();

        let store = IdentityStore::with_dir(tmp.clone());
        let loaded = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(loaded.migrated);
        assert_eq!(
            loaded.keypair.peer_id(),
            original.peer_id(),
            "migration preserves identity"
        );
        assert!(tmp.join("identity.age").exists(), "re-encrypted");
        assert!(
            !tmp.join("identity.legacy.bak").exists(),
            "no backup of the plaintext is kept"
        );
        assert!(!tmp.join("identity").exists(), "plaintext deleted");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn keyring_not_found_maps_to_none() {
        assert!(matches!(
            map_keyring_get(Err(keyring::Error::NoEntry)),
            Ok(None)
        ));
    }

    #[test]
    fn keyring_other_errors_are_fatal() {
        let r = map_keyring_get(Err(keyring::Error::Invalid("a".into(), "b".into())));
        assert!(r.is_err());
        assert!(map_keyring_delete(Err(keyring::Error::Invalid("a".into(), "b".into()))).is_err());
        assert!(map_keyring_delete(Err(keyring::Error::NoEntry)).is_ok());
    }

    #[test]
    fn keyring_success_maps_to_some() {
        assert!(matches!(map_keyring_get(Ok("words".into())), Ok(Some(_))));
    }

    fn failing_kr<R>(f: impl FnOnce(&Kr) -> R) -> R {
        let load = |_: &str| Err(Error::Other("boom".into()));
        let save = |_: &str, _: &str| false;
        let delete = |_: &str| Err(Error::Other("boom".into()));
        f(&Kr {
            load: &load,
            save: &save,
            delete: &delete,
        })
    }

    #[test]
    fn keyring_error_creates_nothing() {
        let tmp = tmp_dir("kr-err");
        std::fs::create_dir_all(&tmp).unwrap();
        let cfg = "backend = \"keyring\"\n";
        std::fs::write(tmp.join("config.toml"), cfg).unwrap();

        let store = IdentityStore::with_dir(tmp.clone());
        let r = failing_kr(|kr| store.load_or_create_with(CryptoSuite::Hybrid, kr));
        assert!(r.is_err());
        assert!(failing_kr(|kr| store.load_device_with(CryptoSuite::Hybrid, kr)).is_err());
        assert!(failing_kr(|kr| store.has_root_with(kr)).is_err());
        assert!(!tmp.join("identity.age").exists());
        assert!(!tmp.join("root.pub").exists());
        assert_eq!(
            std::fs::read_to_string(tmp.join("config.toml")).unwrap(),
            cfg
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn keyring_save_failure_is_fatal_no_age_fallback() {
        let tmp = tmp_dir("kr-save");
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("config.toml"), "backend = \"keyring\"\n").unwrap();
        let store = IdentityStore::with_dir(tmp.clone());
        let load = |_: &str| Ok(None);
        let save = |_: &str, _: &str| false;
        let delete = |_: &str| Ok(());
        let kr = Kr {
            load: &load,
            save: &save,
            delete: &delete,
        };
        let root = Keypair::generate(CryptoSuite::Classical).unwrap();
        assert!(store
            .provision_device_with(&root, CryptoSuite::Classical, 100, &kr)
            .is_err());
        assert!(!tmp.join("device.age").exists());
        assert!(!tmp.join("device.cert").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn device_roundtrip_and_forget_import() {
        let tmp = tmp_dir("device");
        let store = IdentityStore::with_dir(tmp.clone());
        let root = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        let phrase = root.keypair.mnemonic().to_string();
        assert!(store.load_device(CryptoSuite::Hybrid).unwrap().is_none());
        let dev = store
            .provision_device(&root.keypair, CryptoSuite::Hybrid, 5000)
            .unwrap();
        assert!(tmp.join("device.age").exists());
        assert!(tmp.join("device.cert").exists());
        assert!(tmp.join("root.pub").exists());
        let back = store.load_device(CryptoSuite::Hybrid).unwrap().unwrap();
        assert_eq!(back.keypair.peer_id(), dev.keypair.peer_id());
        assert_eq!(back.cert.to_bytes(), dev.cert.to_bytes());
        assert_eq!(back.root.peer_id(), root.keypair.peer_id());

        assert!(store.has_root().unwrap());
        store.forget_root().unwrap();
        assert!(!store.has_root().unwrap());
        assert!(store.load_root(CryptoSuite::Hybrid).unwrap().is_none());
        assert!(!tmp.join("identity.age").exists());
        assert!(store.load_device(CryptoSuite::Hybrid).unwrap().is_some());
        assert!(store.load_or_create(CryptoSuite::Hybrid).is_err());
        assert!(!tmp.join("identity.age").exists());

        let other = Keypair::generate(CryptoSuite::Hybrid).unwrap();
        assert!(store
            .import_root(CryptoSuite::Hybrid, other.mnemonic())
            .is_err());
        assert!(store
            .import_root(CryptoSuite::Hybrid, "not a phrase")
            .is_err());
        let r = store.import_root(CryptoSuite::Hybrid, &phrase).unwrap();
        assert_eq!(r.keypair.peer_id(), root.keypair.peer_id());
        assert!(store.has_root().unwrap());
        assert!(store.import_root(CryptoSuite::Hybrid, &phrase).is_ok());
        assert!(store.load_root(CryptoSuite::Hybrid).unwrap().is_some());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn forget_root_requires_device() {
        let tmp = tmp_dir("forget-nodev");
        let store = IdentityStore::with_dir(tmp.clone());
        store.load_or_create(CryptoSuite::Classical).unwrap();
        assert!(store.forget_root().is_err());
        assert!(store.load_root(CryptoSuite::Classical).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn legacy_root_only_store_keeps_root_when_device_added() {
        let tmp = tmp_dir("legacy-root");
        let store = IdentityStore::with_dir(tmp.clone());
        let root = store.load_or_create(CryptoSuite::Hybrid).unwrap();
        assert!(store.load_device(CryptoSuite::Hybrid).unwrap().is_none());
        store
            .provision_device(&root.keypair, CryptoSuite::Hybrid, 5000)
            .unwrap();
        let again = store.load_root(CryptoSuite::Hybrid).unwrap().unwrap();
        assert_eq!(again.keypair.peer_id(), root.keypair.peer_id());
        assert!(store.load_device(CryptoSuite::Hybrid).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_device_rejects_mismatched_cert() {
        let tmp = tmp_dir("bad-cert");
        let store = IdentityStore::with_dir(tmp.clone());
        let root = store.load_or_create(CryptoSuite::Classical).unwrap();
        store
            .provision_device(&root.keypair, CryptoSuite::Classical, 5000)
            .unwrap();
        // Cert for another device under the same root.
        let other_dev = Keypair::generate(CryptoSuite::Classical).unwrap();
        let c = root
            .keypair
            .authorize_device(other_dev.public(), 5000)
            .unwrap();
        std::fs::write(tmp.join("device.cert"), c.to_bytes()).unwrap();
        assert!(store.load_device(CryptoSuite::Classical).is_err());
        // Cert from another root for the right device is also rejected.
        let r2 = Keypair::generate(CryptoSuite::Classical).unwrap();
        let d = store
            .provision_device(&root.keypair, CryptoSuite::Classical, 5000)
            .unwrap();
        let bad = r2.authorize_device(d.keypair.public(), 5000).unwrap();
        std::fs::write(tmp.join("device.cert"), bad.to_bytes()).unwrap();
        assert!(store.load_device(CryptoSuite::Classical).is_err());
        // store_device validates before writing.
        let d = Keypair::generate(CryptoSuite::Classical).unwrap();
        let wrong = Keypair::generate(CryptoSuite::Classical).unwrap();
        let cert = root.keypair.authorize_device(wrong.public(), 5).unwrap();
        assert!(store
            .store_device(&d, &cert, root.keypair.public())
            .is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn revocation_files_roundtrip() {
        let tmp = tmp_dir("revocation");
        let store = IdentityStore::with_dir(tmp.clone());
        assert!(store.load_revocation().unwrap().is_none());
        let root = Keypair::generate(CryptoSuite::Classical).unwrap();
        let l1 = root.revoke_devices(1, 0, &[pid(1)]).unwrap();
        store.store_revocation(&l1).unwrap();
        assert_eq!(
            store.load_revocation().unwrap().unwrap().to_bytes(),
            l1.to_bytes()
        );
        std::fs::write(tmp.join("revocation.bin"), b"junk").unwrap();
        assert!(store.load_revocation().is_err());

        assert!(store.load_peer_revocations().unwrap().is_empty());
        let l2 = root.revoke_devices(2, 0, &[pid(1), pid(2)]).unwrap();
        assert!(store.store_peer_revocation(&l1).unwrap());
        assert!(!store.store_peer_revocation(&l1).unwrap());
        assert!(store.store_peer_revocation(&l2).unwrap());
        assert!(!store.store_peer_revocation(&l1).unwrap());
        std::fs::write(tmp.join("peers").join("garbage.rev"), b"junk").unwrap();
        let loaded = store.load_peer_revocations().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].seq(), 2);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn peer_revocation_cap() {
        let tmp = tmp_dir("peer-cap");
        let store = IdentityStore::with_dir(tmp.clone());
        std::fs::create_dir_all(tmp.join("peers")).unwrap();
        for i in 0..MAX_PEER_REVOCATIONS {
            std::fs::write(tmp.join("peers").join(format!("{i:064x}.rev")), b"x").unwrap();
        }
        let root = Keypair::generate(CryptoSuite::Classical).unwrap();
        let l = root.revoke_devices(1, 0, &[]).unwrap();
        assert!(!store.store_peer_revocation(&l).unwrap());
        assert!(store.load_peer_revocations().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn passphrase_validation() {
        for bad in ["", "   ", "\t\n"] {
            assert!(validate_passphrase(Zeroizing::new(bad.to_string())).is_err());
        }
        for good in ["correct horse battery staple", " x "] {
            let v = validate_passphrase(Zeroizing::new(good.to_string())).unwrap();
            assert_eq!(v.as_str(), good);
        }
    }
}
