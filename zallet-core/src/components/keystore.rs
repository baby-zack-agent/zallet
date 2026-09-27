//! The Zallet keystore.
//!
//! # Design
//!
//! Zallet uses `zcash_client_sqlite` for its wallet, which handles viewing capabilities
//! itself, while leaving key material handling to the application which may have secure
//! storage capabilities (such as provided by mobile platforms). Given that Zallet is a
//! server wallet, we do not assume any secure storage capabilities are available, and
//! instead encrypt key material ourselves.
//!
//! Zallet stores key material (mnemonic seed phrases, standalone spending keys, etc) in
//! the same database as `zcash_client_sqlite`. This simplifies backups (as the wallet
//! operator only has a single database file for both transaction data and key material),
//! and helps to avoid inconsistent state.
//!
//! Zallet uses [`age`] to encrypt key material. age is built around the concept of
//! "encryption recipients" and "decryption identities", and provides several features:
//!
//! - Once the wallet has been initialized for an identity file, spending key material can
//!   be securely added to the wallet at any time without requiring the identity file.
//! - Key material can be encrypted to multiple recipients, which enables wallet operators
//!   to add redundancy to their backup strategies.
//!   - For example, an operator could configure Zallet with an online identity file used
//!     for regular wallet operations, and an offline identity file used to recover the
//!     key material from the wallet database if the online identity file is lost).
//! - Identity files can themselves be encrypted with a passphrase, allowing the wallet
//!   operator to limit the time for which the age identities are present in memory.
//! - age supports plugins for its encryption and decryption, which enable identities to
//!   be stored on hardware tokens like YubiKeys, or managed by a corporate KMS.
//!
//! ```text
//!  Disk
//! ┌───────────────────────┐       ┌──────────┐
//! │      ┌───────────┐    │       │Passphrase│
//! │      │  File or  │    │       └──────────┘
//! │      │zallet.toml│    │             │
//! │      └───────────┘    │             ▼
//! │            │          │       ┌──────────┐
//! │            ▼          │       │ Decrypt  │
//! │    ┌──────────────┐   │ ┌ ─ ─▶│identities│─ ─ ┐
//! │    │ age identity │   │       └──────────┘
//! │    │     file     │───┼─┘─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
//! │    └──────────────┘   │                       │   Memory
//! │                       │             ┌ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┐
//! │  Database ┌───────────┼─────┐                 ▼
//! │ ┌ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┐ │     │       │ ┌───────────────┐ │
//! │           ▼           │     └─────────│age identities │──┐
//! │ │ ┌───────────────┐ │ │             │ └───────────────┘ ││
//! │   │age recipients │───┼─────┐                            │
//! │ │ └───────────────┘ │ │     ▼       │    ┌─────────┐    ││  ┌───────────┐
//! │                       │ ┌───────┐        │   Key   │     │  │Transaction│
//! │ │                   │ │ │encrypt│◀┬─┼────│material │────┼┼─▶│  signing  │
//! │     ┌───────────┐     │ └───────┘        └─────────┘     │  └───────────┘
//! │ │   │    age    │   │ │     │     │ │         ▲         ││
//! │     │ciphertext │◀────┼─────┘        ─ ─ ─ ─ ─│─ ─ ─ ─ ─ │
//! │ │   └───────────┘   │ │           │           │          │
//! │  ─ ─ ─ ─ ─│─ ─ ─ ─ ─  │      ┌─────────┐      │          │
//! └───────────┼───────────┘      │Query KMS│      │          │
//!             │                  └─────────┘      │          │
//!             │                       │           │          │
//!             │                               ┌───────┐      │
//!             └───────────────────────┴──────▶│decrypt│◀─────┘
//!                                             └───────┘
//! ```
//!
//! TODO: Integrate or remote thes other notes:
//!
//! - Store recipients in the keystore as common bundles (a la Tink keysets).
//! - Whenever an identity file is directly visible, check it matches the recipients, to
//!   discover incorrect or outdated identity files ASAP.
//!
//! - Encrypt the seed phrase(s) with age, derive any needed keys on-the-fly after
//!   requesting decryption of the relevant seed phrase.
//!   - Could support any or all of the following encryption methods:
//!     - "native identity file" (only plaintext on disk is the age identity, and that
//!       could be on a different disk)
//!     - "passphrase" (like zcashd's experimental wallet encryption)
//!       - The closest analogue to zcashd's experimental wallet encryption would be a
//!         passphrase-encrypted native identity file: need passphrase once to decrypt the
//!         age identity into memory, and then can use the identity to decrypt and access
//!         seed phrases on-the-fly.
//!       - An advantage over the zcashd approach is that you don't need the wallet to be
//!         decrypted in order to import or generate new seed phrases / key material
//!         (zcashd used solely symmetric crypto; native age identities use asymmetric).
//!       - Current downside is that because of the above, encrypted key material would be
//!         quantum-vulnerable (but ML-KEM support is in progress for the age ecosystem).
//!     - "plugin" (enabling key material to be encrypted in a user-specified way e.g. to
//!       a YubiKey, or a corporate KMS)
//!       - Might also want a hybrid approach here to allow for on-first-use decryption
//!         requests rather than every-time decryption requests. Or maybe we want to
//!         support both.
//!   - Zallet would be configured with a corresponding age identity for encrypting /
//!     decrypting seed phrases.
//!   - If the age identity is native and unencrypted, that means Zallet can access seed
//!     phrases whenever it wants. This would be useful in e.g. a Docker deployment, where
//!     the identity could be decrypted during deployment and injected into the correct
//!     location (e.g. via a custom volume).
//!   - If the age identity is passphrase-encrypted, then we could potentially enable the
//!     Bitcoin Core-inherited JSON-RPC methods for decrypting the wallet as the
//!     passphrase UI. The decrypted age identity would be cached in memory until either
//!     an explicit eviction via JSON-RPC or node shutdown.
//!   - If the age identity uses a plugin, then as long as the plugin doesn't require user
//!     interaction the wallet could request decryption on-the-fly during spend actions,
//!     or explicitly via JSON-RPC (with no passphrase).
//!   - If the age identity uses a plugin, and user interaction is required, then we
//!     couldn't support this without Zallet gaining some kind of UI (TUI or GUI) for
//!     users to interact with. Maybe this could be via a dedicated (non-JSON) RPC
//!     protocol between a zallet foobar command and a running zallet start process?
//!     Probably out of scope for the initial impl.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bip0039::{English, Mnemonic};
use rusqlite::{OptionalExtension, named_params};
use secrecy::{ExposeSecret, SecretString, SecretVec, Zeroize};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
    time,
};
use zcash_client_sqlite::ExtensionTransaction;
use zcash_protocol::consensus;
use zip32::fingerprint::SeedFingerprint;

use crate::network::Network;
use crate::{
    config::ZalletConfig,
    error::{Error, ErrorKind},
};

use super::database::Database;

use crate::fl;

use orchard::keys::{FullViewingKey as OrchardFullViewingKey, SpendingKey as OrchardSpendingKey};
use sapling::zip32::{DiversifiableFullViewingKey, ExtendedSpendingKey};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::{Era, UnifiedSpendingKey};

#[cfg(feature = "transparent-key-import")]
use {transparent::address::TransparentAddress, zcash_keys::address::Address};

pub(super) mod db;

mod error;
pub(crate) use error::KeystoreError;

#[cfg(feature = "zcashd-import")]
pub(crate) mod zewif;

type RelockTask = (SystemTime, JoinHandle<()>);

/// Whether the wallet operator is known to hold a copy of a mnemonic phrase outside the
/// wallet, at the moment Zallet stores that phrase.
///
/// This is not a claim about the quality of the operator's backup, which Zallet cannot
/// observe. It distinguishes a phrase that has provably passed through the operator's
/// hands from one that has only ever existed inside this wallet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackupStatus {
    /// The operator supplied this phrase, and so must already have had it to hand.
    Confirmed,

    /// Zallet is the only place this phrase is known to exist. Spend authority will not
    /// be derived from its seed until the operator confirms having recorded it, unless
    /// `keystore.require_backup` is disabled.
    Unconfirmed,
}

impl BackupStatus {
    fn is_confirmed(self) -> bool {
        matches!(self, BackupStatus::Confirmed)
    }
}

/// Why [`KeyStore::select_seed`] could not choose a mnemonic seed to act on.
pub(crate) enum SeedSelectionError {
    /// Reading the wallet's seeds failed.
    Database(Error),

    /// The wallet holds no mnemonic phrases at all.
    NoSeeds,

    /// The wallet holds several phrases and the caller named none of them.
    Ambiguous,

    /// The caller named a fingerprint the wallet does not hold.
    Unknown,
}

#[derive(Clone)]
pub(crate) struct KeyStore {
    db: Database,

    /// A ciphertext ostensibly containing encrypted age identities, or `None` if the
    /// keystore is not using runtime-encrypted identities.
    encrypted_identities: Option<Vec<u8>>,

    /// The in-memory cache of age identities for decrypting key material.
    identities: Arc<RwLock<Vec<Box<dyn age::Identity + Send + Sync>>>>,

    /// Task that will re-lock the keystore if it has been temporarily unlocked.
    relock_task: Arc<Mutex<Option<RelockTask>>>,

    /// Whether a mnemonic's backup must be confirmed before Zallet will derive new spend
    /// authority from its seed.
    require_backup: bool,
}

impl fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyStore").finish_non_exhaustive()
    }
}

impl KeyStore {
    pub(crate) fn new(config: &ZalletConfig, db: Database) -> Result<Self, Error> {
        // TODO: Maybe support storing the identity in `zallet.toml` instead of as a
        //       separate file on disk?
        //       https://github.com/zcash/zallet/issues/253
        let path = config.encryption_identity();
        if !path.exists() {
            return Err(ErrorKind::Init
                .context(fl!(
                    "err-init-identity-not-found",
                    path = path.display().to_string(),
                ))
                .into());
        }

        let (encrypted_identities, identities) = {
            let mut identity_data = vec![];
            File::open(&path)
                .map_err(|e| ErrorKind::Init.context(e))?
                .read_to_end(&mut identity_data)
                .map_err(|e| ErrorKind::Init.context(e))?;

            // Try parsing as an encrypted age identity.
            match age::Decryptor::new_buffered(age::armor::ArmoredReader::new(
                identity_data.as_slice(),
            )) {
                Ok(decryptor) => {
                    // Only passphrase-encrypted age identities are supported.
                    if age::encrypted::EncryptedIdentity::new(decryptor, age::NoCallbacks, None)
                        .is_none()
                    {
                        return Err(ErrorKind::Init
                            .context(fl!(
                                "err-init-identity-not-passphrase-encrypted",
                                path = path.display().to_string(),
                            ))
                            .into());
                    }

                    (Some(identity_data), vec![])
                }
                _ => {
                    identity_data.zeroize();

                    // Try parsing as multiple single-line age identities.
                    let identity_file = age::IdentityFile::from_file(
                        path.to_str()
                            .ok_or_else(|| {
                                ErrorKind::Init.context(fl!(
                                    "err-init-path-not-utf8",
                                    path = path.display().to_string(),
                                ))
                            })?
                            .to_string(),
                    )
                    .map_err(|e| ErrorKind::Init.context(e))?
                    .with_callbacks(age::cli_common::UiCallbacks);
                    let identities = identity_file.into_identities().map_err(|e| {
                        ErrorKind::Init.context(fl!(
                            "err-init-identity-not-usable",
                            path = path.display().to_string(),
                            error = e.to_string(),
                        ))
                    })?;

                    (None, identities)
                }
            }
        };

        Ok(Self {
            db,
            encrypted_identities,
            identities: Arc::new(RwLock::new(identities)),
            relock_task: Arc::new(Mutex::new(None)),
            require_backup: config.require_backup(),
        })
    }

    /// Returns `true` if the keystore's age identities are runtime-encrypted.
    ///
    /// When this returns `true`, [`Self::is_locked`] must return `false` in order to have
    /// access to spending key material.
    pub(crate) fn uses_encrypted_identities(&self) -> bool {
        self.encrypted_identities.is_some()
    }

    /// Returns `true` if the keystore's age identities are not available for decrypting
    /// key material.
    ///
    /// - If [`Self::uses_encrypted_identities`] returns `false`, this always returns
    ///   `true`.
    /// - If [`Self::uses_encrypted_identities`] returns `true`, this returns `true` when
    ///   [`Self::unlocked_until`] returns `None`.
    pub(crate) async fn is_locked(&self) -> bool {
        self.identities.read().await.is_empty()
    }

    /// Returns the [`SystemTime`] at which the keystore will re-lock, if it is currently
    /// unlocked.
    ///
    /// - To unlock the keystore or extend this time, use [`Self::unlock`].
    /// - To re-lock the keystore before this time, use [`Self::lock`].
    pub(crate) async fn unlocked_until(&self) -> Option<SystemTime> {
        let relock_task = self.relock_task.lock().await;
        relock_task
            .as_ref()
            .and_then(|(deadline, task)| (!task.is_finished()).then_some(*deadline))
    }

    /// Decrypts the keystore's [`age::IdentityFile`] using the given passphrase.
    pub(crate) async fn decrypt_identity_file<C: age::Callbacks>(
        &self,
        callbacks: C,
    ) -> Result<Option<age::IdentityFile<age::NoCallbacks>>, Error> {
        let encrypted_identities = match &self.encrypted_identities {
            Some(data) => data,
            // If the keystore isn't encrypted, we don't need to do anything.
            None => return Ok(None),
        };

        let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(
            encrypted_identities.as_slice(),
        ))
        .expect("validated on start");

        let encrypted_identity = age::encrypted::EncryptedIdentity::new(decryptor, callbacks, None)
            .expect("validated on start");

        encrypted_identity
            .decrypt(None)
            .map(|identity_file| Some(identity_file.with_callbacks(age::NoCallbacks)))
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    /// Unlocks the keystore using the given passphrase.
    ///
    /// The keystore will be re-locked after `timeout` seconds. Calling this method again
    /// before the existing timeout expires will reset the timeout.
    pub(crate) async fn unlock(
        &self,
        passphrase: age::secrecy::SecretString,
        timeout: u64,
    ) -> Result<(), KeystoreError> {
        // Compute the absolute re-lock deadline up front, rejecting timeouts so large
        // that the addition would overflow `SystemTime` (which would otherwise panic).
        let duration = Duration::from_secs(timeout);
        let relock_at = SystemTime::now()
            .checked_add(duration)
            .ok_or(KeystoreError::TimeoutTooLarge)?;

        // Prepare a callback that only responds to passphrase requests.
        #[derive(Clone)]
        struct PassphraseCallbacks(age::secrecy::SecretString);
        impl age::Callbacks for PassphraseCallbacks {
            fn display_message(&self, _: &str) {}
            fn confirm(&self, _: &str, _: &str, _: Option<&str>) -> Option<bool> {
                unreachable!()
            }
            fn request_public_string(&self, _: &str) -> Option<String> {
                unreachable!()
            }
            fn request_passphrase(&self, _: &str) -> Option<age::secrecy::SecretString> {
                Some(self.0.clone())
            }
        }

        let identity_file = match self
            .decrypt_identity_file(PassphraseCallbacks(passphrase))
            .await
        {
            Ok(Some(identity_file)) => identity_file,
            _ => return Err(KeystoreError::IncorrectPassphrase),
        };

        let decrypted_identities = match identity_file.into_identities() {
            Ok(identities) => identities,
            Err(_) => return Err(KeystoreError::IncorrectPassphrase),
        };

        // If there is an existing relock task, abort it so we don't race while writing
        // the decrypted identities.
        let mut relock_task = self.relock_task.lock().await;
        if let Some((_, existing_timeout)) = relock_task.take() {
            existing_timeout.abort();
            // Wait for the task to either finish or abort, to ensure there's zero
            // possibility of the `decrypted_identities` write below being cleared.
            let _ = existing_timeout.await;
        }

        *self.identities.write().await = decrypted_identities;

        // Start a task to relock the keystore after the given timeout.
        let identities = self.identities.clone();
        *relock_task = Some((
            relock_at,
            crate::spawn!("Keystore relock", async move {
                time::sleep(duration).await;
                identities.write().await.clear();
            }),
        ));

        Ok(())
    }

    /// Unlocks the keystore for the remainder of the current process, prompting on the
    /// terminal for the identity file's passphrase if it has one.
    ///
    /// This is for one-shot CLI commands, whose process exits long before any re-lock
    /// timeout would matter; a long-running `zallet start` should use [`Self::unlock`]
    /// instead, so that the identities do not stay in memory indefinitely.
    ///
    /// Does nothing if the keystore's identity file is not passphrase-encrypted, since
    /// its identities are already loaded.
    pub(crate) async fn unlock_on_terminal(&self) -> Result<(), Error> {
        let identity_file = match self
            .decrypt_identity_file(age::cli_common::UiCallbacks)
            .await?
        {
            Some(identity_file) => identity_file,
            None => return Ok(()),
        };

        *self.identities.write().await = identity_file
            .into_identities()
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(())
    }

    /// Clears the in-memory cache of age identities, locking the keystore.
    pub(crate) async fn lock(&self) {
        // If the keystore isn't encrypted, we don't want to clear the cached identities.
        if !self.uses_encrypted_identities() {
            return;
        }

        // Any existing relock task is now unnecessary.
        let mut relock_task = self.relock_task.lock().await;
        if let Some((_, existing_timeout)) = relock_task.take() {
            existing_timeout.abort();
            // Wait for the task to either finish or abort, to ensure there's zero
            // possibility of a subsequent `unlock` having its identities cleared.
            let _ = existing_timeout.await;
        }

        self.identities.write().await.clear();
    }

    async fn with_db<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection, &Network) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.db.handle().await?.with_raw(f)
    }

    async fn with_db_mut<T>(
        &self,
        f: impl FnOnce(&mut rusqlite::Connection, &Network) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.db.handle().await?.with_raw_mut(f)
    }

    /// Sets the age recipients for this keystore.
    ///
    /// It is the caller's responsibility to ensure that the corresponding age identities
    /// are known.
    pub(crate) async fn initialize_recipients(
        &self,
        recipient_strings: Vec<String>,
    ) -> Result<(), Error> {
        // Validate up front so a malformed or empty recipient set fails initialization
        // with a clear error, instead of being stored and then breaking the wallet at
        // the first attempt to encrypt key material.
        if recipient_strings.is_empty() {
            return Err(ErrorKind::Generic
                .context(KeystoreError::EmptyRecipients)
                .into());
        }
        Encryptor::parse_recipient_strings(recipient_strings.clone())?;

        let now = ::time::OffsetDateTime::now_utc();

        self.with_db_mut(|conn, _| {
            // Use an explicit transaction so the emptiness check and the inserts are
            // atomic: either every recipient is committed or none are. This prevents a
            // partial write (e.g. from a disk-full or I/O error mid-loop) from committing
            // an incomplete recipient set that the one-shot guard below would then refuse
            // to ever repair.
            let tx = conn
                .transaction()
                .map_err(|e| ErrorKind::Generic.context(e))?;

            // If the wallet has any existing recipients, fail (we would instead need to
            // re-encrypt the wallet).
            let existing_recipients: i64 = tx
                .query_row(
                    "SELECT COUNT(*) FROM ext_zallet_keystore_age_recipients",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;
            if existing_recipients != 0 {
                return Err(ErrorKind::Generic
                    .context(fl!("err-keystore-already-initialized"))
                    .into());
            }

            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO ext_zallet_keystore_age_recipients
                        VALUES (:recipient, :added)",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                for recipient in recipient_strings {
                    stmt.execute(named_params! {
                        ":recipient": recipient,
                        ":added": now,
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                }
            }

            tx.commit().map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(())
        })
        .await?;

        Ok(())
    }

    /// Constructs the encryptor for this wallet using the recipients from the database.
    ///
    /// Returns an error if there are no age recipients.
    pub(crate) async fn encryptor(&self) -> Result<Encryptor, Error> {
        let encryptor = self.maybe_encryptor().await?;
        if encryptor.is_empty() {
            Err(ErrorKind::Generic
                .context(KeystoreError::MissingRecipients)
                .into())
        } else {
            Ok(encryptor)
        }
    }

    /// Constructs the encryptor for this wallet using the recipients from the database.
    ///
    /// Unlike [`Self::encryptor`], this might return an empty encryptor.
    async fn maybe_encryptor(&self) -> Result<Encryptor, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT recipient
                        FROM ext_zallet_keystore_age_recipients",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0))
                .map_err(|e| ErrorKind::Generic.context(e))?;
            let recipient_strings = rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Encryptor::from_recipient_strings(recipient_strings)
        })
        .await
    }

    /// Lists the fingerprint of every seed available in the keystore.
    pub(crate) async fn list_seed_fingerprints(&self) -> Result<HashSet<SeedFingerprint>, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT hd_seed_fingerprint
                    FROM ext_zallet_keystore_mnemonics",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0).map(SeedFingerprint::from_bytes))
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?)
        })
        .await
    }

    /// Lists the fingerprint of every legacy non-mnemonic seed available in the keystore.
    pub(crate) async fn list_legacy_seed_fingerprints(
        &self,
    ) -> Result<HashSet<SeedFingerprint>, Error> {
        self.with_db(|conn, _| {
            let mut stmt = conn
                .prepare(
                    "SELECT hd_seed_fingerprint
                    FROM ext_zallet_keystore_legacy_seeds",
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;

            let rows = stmt
                .query_map([], |row| row.get(0).map(SeedFingerprint::from_bytes))
                .map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(rows
                .collect::<Result<_, _>>()
                .map_err(|e| ErrorKind::Generic.context(e))?)
        })
        .await
    }

    /// Stores `mnemonic` in the keystore, encrypted to the wallet's age recipients.
    ///
    /// `backup` records whether the operator is already known to hold this phrase; see
    /// [`BackupStatus`]. Storing a phrase the keystore already holds leaves the existing
    /// ciphertext in place, but a [`BackupStatus::Confirmed`] store still confirms it:
    /// re-supplying a phrase Zallet generated demonstrates possession just as
    /// [`Self::confirm_backup`] does. Confirmation is never withdrawn by a later store.
    pub(crate) async fn encrypt_and_store_mnemonic(
        &self,
        mnemonic: Mnemonic,
        backup: BackupStatus,
    ) -> Result<SeedFingerprint, Error> {
        let encryptor = self.encryptor().await?;

        let seed_bytes = SecretVec::new(mnemonic.to_seed("").to_vec());
        let seed_fp = SeedFingerprint::from_seed(seed_bytes.expose_secret()).expect("valid length");

        // Take ownership of the memory of the mnemonic to ensure it will be correctly zeroized on drop
        let mnemonic = SecretString::new(mnemonic.into_phrase());
        let encrypted_mnemonic =
            encryptor.encrypt_string(mnemonic.expose_secret(), age::armor::Format::Binary)?;

        self.with_db_mut(|conn, _| {
            conn.execute(
                "INSERT INTO ext_zallet_keystore_mnemonics
                VALUES (:hd_seed_fingerprint, :encrypted_mnemonic, :backup_confirmed)
                ON CONFLICT (hd_seed_fingerprint) DO UPDATE
                SET backup_confirmed = backup_confirmed OR excluded.backup_confirmed ",
                named_params! {
                    ":hd_seed_fingerprint": seed_fp.to_bytes(),
                    ":encrypted_mnemonic": encrypted_mnemonic,
                    ":backup_confirmed": backup.is_confirmed(),
                },
            )
            .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await?;

        Ok(seed_fp)
    }

    /// Returns `true` if the operator is known to hold a copy of the mnemonic phrase for
    /// the given seed outside the wallet.
    ///
    /// A seed the keystore has no mnemonic for is reported as unconfirmed: there is no
    /// phrase for the operator to have backed up, so no basis on which to say they have.
    pub(crate) async fn backup_confirmed(&self, seed_fp: &SeedFingerprint) -> Result<bool, Error> {
        self.with_db(|conn, _| {
            Ok(conn
                .query_row(
                    "SELECT backup_confirmed
                    FROM ext_zallet_keystore_mnemonics
                    WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                    named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                    |row| row.get::<_, bool>(0),
                )
                .optional()
                .map_err(|e| ErrorKind::Generic.context(e))?
                .unwrap_or(false))
        })
        .await
    }

    /// Deletes the mnemonic stored under `seed_fp`, returning whether a stored
    /// mnemonic was deleted (`false` means no mnemonic was stored under `seed_fp`).
    ///
    /// A mnemonic that any account derives from must never be deleted; this exists
    /// solely to roll back a provisionally stored mnemonic after a failed wallet
    /// import, before any account references it.
    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn delete_mnemonic(&self, seed_fp: &SeedFingerprint) -> Result<bool, Error> {
        self.with_db_mut(|conn, _| {
            let deleted = conn
                .execute(
                    "DELETE FROM ext_zallet_keystore_mnemonics
                    WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                    named_params! {
                        ":hd_seed_fingerprint": seed_fp.to_bytes(),
                    },
                )
                .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(deleted > 0)
        })
        .await
    }

    /// Chooses which of the wallet's mnemonic seeds an operation should act on.
    ///
    /// A wallet holding exactly one phrase needs no fingerprint; otherwise the caller must
    /// name one, because Zallet will not pick a root of spend authority on the operator's
    /// behalf.
    pub(crate) async fn select_seed(
        &self,
        seedfp: Option<SeedFingerprint>,
    ) -> Result<SeedFingerprint, SeedSelectionError> {
        let seed_fps = self
            .list_seed_fingerprints()
            .await
            .map_err(SeedSelectionError::Database)?;

        match (seed_fps.len(), seedfp) {
            (0, _) => Err(SeedSelectionError::NoSeeds),
            (_, Some(seed_fp)) => seed_fps
                .contains(&seed_fp)
                .then_some(seed_fp)
                .ok_or(SeedSelectionError::Unknown),
            (1, None) => Ok(seed_fps.into_iter().next().expect("present")),
            (_, None) => Err(SeedSelectionError::Ambiguous),
        }
    }

    /// Returns `true` if new spend authority must not be derived from the given seed,
    /// because the operator has not confirmed that they hold its mnemonic phrase.
    pub(crate) async fn backup_required(&self, seed_fp: &SeedFingerprint) -> Result<bool, Error> {
        Ok(self.require_backup && !self.backup_confirmed(seed_fp).await?)
    }

    /// Records that the operator holds a copy of the mnemonic phrase for the given seed.
    ///
    /// The caller is responsible for having established that: this writes the conclusion,
    /// it does not check it. See the `confirm-backup` command.
    ///
    /// Returns an error if the keystore holds no mnemonic with this fingerprint.
    pub(crate) async fn confirm_backup(&self, seed_fp: &SeedFingerprint) -> Result<(), Error> {
        let rows = self
            .with_db_mut(|conn, _| {
                let rows = conn
                    .execute(
                        "UPDATE ext_zallet_keystore_mnemonics
                        SET backup_confirmed = TRUE
                        WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                        named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                Ok(rows)
            })
            .await?;

        if rows == 0 {
            return Err(ErrorKind::Generic
                .context(fl!(
                    "err-keystore-no-such-mnemonic",
                    seedfp = seed_fp.to_string(),
                ))
                .into());
        }

        Ok(())
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn encrypt_and_store_legacy_seed(
        &self,
        legacy_seed: &SecretVec<u8>,
    ) -> Result<SeedFingerprint, Error> {
        let encryptor = self.encryptor().await?;

        let legacy_seed_fp = SeedFingerprint::from_seed(legacy_seed.expose_secret())
            .ok_or_else(|| ErrorKind::Generic.context(fl!("err-failed-seed-fingerprinting")))?;

        let encrypted_legacy_seed = encryptor
            .encrypt_legacy_seed_bytes(legacy_seed)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        self.with_db_mut(|conn, _| {
            conn.execute(
                "INSERT INTO ext_zallet_keystore_legacy_seeds
                VALUES (:hd_seed_fingerprint, :encrypted_legacy_seed)
                ON CONFLICT (hd_seed_fingerprint) DO NOTHING ",
                named_params! {
                    ":hd_seed_fingerprint": legacy_seed_fp.to_bytes(),
                    ":encrypted_legacy_seed": encrypted_legacy_seed,
                },
            )
            .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await?;

        Ok(legacy_seed_fp)
    }

    /// Encrypts a standalone Sapling spending key without touching the database.
    ///
    /// This is the fallible half of storing a standalone Sapling key: it needs the keystore
    /// encryptor (unavailable while the wallet is locked), and it is async. Persist the
    /// result with [`EncryptedStandaloneSaplingKey::insert`] to write it inside a wallet
    /// transaction, or with `Self::store_standalone_sapling_key`.
    pub(crate) async fn encrypt_standalone_sapling_key(
        &self,
        sapling_key: &ExtendedSpendingKey,
    ) -> Result<EncryptedStandaloneSaplingKey, Error> {
        let encryptor = self.encryptor().await?;

        let dfvk = sapling_key.to_diversifiable_full_viewing_key();
        let encrypted_sapling_extsk = encryptor
            .encrypt_standalone_sapling_key(sapling_key)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(EncryptedStandaloneSaplingKey {
            dfvk,
            encrypted_sapling_extsk,
        })
    }

    /// Encrypts a standalone Orchard spending key without touching the database.
    ///
    /// This is the fallible half of storing a standalone Orchard key: it needs the keystore
    /// encryptor (unavailable while the wallet is locked), and it is async. Persist the
    /// result with [`EncryptedStandaloneOrchardKey::insert`] to write it inside a wallet
    /// transaction.
    pub(crate) async fn encrypt_standalone_orchard_key(
        &self,
        orchard_key: &OrchardSpendingKey,
    ) -> Result<EncryptedStandaloneOrchardKey, Error> {
        let encryptor = self.encryptor().await?;

        let fvk = OrchardFullViewingKey::from(orchard_key);
        let encrypted_orchard_sk = encryptor
            .encrypt_standalone_orchard_key(orchard_key)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(EncryptedStandaloneOrchardKey {
            fvk,
            encrypted_orchard_sk,
        })
    }

    /// Encrypts a standalone unified spending key without touching the database.
    ///
    /// This is the fallible half of storing a standalone unified key: it needs the keystore
    /// encryptor (unavailable while the wallet is locked), and it is async. Persist the
    /// result with [`EncryptedStandaloneUnifiedKey::insert`] to write it inside a wallet
    /// transaction.
    ///
    /// `params` is used to encode the derived unified full viewing key that identifies the
    /// stored key; only public viewing-key material is stored alongside the ciphertext.
    pub(crate) async fn encrypt_standalone_unified_key<P: consensus::Parameters>(
        &self,
        params: &P,
        unified_key: &UnifiedSpendingKey,
    ) -> Result<EncryptedStandaloneUnifiedKey, Error> {
        let encryptor = self.encryptor().await?;

        let ufvk_encoded = unified_key.to_unified_full_viewing_key().encode(params);
        let encrypted_usk = encryptor
            .encrypt_standalone_unified_key(unified_key)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(EncryptedStandaloneUnifiedKey {
            ufvk_encoded,
            encrypted_usk,
        })
    }

    /// Stores a pre-encrypted standalone Sapling key over a pooled connection.
    ///
    /// The upsert is idempotent; re-storing a key replaces any ciphertext already stored for it.
    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn store_standalone_sapling_key(
        &self,
        encrypted: &EncryptedStandaloneSaplingKey,
    ) -> Result<(), Error> {
        self.with_db_mut(|conn, _| {
            encrypted
                .store_with(|sql, params| conn.execute(sql, params))
                .map_err(|e| ErrorKind::Generic.context(e))?;
            Ok(())
        })
        .await
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn encrypt_and_store_standalone_sapling_key(
        &self,
        sapling_key: &ExtendedSpendingKey,
    ) -> Result<DiversifiableFullViewingKey, Error> {
        let encrypted = self.encrypt_standalone_sapling_key(sapling_key).await?;
        self.store_standalone_sapling_key(&encrypted).await?;
        Ok(encrypted.dfvk)
    }

    #[cfg(feature = "zcashd-import")]
    #[allow(dead_code)]
    pub(crate) async fn encrypt_and_store_standalone_transparent_key(
        &self,
        key: &zcash_keys::keys::transparent::Key,
    ) -> Result<(), Error> {
        self.store_encrypted_standalone_transparent_keys(&[self
            .encryptor()
            .await?
            .encrypt_standalone_transparent_key(key)?])
            .await
    }

    /// Stores a batch of encrypted standalone transparent keys produced by
    /// [`Encryptor::encrypt_standalone_transparent_key`].
    ///
    /// This creates a single database transaction for all inserts, significantly reducing
    /// overhead for large migrated wallets.
    #[cfg(feature = "zcashd-import")]
    pub(crate) async fn store_encrypted_standalone_transparent_keys(
        &self,
        keys: &[EncryptedStandaloneTransparentKey],
    ) -> Result<(), Error> {
        self.with_db_mut(|conn, _| {
            // Use an explicit transaction to avoid autocommit mode and reduce overhead.
            let tx = conn
                .transaction()
                .map_err(|e| ErrorKind::Generic.context(e))?;

            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO ext_zallet_keystore_standalone_transparent_keys
                        VALUES (:pubkey, :encrypted_key_bytes)
                        ON CONFLICT (pubkey) DO NOTHING ",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                for key in keys {
                    stmt.execute(named_params! {
                        ":pubkey": &key.pubkey.serialize(),
                        ":encrypted_key_bytes": key.encrypted_key_bytes,
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                }
            }

            tx.commit().map_err(|e| ErrorKind::Generic.context(e))?;

            Ok(())
        })
        .await?;

        Ok(())
    }

    /// Decrypts the mnemonic phrase corresponding to the given seed fingerprint.
    pub(crate) async fn decrypt_mnemonic(
        &self,
        seed_fp: &SeedFingerprint,
    ) -> Result<SecretString, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let encrypted_mnemonic = self
            .with_db(|conn, _| {
                Ok(conn
                    .query_row(
                        "SELECT encrypted_mnemonic
                        FROM ext_zallet_keystore_mnemonics
                        WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                        named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?)
            })
            .await?;

        let mnemonic = decrypt_string(&identities, &encrypted_mnemonic)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        // The ciphertext is not bound to the fingerprint the row is keyed by, so verify
        // that the decrypted mnemonic reproduces the fingerprint used for the lookup.
        if !mnemonic_matches_fingerprint(&mnemonic, seed_fp)? {
            return Err(ErrorKind::Generic
                .context(fl!("err-keystore-key-material-mismatch"))
                .into());
        }

        Ok(mnemonic)
    }

    /// Decrypts the seed with the given fingerprint.
    pub(crate) async fn decrypt_seed(
        &self,
        seed_fp: &SeedFingerprint,
    ) -> Result<SecretVec<u8>, Error> {
        let mnemonic = self.decrypt_mnemonic(seed_fp).await?;

        let mut seed_bytes = Mnemonic::<English>::from_phrase(mnemonic.expose_secret())
            .map_err(|e| ErrorKind::Generic.context(e))?
            .to_seed("");
        let seed = SecretVec::new(seed_bytes.to_vec());
        seed_bytes.zeroize();

        Ok(seed)
    }

    /// Decrypts the legacy non-mnemonic HD seed with the given fingerprint.
    ///
    /// Unlike [`Self::decrypt_seed`], this returns the raw seed bytes exactly as
    /// they were imported from `zcashd`, which are what the very-legacy
    /// transparent shielding OVK derivation operates on.
    pub(crate) async fn decrypt_legacy_seed(
        &self,
        seed_fp: &SeedFingerprint,
    ) -> Result<SecretVec<u8>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let encrypted_legacy_seed = self
            .with_db(|conn, _| {
                Ok(conn
                    .query_row(
                        "SELECT encrypted_legacy_seed
                        FROM ext_zallet_keystore_legacy_seeds
                        WHERE hd_seed_fingerprint = :hd_seed_fingerprint",
                        named_params! {":hd_seed_fingerprint": seed_fp.to_bytes()},
                        |row| row.get::<_, Vec<u8>>(0),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?)
            })
            .await?;

        let legacy_seed = decrypt_secret_bytes(&identities, &encrypted_legacy_seed)
            .map_err(|e| ErrorKind::Generic.context(e))?;

        // The ciphertext is not bound to the fingerprint the row is keyed by, so verify
        // that the decrypted seed reproduces the fingerprint used for the lookup.
        if !seed_matches_fingerprint(legacy_seed.expose_secret(), seed_fp) {
            return Err(ErrorKind::Generic
                .context(fl!("err-keystore-key-material-mismatch"))
                .into());
        }

        Ok(legacy_seed)
    }

    /// Exports the mnemonic phrase corresponding to the given seed fingerprint.
    pub(crate) async fn export_mnemonic(
        &self,
        seed_fp: &SeedFingerprint,
        armor: bool,
    ) -> Result<Vec<u8>, Error> {
        let encryptor = self.encryptor().await?;

        let mnemonic = self.decrypt_mnemonic(seed_fp).await?;

        let encrypted_mnemonic = encryptor.encrypt_string(
            mnemonic.expose_secret(),
            if armor {
                age::armor::Format::AsciiArmor
            } else {
                age::armor::Format::Binary
            },
        )?;

        Ok(encrypted_mnemonic)
    }

    /// Decrypts the standalone Sapling spending key corresponding to the given payment
    /// address, if one exists in the keystore.
    ///
    /// Unlike transparent keys (which can be looked up by address via a SQL join), Sapling
    /// keys require loading all standalone DFVKs and using `decrypt_diversifier` to find
    /// the one that matches the given payment address. This is because the DB schema only
    /// stores the DFVK, not the derived payment addresses.
    pub(crate) async fn decrypt_standalone_sapling_key(
        &self,
        address: &sapling::PaymentAddress,
    ) -> Result<Option<ExtendedSpendingKey>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        // Query all standalone sapling keys and find the one matching the address.
        let rows = self
            .with_db(|conn, _| {
                let mut stmt = conn
                    .prepare(
                        "SELECT dfvk, encrypted_sapling_extsk
                         FROM ext_zallet_keystore_standalone_sapling_keys",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                Ok(rows)
            })
            .await?;

        for (dfvk_bytes, encrypted_extsk) in rows {
            let dfvk_array: [u8; 128] = match dfvk_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            };
            let dfvk = DiversifiableFullViewingKey::from_bytes(&dfvk_array);
            if let Some(dfvk) = dfvk
                && dfvk.decrypt_diversifier(address).is_some()
            {
                let extsk = decrypt_standalone_sapling_extsk(&identities, &encrypted_extsk)?;

                // The ciphertext is not bound to the DFVK the row is keyed by, so verify
                // that the decrypted key reproduces it.
                if !bool::from(
                    extsk
                        .to_diversifiable_full_viewing_key()
                        .to_bytes()
                        .ct_eq(&dfvk_array),
                ) {
                    return Err(ErrorKind::Generic
                        .context(fl!("err-keystore-key-material-mismatch"))
                        .into());
                }

                return Ok(Some(extsk));
            }
        }

        Ok(None)
    }

    /// Looks up the standalone Orchard spending key whose full viewing key derives the given
    /// Orchard receiver, if one is stored in the keystore.
    pub(crate) async fn decrypt_standalone_orchard_key(
        &self,
        address: &orchard::Address,
    ) -> Result<Option<OrchardSpendingKey>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        // Query all standalone Orchard keys and find the one matching the address.
        let rows = self
            .with_db(|conn, _| {
                let mut stmt = conn
                    .prepare(
                        "SELECT fvk, encrypted_orchard_sk
                         FROM ext_zallet_keystore_standalone_orchard_keys",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                Ok(rows)
            })
            .await?;

        for (fvk_bytes, encrypted_sk) in rows {
            let fvk_array: [u8; 96] = match fvk_bytes.try_into() {
                Ok(arr) => arr,
                Err(_) => continue,
            };
            let Some(fvk) = OrchardFullViewingKey::from_bytes(&fvk_array) else {
                continue;
            };
            if fvk.scope_for_address(address).is_some() {
                let sk = decrypt_standalone_orchard_sk(&identities, &encrypted_sk)?;

                // The ciphertext is not bound to the FVK the row is keyed by, so verify
                // that the decrypted key reproduces it.
                if OrchardFullViewingKey::from(&sk).to_bytes() != fvk_array {
                    return Err(ErrorKind::Generic
                        .context(fl!("err-keystore-key-material-mismatch"))
                        .into());
                }

                return Ok(Some(sk));
            }
        }

        Ok(None)
    }

    /// Looks up the standalone unified spending key whose incoming viewing key derives all of
    /// the shielded receivers in the given unified address, if one is stored in the keystore.
    ///
    /// A unified address with no shielded receivers never matches: this keystore holds only
    /// shielded key material.
    pub(crate) async fn decrypt_standalone_unified_key(
        &self,
        address: &UnifiedAddress,
    ) -> Result<Option<UnifiedSpendingKey>, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        // Query all standalone unified keys and find the one matching the address.
        let (network, rows) = self
            .with_db(|conn, network| {
                let mut stmt = conn
                    .prepare(
                        "SELECT ufvk, encrypted_usk
                         FROM ext_zallet_keystore_standalone_unified_keys",
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(|e| ErrorKind::Generic.context(e))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ErrorKind::Generic.context(e))?;

                Ok((*network, rows))
            })
            .await?;

        for (ufvk_bytes, encrypted_usk) in rows {
            let usk = decrypt_standalone_unified_sk(&identities, &encrypted_usk)?;

            // The ciphertext is not bound to the UFVK the row is keyed by, so verify
            // that the decrypted key reproduces it.
            if usk
                .to_unified_full_viewing_key()
                .encode(&network)
                .as_bytes()
                != ufvk_bytes
            {
                return Err(ErrorKind::Generic
                    .context(fl!("err-keystore-key-material-mismatch"))
                    .into());
            }

            if unified_spending_key_matches_address(&usk, address) {
                return Ok(Some(usk));
            }
        }

        Ok(None)
    }

    #[cfg(feature = "transparent-key-import")]
    pub(crate) async fn decrypt_standalone_transparent_key(
        &self,
        address: &TransparentAddress,
    ) -> Result<secp256k1::SecretKey, Error> {
        // Acquire a read lock on the identities for decryption.
        let identities = self.identities.read().await;
        if identities.is_empty() {
            return Err(ErrorKind::Generic.context(fl!("err-wallet-locked")).into());
        }

        let (pubkey_bytes, encrypted_key_bytes) = self
            .with_db(|conn, network| {
                let addr_str = Address::Transparent(*address).encode(network);
                let row = conn
                    .query_row(
                        "SELECT ztk.pubkey, encrypted_transparent_privkey
                         FROM ext_zallet_keystore_standalone_transparent_keys ztk
                         JOIN addresses a ON ztk.pubkey = a.imported_transparent_receiver_pubkey
                         WHERE a.cached_transparent_receiver_address = :address",
                        named_params! {
                            ":address": addr_str,
                        },
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>("pubkey")?,
                                row.get::<_, Vec<u8>>("encrypted_transparent_privkey")?,
                            ))
                        },
                    )
                    .map_err(|e| ErrorKind::Generic.context(e))?;
                Ok(row)
            })
            .await?;

        let secret_key =
            decrypt_standalone_transparent_privkey(&identities, &encrypted_key_bytes[..])?;

        // The ciphertext is not bound to the pubkey the row is keyed by, so verify that
        // the decrypted key reproduces the pubkey used for the lookup.
        let pubkey = secret_key.public_key(&secp256k1::Secp256k1::signing_only());
        if pubkey.serialize()[..] != pubkey_bytes[..] {
            return Err(ErrorKind::Generic
                .context(fl!("err-keystore-key-material-mismatch"))
                .into());
        }

        Ok(secret_key)
    }
}

/// Canonicalizes the contents of an age recipients file into bare recipient strings.
///
/// The age recipients-file format permits blank lines and `#`-prefixed comments; neither
/// is a recipient, so both are dropped rather than stored. `@`-prefixed entries are
/// rejected: they denote indirection through an external source, which would make the
/// effective recipient set depend on state outside the stored set itself.
pub(crate) fn canonicalize_recipients_file(contents: &str) -> Result<Vec<String>, KeystoreError> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            if line.starts_with('@') {
                Err(KeystoreError::RecipientIndirection(line.into()))
            } else {
                Ok(line.into())
            }
        })
        .collect()
}

pub(crate) struct Encryptor {
    recipient_strings: Vec<String>,
    recipients: Vec<Box<dyn age::Recipient + Send>>,
}

impl Encryptor {
    fn from_recipient_strings(recipient_strings: Vec<String>) -> Result<Self, Error> {
        let recipients = Self::parse_recipient_strings(recipient_strings.clone())?;
        Ok(Self {
            recipient_strings,
            recipients,
        })
    }

    fn parse_recipient_strings(
        recipient_strings: Vec<String>,
    ) -> Result<Vec<Box<dyn age::Recipient + Send>>, Error> {
        // TODO: Replace with a helper with configurable callbacks.
        let mut stdin_guard = age::cli_common::StdinGuard::new(false);
        let recipients = age::cli_common::read_recipients(
            recipient_strings,
            vec![],
            vec![],
            None,
            &mut stdin_guard,
        )
        .map_err(|e| ErrorKind::Generic.context(e))?;
        Ok(recipients)
    }

    fn is_empty(&self) -> bool {
        self.recipient_strings.is_empty()
    }

    fn encrypt_string(
        &self,
        plaintext: &str,
        format: age::armor::Format,
    ) -> Result<Vec<u8>, Error> {
        encrypt_string(&self.recipients, plaintext, format)
            .map_err(|e| ErrorKind::Generic.context(e).into())
    }

    #[cfg(feature = "zcashd-import")]
    pub(crate) fn encrypt_standalone_transparent_key(
        &self,
        key: &zcash_keys::keys::transparent::Key,
    ) -> Result<EncryptedStandaloneTransparentKey, Error> {
        let encrypted_key_bytes = self
            .encrypt_standalone_transparent_privkey(key.secret())
            .map_err(|e| ErrorKind::Generic.context(e))?;

        Ok(EncryptedStandaloneTransparentKey {
            pubkey: key.pubkey(),
            encrypted_key_bytes,
        })
    }

    #[cfg(feature = "zcashd-import")]
    fn encrypt_legacy_seed_bytes(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<Vec<u8>, age::EncryptError> {
        encrypt_secret(&self.recipients, seed)
    }

    fn encrypt_standalone_sapling_key(
        &self,
        key: &ExtendedSpendingKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.to_bytes().to_vec());
        encrypt_secret(&self.recipients, &secret)
    }

    fn encrypt_standalone_orchard_key(
        &self,
        key: &OrchardSpendingKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.to_bytes().to_vec());
        encrypt_secret(&self.recipients, &secret)
    }

    fn encrypt_standalone_unified_key(
        &self,
        key: &UnifiedSpendingKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.to_bytes(Era::Orchard));
        encrypt_secret(&self.recipients, &secret)
    }

    #[cfg(feature = "zcashd-import")]
    fn encrypt_standalone_transparent_privkey(
        &self,
        key: &secp256k1::SecretKey,
    ) -> Result<Vec<u8>, age::EncryptError> {
        let secret = SecretVec::new(key.secret_bytes().to_vec());
        encrypt_secret(&self.recipients, &secret)
    }
}

/// Idempotent upsert for an encrypted standalone Sapling key, shared by the pooled-connection
/// and in-transaction write paths so the SQL and table layout live in one place. The `dfvk`
/// key uniquely identifies the plaintext, so re-storing a key replaces the stored ciphertext,
/// refreshing it to the current encryption recipients.
const INSERT_STANDALONE_SAPLING_KEY_SQL: &str =
    "INSERT INTO ext_zallet_keystore_standalone_sapling_keys
    VALUES (:dfvk, :encrypted_sapling_extsk)
    ON CONFLICT (dfvk) DO UPDATE SET encrypted_sapling_extsk = :encrypted_sapling_extsk ";

/// An age-encrypted standalone Sapling spending key, ready to be persisted.
///
/// Produced by [`KeyStore::encrypt_standalone_sapling_key`]; holds only ciphertext and the
/// derived (public) full viewing key used as the table's key, so it carries no plaintext.
pub(crate) struct EncryptedStandaloneSaplingKey {
    dfvk: DiversifiableFullViewingKey,
    encrypted_sapling_extsk: Vec<u8>,
}

impl EncryptedStandaloneSaplingKey {
    /// Runs the upsert against the given executor (a pooled connection or an extension
    /// transaction), replacing any ciphertext already stored for this key.
    fn store_with(
        &self,
        execute: impl FnOnce(&str, &[(&str, &dyn rusqlite::ToSql)]) -> rusqlite::Result<usize>,
    ) -> rusqlite::Result<()> {
        execute(
            INSERT_STANDALONE_SAPLING_KEY_SQL,
            named_params! {
                ":dfvk": &self.dfvk.to_bytes(),
                ":encrypted_sapling_extsk": self.encrypted_sapling_extsk,
            },
        )?;
        Ok(())
    }

    /// Writes this key into the keystore table using the given wallet-database extension
    /// transaction, so the write commits atomically with the caller's other wallet writes.
    pub(crate) fn insert(&self, ext: &ExtensionTransaction<'_>) -> rusqlite::Result<()> {
        self.store_with(|sql, params| ext.execute(sql, params))
    }
}

/// Idempotent upsert for an encrypted standalone Orchard key, shared by the pooled-connection
/// and in-transaction write paths so the SQL and table layout live in one place. The `fvk`
/// key uniquely identifies the plaintext, so re-storing a key replaces the stored ciphertext,
/// refreshing it to the current encryption recipients.
const INSERT_STANDALONE_ORCHARD_KEY_SQL: &str =
    "INSERT INTO ext_zallet_keystore_standalone_orchard_keys
    VALUES (:fvk, :encrypted_orchard_sk)
    ON CONFLICT (fvk) DO UPDATE SET encrypted_orchard_sk = :encrypted_orchard_sk ";

/// An age-encrypted standalone Orchard spending key, ready to be persisted.
///
/// Produced by [`KeyStore::encrypt_standalone_orchard_key`]; holds only ciphertext and the
/// derived (public) full viewing key used as the table's key, so it carries no plaintext.
pub(crate) struct EncryptedStandaloneOrchardKey {
    fvk: OrchardFullViewingKey,
    encrypted_orchard_sk: Vec<u8>,
}

impl EncryptedStandaloneOrchardKey {
    /// Runs the upsert against the given executor (a pooled connection or an extension
    /// transaction), replacing any ciphertext already stored for this key.
    fn store_with(
        &self,
        execute: impl FnOnce(&str, &[(&str, &dyn rusqlite::ToSql)]) -> rusqlite::Result<usize>,
    ) -> rusqlite::Result<()> {
        execute(
            INSERT_STANDALONE_ORCHARD_KEY_SQL,
            named_params! {
                ":fvk": &self.fvk.to_bytes(),
                ":encrypted_orchard_sk": self.encrypted_orchard_sk,
            },
        )?;
        Ok(())
    }

    /// Writes this key into the keystore table using the given wallet-database extension
    /// transaction, so the write commits atomically with the caller's other wallet writes.
    pub(crate) fn insert(&self, ext: &ExtensionTransaction<'_>) -> rusqlite::Result<()> {
        self.store_with(|sql, params| ext.execute(sql, params))
    }
}

/// Idempotent upsert for an encrypted standalone unified key, shared by the pooled-connection
/// and in-transaction write paths so the SQL and table layout live in one place. The `ufvk`
/// key uniquely identifies the plaintext, so re-storing a key replaces the stored ciphertext,
/// refreshing it to the current encryption recipients.
const INSERT_STANDALONE_UNIFIED_KEY_SQL: &str =
    "INSERT INTO ext_zallet_keystore_standalone_unified_keys
    VALUES (:ufvk, :encrypted_usk)
    ON CONFLICT (ufvk) DO UPDATE SET encrypted_usk = :encrypted_usk ";

/// An age-encrypted standalone unified spending key, ready to be persisted.
///
/// Produced by [`KeyStore::encrypt_standalone_unified_key`]; holds only ciphertext and the
/// derived (public) unified full viewing key encoding used as the table's key, so it carries
/// no plaintext.
pub(crate) struct EncryptedStandaloneUnifiedKey {
    ufvk_encoded: String,
    encrypted_usk: Vec<u8>,
}

impl EncryptedStandaloneUnifiedKey {
    /// Runs the upsert against the given executor (a pooled connection or an extension
    /// transaction), replacing any ciphertext already stored for this key.
    fn store_with(
        &self,
        execute: impl FnOnce(&str, &[(&str, &dyn rusqlite::ToSql)]) -> rusqlite::Result<usize>,
    ) -> rusqlite::Result<()> {
        execute(
            INSERT_STANDALONE_UNIFIED_KEY_SQL,
            named_params! {
                ":ufvk": &self.ufvk_encoded.as_bytes(),
                ":encrypted_usk": self.encrypted_usk,
            },
        )?;
        Ok(())
    }

    /// Writes this key into the keystore table using the given wallet-database extension
    /// transaction, so the write commits atomically with the caller's other wallet writes.
    pub(crate) fn insert(&self, ext: &ExtensionTransaction<'_>) -> rusqlite::Result<()> {
        self.store_with(|sql, params| ext.execute(sql, params))
    }
}

/// An age-encrypted standalone spending key of any supported kind, ready to be persisted.
///
/// This lets callers that accept several key formats (such as `z_importkey`) keep a single
/// atomic account-import transaction instead of one per key kind.
pub(crate) enum EncryptedStandaloneKey {
    Sapling(Box<EncryptedStandaloneSaplingKey>),
    Orchard(EncryptedStandaloneOrchardKey),
    Unified(EncryptedStandaloneUnifiedKey),
}

impl EncryptedStandaloneKey {
    /// Writes this key into its keystore table using the given wallet-database extension
    /// transaction, so the write commits atomically with the caller's other wallet writes.
    pub(crate) fn insert(&self, ext: &ExtensionTransaction<'_>) -> rusqlite::Result<()> {
        match self {
            EncryptedStandaloneKey::Sapling(key) => key.insert(ext),
            EncryptedStandaloneKey::Orchard(key) => key.insert(ext),
            EncryptedStandaloneKey::Unified(key) => key.insert(ext),
        }
    }
}

#[cfg(feature = "zcashd-import")]
pub(crate) struct EncryptedStandaloneTransparentKey {
    pubkey: secp256k1::PublicKey,
    encrypted_key_bytes: Vec<u8>,
}

fn encrypt_string(
    recipients: &[Box<dyn age::Recipient + Send>],
    plaintext: &str,
    format: age::armor::Format,
) -> Result<Vec<u8>, age::EncryptError> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _))?;

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut writer = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut ciphertext,
        format,
    )?)?;
    writer.write_all(plaintext.as_bytes())?;
    writer.finish()?.finish()?;

    Ok(ciphertext)
}

/// Returns whether the given seed bytes have the given [ZIP 32] seed fingerprint.
///
/// Keystore rows are keyed by seed fingerprint, but their ciphertexts are not bound to
/// that key (age recipients are public), so decrypted seed material must be checked
/// against the fingerprint it was looked up by before use.
///
/// [ZIP 32]: https://zips.z.cash/zip-0032#seed-fingerprints
fn seed_matches_fingerprint(seed: &[u8], seed_fp: &SeedFingerprint) -> bool {
    SeedFingerprint::from_seed(seed)
        .is_some_and(|fp| bool::from(fp.to_bytes().ct_eq(&seed_fp.to_bytes())))
}

/// Returns whether the seed derived from the given mnemonic phrase has the given [ZIP 32]
/// seed fingerprint.
///
/// [ZIP 32]: https://zips.z.cash/zip-0032#seed-fingerprints
fn mnemonic_matches_fingerprint(
    mnemonic: &SecretString,
    seed_fp: &SeedFingerprint,
) -> Result<bool, Error> {
    let mut seed_bytes = Mnemonic::<English>::from_phrase(mnemonic.expose_secret())
        .map_err(|e| ErrorKind::Generic.context(e))?
        .to_seed("");
    let matches = seed_matches_fingerprint(&seed_bytes, seed_fp);
    seed_bytes.zeroize();
    Ok(matches)
}

fn decrypt_string(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<SecretString, age::DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // string ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = String::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))?
        .read_to_string(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretString` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let mnemonic = SecretString::new(buf);
    res?;

    Ok(mnemonic)
}

/// Decrypts age-encrypted ciphertext into raw secret bytes.
fn decrypt_secret_bytes(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<SecretVec<u8>, age::DecryptError> {
    let decryptor = age::Decryptor::new(ciphertext)?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // buffer ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = Vec::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))?
        .read_to_end(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretVec` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let secret = SecretVec::new(buf);
    res?;

    Ok(secret)
}

fn encrypt_secret(
    recipients: &[Box<dyn age::Recipient + Send>],
    secret: &SecretVec<u8>,
) -> Result<Vec<u8>, age::EncryptError> {
    let encryptor = age::Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _))?;

    let mut ciphertext = Vec::with_capacity(secret.expose_secret().len());
    let mut writer = encryptor.wrap_output(&mut ciphertext)?;
    writer.write_all(secret.expose_secret())?;
    writer.finish()?;

    Ok(ciphertext)
}

/// The byte length of a raw Orchard spending key: a 32-byte scalar.
const ORCHARD_SPENDING_KEY_BYTES: usize = 32;

/// Encoding version for the unified spending key strings accepted and produced by
/// `z_exportkey` / `z_importkey`.
///
/// Version 1 is the `UnifiedSpendingKey::to_bytes(Era::Orchard)` binary encoding prefixed
/// with this version byte, hex-encoded. The prefix distinguishes the format from a raw
/// 32-byte Orchard spending key (64 hex characters) and leaves room for future formats.
const UNIFIED_SPENDING_KEY_VERSION: u8 = 1;

/// Encodes a standalone Orchard spending key for the user: the raw 32-byte key as
/// lowercase hex.
///
/// Unlike the unified spending key, a raw Orchard spending key needs no version byte: its
/// fixed 64-hex-character length already distinguishes it from the other accepted formats.
pub(crate) fn encode_orchard_spending_key(key: &OrchardSpendingKey) -> String {
    hex::encode(key.to_bytes())
}

/// Decodes a standalone Orchard spending key from its hex encoding.
pub(crate) fn decode_orchard_spending_key(s: &str) -> Result<OrchardSpendingKey, Error> {
    let bytes =
        hex::decode(s).map_err(|_| ErrorKind::Generic.context("Invalid Orchard spending key"))?;
    let key_bytes: [u8; ORCHARD_SPENDING_KEY_BYTES] = bytes
        .try_into()
        .map_err(|_| ErrorKind::Generic.context("Invalid Orchard spending key"))?;
    Option::from(OrchardSpendingKey::from_bytes(key_bytes)).ok_or_else(|| {
        ErrorKind::Generic
            .context("Invalid Orchard spending key")
            .into()
    })
}

/// Encodes a standalone unified spending key for the user: the version byte
/// [`UNIFIED_SPENDING_KEY_VERSION`] followed by the `UnifiedSpendingKey::to_bytes(Era::Orchard)`
/// binary encoding, hex-encoded.
pub(crate) fn encode_unified_spending_key(key: &UnifiedSpendingKey) -> String {
    let mut bytes = vec![UNIFIED_SPENDING_KEY_VERSION];
    bytes.extend_from_slice(&key.to_bytes(Era::Orchard));
    hex::encode(bytes)
}

/// Decodes a standalone unified spending key from its hex encoding.
///
/// The string must start with the version byte [`UNIFIED_SPENDING_KEY_VERSION`]; the
/// version byte exists only in this user-facing encoding, while the keystore stores the
/// unversioned `to_bytes(Era::Orchard)` plaintext.
pub(crate) fn decode_unified_spending_key(s: &str) -> Result<UnifiedSpendingKey, Error> {
    let invalid = || ErrorKind::Generic.context("Invalid unified spending key");
    let bytes = hex::decode(s).map_err(|_| invalid())?;
    let (version, rest) = bytes.split_first().ok_or_else(invalid)?;
    if *version != UNIFIED_SPENDING_KEY_VERSION {
        return Err(invalid().into());
    }
    UnifiedSpendingKey::from_bytes(Era::Orchard, rest).map_err(|_| invalid().into())
}

/// Returns whether the unified spending key's incoming viewing key derives every shielded
/// receiver in the given unified address.
///
/// Each shielded receiver present in the address must be derivable from the key; an address
/// with no shielded receivers at all never matches, since this keystore holds only shielded
/// key material.
pub(crate) fn unified_spending_key_matches_address(
    usk: &UnifiedSpendingKey,
    address: &UnifiedAddress,
) -> bool {
    let uivk = usk
        .to_unified_full_viewing_key()
        .to_unified_incoming_viewing_key();

    let sapling_matches = address
        .sapling()
        .map(|receiver| {
            uivk.sapling()
                .as_ref()
                .is_some_and(|ivk| ivk.decrypt_diversifier(receiver).is_some())
        })
        .unwrap_or(true);
    let orchard_matches = address
        .orchard()
        .map(|receiver| {
            uivk.orchard()
                .as_ref()
                .is_some_and(|ivk| ivk.diversifier_index(receiver).is_some())
        })
        .unwrap_or(true);

    let has_shielded_receiver = address.sapling().is_some() || address.orchard().is_some();

    has_shielded_receiver && sapling_matches && orchard_matches
}

fn decrypt_standalone_sapling_extsk(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<ExtendedSpendingKey, Error> {
    let decryptor = age::Decryptor::new(ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;

    // The plaintext is always shorter than the ciphertext. Over-allocating the initial
    // buffer ensures that no internal re-allocations occur that might leave plaintext
    // bytes strewn around the heap.
    let mut buf = Vec::with_capacity(ciphertext.len());
    let res = decryptor
        .decrypt(identities.iter().map(|i| i.as_ref() as _))
        .map_err(|e| ErrorKind::Generic.context(e))?
        .read_to_end(&mut buf);

    // We intentionally do not use `?` on the decryption expression because doing so in
    // the case of a partial failure could result in part of the secret data being read
    // into `buf`, which would not then be properly zeroized. Instead, we take ownership
    // of the buffer in construction of a `SecretVec` to ensure that the memory is
    // zeroed out when we raise the error on the following line.
    let buf_secret = SecretVec::new(buf);
    res.map_err(|e| ErrorKind::Generic.context(e))?;
    let extsk = ExtendedSpendingKey::from_bytes(buf_secret.expose_secret())
        .map_err(|_| ErrorKind::Generic.context("Invalid Sapling extended spending key"))?;

    Ok(extsk)
}

/// Decrypts the age-encrypted standalone Orchard spending key stored by
/// [`EncryptedStandaloneOrchardKey`].
///
/// The stored plaintext is the raw 32-byte key, matching [`encode_orchard_spending_key`]'s
/// wire format minus the hex encoding.
fn decrypt_standalone_orchard_sk(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<OrchardSpendingKey, Error> {
    let secret =
        decrypt_secret_bytes(identities, ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;
    let key_bytes: [u8; ORCHARD_SPENDING_KEY_BYTES] = secret
        .expose_secret()
        .as_slice()
        .try_into()
        .map_err(|_| ErrorKind::Generic.context("Invalid Orchard spending key"))?;
    Option::from(OrchardSpendingKey::from_bytes(key_bytes)).ok_or_else(|| {
        ErrorKind::Generic
            .context("Invalid Orchard spending key")
            .into()
    })
}

/// Decrypts the age-encrypted standalone unified spending key stored by
/// [`EncryptedStandaloneUnifiedKey`].
///
/// The stored plaintext is the unversioned `to_bytes(Era::Orchard)` binary encoding; the
/// version byte exists only in the user-facing [`decode_unified_spending_key`] encoding.
fn decrypt_standalone_unified_sk(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<UnifiedSpendingKey, Error> {
    let secret =
        decrypt_secret_bytes(identities, ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;
    UnifiedSpendingKey::from_bytes(Era::Orchard, secret.expose_secret()).map_err(|_| {
        ErrorKind::Generic
            .context("Invalid unified spending key")
            .into()
    })
}

#[cfg(feature = "transparent-key-import")]
fn decrypt_standalone_transparent_privkey(
    identities: &[Box<dyn age::Identity + Send + Sync>],
    ciphertext: &[u8],
) -> Result<secp256k1::SecretKey, Error> {
    let secret =
        decrypt_secret_bytes(identities, ciphertext).map_err(|e| ErrorKind::Generic.context(e))?;
    let secret_key = secp256k1::SecretKey::from_slice(secret.expose_secret())
        .map_err(|e| ErrorKind::Generic.context(e))?;

    Ok(secret_key)
}

/// Helpers for building a real keystore in unit tests.
///
/// Lives here rather than in each test module because a keystore needs a wallet database
/// and an age identity on disk, which is more setup than is worth repeating.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write;

    use bip0039::{English, Mnemonic};
    use tempfile::TempDir;
    use zcash_protocol::consensus::NetworkType;

    use super::KeyStore;
    use crate::{components::database::Database, config::ZalletConfig};

    /// Builds a keystore backed by a fresh wallet database and a fresh age identity.
    ///
    /// `configure` may adjust the config before the keystore reads it, for tests that
    /// depend on a config-derived policy such as `keystore.require_backup`.
    pub(crate) async fn keystore_with_config(
        datadir: &TempDir,
        configure: impl FnOnce(&mut ZalletConfig),
    ) -> KeyStore {
        crate::i18n::load_languages(&[]);

        let identity = age::x25519::Identity::generate();
        let identity_path = datadir.path().join("encryption-identity.txt");
        let mut identity_file = std::fs::File::create(&identity_path).unwrap();
        writeln!(
            identity_file,
            "{}",
            age::secrecy::ExposeSecret::expose_secret(&identity.to_string()),
        )
        .unwrap();
        drop(identity_file);

        let mut config = ZalletConfig {
            datadir: Some(datadir.path().to_path_buf()),
            consensus: crate::config::ConsensusSection {
                network: NetworkType::Test,
                ..Default::default()
            },
            keystore: crate::config::KeyStoreSection {
                encryption_identity: Some(identity_path),
                ..Default::default()
            },
            ..Default::default()
        };
        configure(&mut config);

        let db = Database::open(&config).await.unwrap();
        let keystore = KeyStore::new(&config, db).unwrap();
        keystore
            .initialize_recipients(vec![identity.to_public().to_string()])
            .await
            .unwrap();

        keystore
    }

    /// Builds a keystore with the default configuration.
    pub(crate) async fn keystore(datadir: &TempDir) -> KeyStore {
        keystore_with_config(datadir, |_| {}).await
    }

    /// Builds a deterministic mnemonic phrase from fixed entropy.
    pub(crate) fn phrase(entropy: [u8; 32]) -> Mnemonic {
        Mnemonic::<English>::from_entropy(entropy).expect("valid entropy")
    }

    /// Runs an async test body on a multi-threaded runtime.
    pub(crate) fn run_async<F: Future>(f: impl FnOnce() -> F) -> F::Output {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f())
    }
}

#[cfg(test)]
mod tests {
    use bip0039::{English, Mnemonic};
    use proptest::prelude::*;
    use secrecy::SecretString;
    use tempfile::tempdir;
    use zip32::fingerprint::SeedFingerprint;

    use super::{
        BackupStatus, KeystoreError, canonicalize_recipients_file, mnemonic_matches_fingerprint,
        seed_matches_fingerprint,
        testing::{keystore as test_keystore, phrase, run_async},
    };

    #[test]
    fn generated_mnemonics_start_unconfirmed_and_confirm_once() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([0; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();
            assert!(
                !keystore.backup_confirmed(&seed_fp).await.unwrap(),
                "a phrase Zallet generated has not been backed up by anyone yet",
            );

            keystore.confirm_backup(&seed_fp).await.unwrap();
            assert!(keystore.backup_confirmed(&seed_fp).await.unwrap());
        });
    }

    #[test]
    fn imported_mnemonics_are_confirmed_on_arrival() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([1; 32]), BackupStatus::Confirmed)
                .await
                .unwrap();

            assert!(
                keystore.backup_confirmed(&seed_fp).await.unwrap(),
                "the operator typed this phrase in, so they already hold it",
            );
        });
    }

    #[test]
    fn re_importing_a_generated_mnemonic_confirms_it() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            // Zallet generates the phrase...
            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([2; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();
            assert!(!keystore.backup_confirmed(&seed_fp).await.unwrap());

            // ... and the operator later types it back in, which demonstrates that they
            // hold it just as reading it back to `confirm-backup` would.
            let reimported = keystore
                .encrypt_and_store_mnemonic(phrase([2; 32]), BackupStatus::Confirmed)
                .await
                .unwrap();

            assert_eq!(reimported.to_bytes(), seed_fp.to_bytes());
            assert!(keystore.backup_confirmed(&seed_fp).await.unwrap());
        });
    }

    #[test]
    fn storing_a_confirmed_mnemonic_again_does_not_unconfirm_it() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([3; 32]), BackupStatus::Confirmed)
                .await
                .unwrap();

            keystore
                .encrypt_and_store_mnemonic(phrase([3; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            assert!(
                keystore.backup_confirmed(&seed_fp).await.unwrap(),
                "confirmation must never be withdrawn by a later store",
            );
        });
    }

    #[test]
    fn backup_is_required_only_while_unconfirmed_and_the_policy_is_on() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([4; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            assert!(
                keystore.backup_required(&seed_fp).await.unwrap(),
                "an unconfirmed phrase must block derivation while the policy is on",
            );

            keystore.confirm_backup(&seed_fp).await.unwrap();
            assert!(
                !keystore.backup_required(&seed_fp).await.unwrap(),
                "confirming must unblock derivation",
            );
        });
    }

    #[test]
    fn backup_is_never_required_when_the_policy_is_off() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = super::testing::keystore_with_config(&datadir, |config| {
                config.keystore.require_backup = Some(false);
            })
            .await;

            let seed_fp = keystore
                .encrypt_and_store_mnemonic(phrase([5; 32]), BackupStatus::Unconfirmed)
                .await
                .unwrap();

            assert!(
                !keystore.backup_confirmed(&seed_fp).await.unwrap(),
                "the phrase is still unconfirmed; only the policy has been turned off",
            );
            assert!(
                !keystore.backup_required(&seed_fp).await.unwrap(),
                "keystore.require_backup = false must not block derivation",
            );
        });
    }

    #[test]
    fn a_seed_with_no_mnemonic_is_never_reported_as_backed_up() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;

            let absent = SeedFingerprint::from_bytes([9; 32]);

            assert!(!keystore.backup_confirmed(&absent).await.unwrap());
            keystore
                .confirm_backup(&absent)
                .await
                .expect_err("there is no phrase here to have been backed up");
        });
    }

    proptest! {
        #[test]
        fn seed_matches_its_own_fingerprint(seed in proptest::collection::vec(any::<u8>(), 32..=252)) {
            let seed_fp = SeedFingerprint::from_seed(&seed).expect("valid length");
            prop_assert!(seed_matches_fingerprint(&seed, &seed_fp));
        }

        #[test]
        fn seed_does_not_match_other_fingerprint(
            seed in proptest::collection::vec(any::<u8>(), 32..=252),
            other_fp in any::<[u8; 32]>(),
        ) {
            let seed_fp = SeedFingerprint::from_seed(&seed).expect("valid length");
            let other_fp = SeedFingerprint::from_bytes(other_fp);
            prop_assert_eq!(
                seed_matches_fingerprint(&seed, &other_fp),
                other_fp.to_bytes() == seed_fp.to_bytes(),
            );
        }

        #[test]
        fn invalid_length_seed_matches_no_fingerprint(
            seed in proptest::collection::vec(any::<u8>(), 0..32),
            seed_fp in any::<[u8; 32]>(),
        ) {
            prop_assert!(!seed_matches_fingerprint(&seed, &SeedFingerprint::from_bytes(seed_fp)));
        }
    }

    proptest! {
        // Deriving a seed from a mnemonic uses PBKDF2, which is slow in unoptimized
        // builds, so run fewer cases than the default.
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn mnemonic_matches_only_its_own_fingerprint(
            entropy in any::<[u8; 32]>(),
            other_fp in any::<[u8; 32]>(),
        ) {
            let mnemonic = Mnemonic::<English>::from_entropy(entropy).expect("valid entropy");
            let seed_fp = SeedFingerprint::from_seed(&mnemonic.to_seed("")).expect("valid length");
            let phrase = SecretString::new(mnemonic.into_phrase());

            prop_assert!(mnemonic_matches_fingerprint(&phrase, &seed_fp).expect("valid phrase"));

            let other_fp = SeedFingerprint::from_bytes(other_fp);
            prop_assert_eq!(
                mnemonic_matches_fingerprint(&phrase, &other_fp).expect("valid phrase"),
                other_fp.to_bytes() == seed_fp.to_bytes(),
            );
        }
    }

    #[test]
    fn invalid_phrase_is_an_error() {
        let phrase = SecretString::new("not a mnemonic".into());
        assert!(
            mnemonic_matches_fingerprint(&phrase, &SeedFingerprint::from_bytes([0; 32])).is_err()
        );
    }

    #[test]
    fn recipients_file_canonicalization_keeps_only_recipient_lines() {
        let contents =
            "# created: 2026-08-04\n\nage1first\n   \t\n  age1second  \n# trailing comment";
        assert_eq!(
            canonicalize_recipients_file(contents),
            Ok(vec!["age1first".into(), "age1second".into()]),
        );
    }

    #[test]
    fn recipients_file_canonicalization_handles_crlf() {
        let contents = "# comment\r\nage1first\r\n\r\nage1second\r\n";
        assert_eq!(
            canonicalize_recipients_file(contents),
            Ok(vec!["age1first".into(), "age1second".into()]),
        );
    }

    #[test]
    fn recipients_file_canonicalization_of_only_comments_is_empty() {
        assert_eq!(
            canonicalize_recipients_file("# nothing here\n\n"),
            Ok(vec![]),
        );
    }

    #[test]
    fn recipients_file_canonicalization_rejects_indirection() {
        assert_eq!(
            canonicalize_recipients_file("age1first\n  @/etc/age/recipients.txt\n"),
            Err(KeystoreError::RecipientIndirection(
                "@/etc/age/recipients.txt".into()
            )),
        );
    }
}

// -- Orchard and unified spending key codec and keystore tests --

#[cfg(test)]
mod orchard_unified_key_tests {
    use orchard::keys::{
        FullViewingKey as OrchardFullViewingKey, SpendingKey as OrchardSpendingKey,
    };
    use proptest::prelude::*;
    use tempfile::tempdir;
    use zcash_client_backend::data_api::{
        AccountBirthday, AccountPurpose, WalletRead, WalletWrite, chain::ChainState,
    };
    use zcash_keys::keys::{Era, UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::BlockHeight;

    use super::testing::{keystore as test_keystore, run_async};
    use super::{
        EncryptedStandaloneKey, ErrorKind, KeyStore, ORCHARD_SPENDING_KEY_BYTES,
        UNIFIED_SPENDING_KEY_VERSION, decode_orchard_spending_key, decode_unified_spending_key,
        encode_orchard_spending_key, encode_unified_spending_key,
        unified_spending_key_matches_address,
    };

    fn test_network() -> crate::network::Network {
        crate::network::Network::Consensus(zcash_protocol::consensus::Network::TestNetwork)
    }

    /// A deterministic Orchard spending key (the scalar 7) for codec and keystore tests.
    fn orchard_spending_key() -> OrchardSpendingKey {
        let mut bytes = [0u8; ORCHARD_SPENDING_KEY_BYTES];
        bytes[0] = 7;
        Option::from(OrchardSpendingKey::from_bytes(bytes))
            .expect("the scalar 7 is a valid Orchard spending key")
    }

    /// A deterministic unified spending key (Sapling + Orchard components) for codec and
    /// keystore tests.
    fn unified_spending_key() -> UnifiedSpendingKey {
        UnifiedSpendingKey::from_seed(&test_network(), &[7u8; 64], zip32::AccountId::ZERO)
            .expect("any 64-byte seed yields a unified spending key")
    }

    proptest! {
        #[test]
        fn orchard_spending_key_hex_roundtrip(seed in prop::array::uniform32(0u8..)) {
            // Only some 32-byte strings are valid scalars; skip the invalid ones.
            let Some(sk) = Option::from(OrchardSpendingKey::from_bytes(seed)) else {
                return Ok(());
            };
            let encoded = encode_orchard_spending_key(&sk);
            prop_assert_eq!(encoded.len(), 2 * ORCHARD_SPENDING_KEY_BYTES);
            let decoded = decode_orchard_spending_key(&encoded).unwrap();
            prop_assert_eq!(decoded.to_bytes(), sk.to_bytes());
        }

        #[test]
        fn unified_spending_key_hex_roundtrip(seed in any::<[u8; 64]>()) {
            let network = test_network();
            let usk = UnifiedSpendingKey::from_seed(&network, &seed, zip32::AccountId::ZERO)
                .expect("any 64-byte seed yields a unified spending key");
            let encoded = encode_unified_spending_key(&usk);
            // The version byte is the first byte of the decoded payload.
            let raw = hex::decode(&encoded).unwrap();
            prop_assert_eq!(raw[0], UNIFIED_SPENDING_KEY_VERSION);
            let decoded = decode_unified_spending_key(&encoded).unwrap();
            prop_assert_eq!(
                decoded.to_unified_full_viewing_key().encode(&network),
                usk.to_unified_full_viewing_key().encode(&network),
            );
        }
    }

    #[test]
    fn unified_spending_key_decode_rejects_unknown_version() {
        let usk = unified_spending_key();
        let mut raw = usk.to_bytes(Era::Orchard);
        raw[0] = raw[0].wrapping_add(1);
        let mut encoded = vec![UNIFIED_SPENDING_KEY_VERSION.wrapping_add(1)];
        encoded.extend_from_slice(&raw);
        assert!(decode_unified_spending_key(&hex::encode(encoded)).is_err());
    }

    #[test]
    fn unified_spending_key_decode_rejects_truncation() {
        let encoded = encode_unified_spending_key(&unified_spending_key());
        assert!(decode_unified_spending_key(&encoded[..encoded.len() - 2]).is_err());
        assert!(decode_unified_spending_key("").is_err());
    }

    #[test]
    fn orchard_spending_key_decode_rejects_bad_input() {
        // Not hex.
        assert!(decode_orchard_spending_key("not-hex").is_err());
        // Valid hex, wrong length. (The underlying `from_bytes` accepts essentially
        // every 32-byte input, so length and hex validity are what the decoder
        // enforces.)
        assert!(decode_orchard_spending_key(&"00".repeat(31)).is_err());
        assert!(decode_orchard_spending_key(&"00".repeat(33)).is_err());
        assert!(decode_orchard_spending_key("").is_err());
    }

    /// Stores an Orchard spending key via the same `transactionally_with_extension` path
    /// `z_importkey` uses (with no wallet-side write in this helper).
    async fn store_orchard_key(keystore: &KeyStore, sk: &OrchardSpendingKey) {
        let encrypted = EncryptedStandaloneKey::Orchard(
            keystore.encrypt_standalone_orchard_key(sk).await.unwrap(),
        );
        keystore.db.handle().await.unwrap().with_mut(|mut db_data| {
            db_data
                .transactionally_with_extension(|_, ext| encrypted.insert(ext))
                .unwrap();
        });
    }

    /// Stores a unified spending key via the same `transactionally_with_extension` path
    /// `z_importkey` uses (with no wallet-side write in this helper).
    async fn store_unified_key(
        keystore: &KeyStore,
        params: &crate::network::Network,
        usk: &UnifiedSpendingKey,
    ) {
        let encrypted = EncryptedStandaloneKey::Unified(
            keystore
                .encrypt_standalone_unified_key(params, usk)
                .await
                .unwrap(),
        );
        keystore.db.handle().await.unwrap().with_mut(|mut db_data| {
            db_data
                .transactionally_with_extension(|_, ext| encrypted.insert(ext))
                .unwrap();
        });
    }

    #[test]
    fn standalone_orchard_key_lookup_matches_by_receiver() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let sk = orchard_spending_key();
            let fvk = OrchardFullViewingKey::from(&sk);
            let expected_address = fvk.address_at(
                zip32::DiversifierIndex::new(),
                orchard::keys::Scope::External,
            );

            store_orchard_key(&keystore, &sk).await;

            let found = keystore
                .decrypt_standalone_orchard_key(&expected_address)
                .await
                .unwrap()
                .expect("the stored key must be found by its receiver");
            assert_eq!(found.to_bytes(), sk.to_bytes());

            // An unrelated Orchard address must not match.
            let mut other_bytes = [0u8; ORCHARD_SPENDING_KEY_BYTES];
            other_bytes[0] = 9;
            let other_sk: OrchardSpendingKey =
                Option::from(OrchardSpendingKey::from_bytes(other_bytes)).unwrap();
            let other_fvk = OrchardFullViewingKey::from(&other_sk);
            let other_address = other_fvk.address_at(
                zip32::DiversifierIndex::new(),
                orchard::keys::Scope::External,
            );
            assert!(
                keystore
                    .decrypt_standalone_orchard_key(&other_address)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    #[test]
    fn standalone_unified_key_lookup_matches_by_unified_address() {
        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let network = test_network();
            let usk = unified_spending_key();

            store_unified_key(&keystore, &network, &usk).await;

            // The key matches a unified address carrying all of its receivers...
            let ufvk = usk.to_unified_full_viewing_key();
            let (ua, _) = ufvk
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .unwrap();
            assert!(unified_spending_key_matches_address(&usk, &ua));
            let found = keystore
                .decrypt_standalone_unified_key(&ua)
                .await
                .unwrap()
                .expect("the stored key must be found by its unified address");
            assert_eq!(
                found.to_unified_full_viewing_key().encode(&network),
                ufvk.encode(&network)
            );

            // ... but not a unified address whose receivers it cannot derive.
            let other_usk =
                UnifiedSpendingKey::from_seed(&network, &[9u8; 64], zip32::AccountId::ZERO)
                    .unwrap();
            let (other_ua, _) = other_usk
                .to_unified_full_viewing_key()
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .unwrap();
            assert!(!unified_spending_key_matches_address(&usk, &other_ua));
            assert!(
                keystore
                    .decrypt_standalone_unified_key(&other_ua)
                    .await
                    .unwrap()
                    .is_none()
            );
        });
    }

    /// When the wallet holds both a full unified spending key and the standalone
    /// Orchard key for its Orchard receiver, exporting the unified address must
    /// return the unified key: it authorizes every receiver, while the Orchard
    /// key authorizes only one.
    #[test]
    fn unified_export_prefers_full_usk_over_component_keys() {
        use crate::components::json_rpc::methods::export_key::export_unified_key;

        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let network = test_network();
            let usk = unified_spending_key();
            let orchard_sk = *usk.orchard();

            // Store the component Orchard key FIRST, so the test proves the
            // export prefers the USK rather than returning the first match.
            store_orchard_key(&keystore, &orchard_sk).await;
            store_unified_key(&keystore, &network, &usk).await;

            let (ua, _) = usk
                .to_unified_full_viewing_key()
                .default_address(UnifiedAddressRequest::AllAvailableKeys)
                .unwrap();

            let exported = export_unified_key(&network, &keystore, &ua)
                .await
                .expect("export must succeed")
                .0;

            assert_eq!(exported, encode_unified_spending_key(&usk));
            assert_ne!(exported, encode_orchard_spending_key(&orchard_sk));
        });
    }

    /// A failure injected after both writes of the import transaction must roll back both:
    /// the wallet must not track an account whose key is missing, and the keystore must
    /// not hold a key for an account the wallet doesn't scan.
    #[test]
    fn standalone_key_import_transaction_rolls_back_on_failure() {
        #[derive(Debug)]
        enum AtomicityError {
            #[allow(dead_code)]
            Database(zcash_client_sqlite::error::SqliteClientError),
            Injected,
        }

        impl From<rusqlite::Error> for AtomicityError {
            fn from(e: rusqlite::Error) -> Self {
                AtomicityError::Database(e.into())
            }
        }

        let datadir = tempdir().unwrap();

        run_async(|| async {
            let keystore = test_keystore(&datadir).await;
            let sk = orchard_spending_key();
            let encrypted = EncryptedStandaloneKey::Orchard(
                keystore.encrypt_standalone_orchard_key(&sk).await.unwrap(),
            );
            let ufvk =
                UnifiedFullViewingKey::from_orchard_fvk(OrchardFullViewingKey::from(&sk)).unwrap();
            let birthday = AccountBirthday::from_parts(
                ChainState::empty(BlockHeight::from_u32(0), BlockHash([0u8; 32])),
                None,
            );

            // Mirror the `z_importkey` transaction: a wallet account import paired with the
            // keystore write, with an injected failure after both writes.
            let handle = keystore.db.handle().await.unwrap();
            let res: Result<(), AtomicityError> = handle.with_mut(|mut db_data| {
                db_data.transactionally_with_extension(|wdb, ext| {
                    wdb.import_account_ufvk(
                        "atomicity test",
                        &ufvk,
                        &birthday,
                        AccountPurpose::Spending { derivation: None },
                        None,
                    )
                    .map_err(AtomicityError::Database)?;
                    encrypted.insert(ext)?;
                    Err(AtomicityError::Injected)
                })
            });
            assert!(
                matches!(res, Err(AtomicityError::Injected)),
                "the injected failure must surface, not a database error: {res:?}"
            );

            // Neither write persisted: no account for the UFVK...
            let account = handle.with(|db_data| db_data.get_account_for_ufvk(&ufvk).unwrap());
            assert!(
                account.is_none(),
                "a rolled-back account import must not leave an account behind"
            );

            // ... and no keystore row.
            let stored: u32 = keystore
                .with_db(|conn, _| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM ext_zallet_keystore_standalone_orchard_keys",
                        [],
                        |row| row.get::<_, u32>(0),
                    )
                    .map_err(|e| ErrorKind::Generic.context(e).into())
                })
                .await
                .unwrap();
            assert_eq!(
                stored, 0,
                "a rolled-back keystore write must not leave a row behind"
            );
        });
    }
}
