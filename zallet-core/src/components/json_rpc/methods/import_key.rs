use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_client_backend::data_api::{AccountPurpose, WalletRead, WalletWrite};
use zcash_client_sqlite::error::SqliteClientError;
use zcash_keys::{
    encoding::{decode_extended_spending_key, encode_payment_address},
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::consensus::{BlockHeight, NetworkConstants, Parameters};

use crate::components::{
    chain::Chain,
    database::DbConnection,
    json_rpc::{server::LegacyCode, utils::fetch_account_birthday},
    keystore::{
        EncryptedStandaloneKey, KeyStore, decode_orchard_spending_key, decode_unified_spending_key,
    },
    sync::WalletDecryptorHandle,
};

/// Response to a `z_importkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// Result of importing a spending key.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
pub(crate) struct ResultType {
    /// The type of the imported key: "sapling", "orchard", or "unified".
    address_type: String,

    /// The address corresponding to the imported key: a Sapling payment address for a
    /// Sapling key, or a unified address for an Orchard or unified spending key.
    address: String,
}

pub(super) const PARAM_KEY_DESC: &str = "The spending key to import: a Sapling extended spending key, a raw Orchard spending key \
     (64 hex characters), or a unified spending key (versioned hex; see `z_exportkey`).";
pub(super) const PARAM_RESCAN_DESC: &str = "Whether to rescan the blockchain for transactions (\"yes\", \"no\", or \"whenkeyisnew\"; default is \"whenkeyisnew\"). When rescan is enabled, the wallet's background sync engine will scan for historical transactions from the given start height.";
pub(super) const PARAM_START_HEIGHT_DESC: &str = "Block height from which to begin the rescan (default is 0). Only used when rescan is \"yes\" or \"whenkeyisnew\" (for a new key).";

/// A spending key decoded from the `key` parameter of `z_importkey`.
enum DecodedSpendingKey {
    /// A Sapling extended spending key, in the network's Bech32 spending-key encoding.
    Sapling(sapling::zip32::ExtendedSpendingKey),

    /// A raw Orchard spending key, as 64 lowercase hex characters.
    Orchard(orchard::keys::SpendingKey),

    /// A unified spending key, in the versioned hex encoding produced by `z_exportkey`.
    Unified(UnifiedSpendingKey),
}

/// Returns the default unified address of the given UFVK as a string.
fn default_unified_address<P: Parameters>(
    params: &P,
    ufvk: &UnifiedFullViewingKey,
) -> RpcResult<String> {
    let (address, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| LegacyCode::Wallet.with_message(format!("Invalid spending key: {e}")))?;
    Ok(address.encode(params))
}

/// Decodes the `key` parameter of `z_importkey`, which accepts three formats:
///
/// - a Sapling extended spending key (Bech32 with the network's spending-key HRP);
/// - a raw Orchard spending key (exactly 64 hex characters);
/// - a unified spending key (the versioned hex encoding produced by `z_exportkey`).
///
/// Sapling is tried first: the hex formats can never parse as Bech32 with the Sapling
/// spending-key HRP, so a Sapling key is never misclassified. The Orchard and unified
/// formats are disjoint by length: a raw Orchard key is exactly 32 bytes, while the
/// versioned unified encoding is always longer.
///
/// Returns the decoded key and the address string to report for the imported key.
fn decode_key_and_address<P: Parameters>(
    params: &P,
    key: &str,
) -> RpcResult<(DecodedSpendingKey, String)> {
    if let Ok(extsk) = decode_extended_spending_key(params.hrp_sapling_extended_spending_key(), key)
    {
        let (_, payment_address) = extsk.default_address();
        let address =
            encode_payment_address(params.hrp_sapling_payment_address(), &payment_address);
        return Ok((DecodedSpendingKey::Sapling(extsk), address));
    }

    if let Ok(spending_key) = decode_orchard_spending_key(key) {
        let ufvk = UnifiedFullViewingKey::from_orchard_fvk(orchard::keys::FullViewingKey::from(
            &spending_key,
        ))
        .map_err(|e| {
            LegacyCode::Wallet.with_message(format!("Invalid Orchard spending key: {e}"))
        })?;
        let address = default_unified_address(params, &ufvk)?;
        return Ok((DecodedSpendingKey::Orchard(spending_key), address));
    }

    let usk = decode_unified_spending_key(key)
        .map_err(|e| LegacyCode::InvalidAddressOrKey.with_message(e.to_string()))?;
    let ufvk = usk.to_unified_full_viewing_key();
    let address = default_unified_address(params, &ufvk)?;
    Ok((DecodedSpendingKey::Unified(usk), address))
}

/// Error from the atomic import transaction, tracking which store failed so each failure keeps
/// its distinct RPC error code: wallet-database problems map to `Database`, and a failure to
/// persist the encrypted spending key maps to `Wallet`.
enum ImportError {
    Database(SqliteClientError),
    Keystore(rusqlite::Error),
}

impl From<rusqlite::Error> for ImportError {
    fn from(e: rusqlite::Error) -> Self {
        // `transactionally_with_extension` surfaces begin/commit failures as `rusqlite::Error`;
        // treat those as wallet-database failures.
        ImportError::Database(e.into())
    }
}

pub(crate) async fn call<C: Chain>(
    wallet: &mut DbConnection,
    keystore: &KeyStore,
    chain: C,
    decryptor: &WalletDecryptorHandle,
    key: &str,
    rescan: Option<&str>,
    start_height: Option<u64>,
) -> Response {
    let rescan = validate_rescan(rescan)?;

    // Resolve and validate start_height, defaulting to 0 (genesis).
    let start_height = BlockHeight::from_u32(
        u32::try_from(start_height.unwrap_or(0))
            .map_err(|_| LegacyCode::InvalidParameter.with_static("Block height out of range."))?,
    );

    let chain_tip = wallet
        .chain_height()
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?;

    // `start_height` is only used as the rescan start when rescanning; for rescan="no"
    // it is ignored entirely, so there is no point validating it against the chain tip.
    if rescan != "no"
        && let Some(tip) = chain_tip
        && start_height > tip
    {
        return Err(LegacyCode::InvalidParameter.with_static("Block height out of range."));
    }

    let (decoded_key, address) = decode_key_and_address(wallet.params(), key)?;

    // Normalize the three key kinds: derive the UFVK the wallet tracks, the account name,
    // the reported address type, and the encrypted key. Encryption is the only step needing
    // the keystore encryptor (unavailable while the wallet is locked) and is async, so it
    // happens before and outside the wallet transaction; the ciphertext is persisted
    // inside it below.
    let (ufvk, account_name, address_type, encrypted_key) = match decoded_key {
        DecodedSpendingKey::Sapling(extsk) => {
            let encrypted_key = keystore
                .encrypt_standalone_sapling_key(&extsk)
                .await
                .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            // Derive the UFVK from the spending key so the wallet can track its addresses.
            #[allow(deprecated)]
            let extfvk = extsk.to_extended_full_viewing_key();
            let ufvk = UnifiedFullViewingKey::from_sapling_extended_full_viewing_key(extfvk)
                .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            (
                ufvk,
                format!("Imported Sapling key {}", &address[..16]),
                "sapling",
                EncryptedStandaloneKey::Sapling(Box::new(encrypted_key)),
            )
        }
        DecodedSpendingKey::Orchard(spending_key) => {
            let encrypted_key = keystore
                .encrypt_standalone_orchard_key(&spending_key)
                .await
                .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            let ufvk = UnifiedFullViewingKey::from_orchard_fvk(
                orchard::keys::FullViewingKey::from(&spending_key),
            )
            .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            (
                ufvk,
                format!("Imported Orchard key {}", &address[..16]),
                "orchard",
                EncryptedStandaloneKey::Orchard(encrypted_key),
            )
        }
        DecodedSpendingKey::Unified(usk) => {
            let encrypted_key = keystore
                .encrypt_standalone_unified_key(wallet.params(), &usk)
                .await
                .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?;

            let ufvk = usk.to_unified_full_viewing_key();

            (
                ufvk,
                format!("Imported unified key {}", &address[..16]),
                "unified",
                EncryptedStandaloneKey::Unified(encrypted_key),
            )
        }
    };

    // Check if the key is already known to the wallet.
    let is_new_key = wallet
        .get_account_for_ufvk(&ufvk)
        .map_err(|e| LegacyCode::Database.with_message(e.to_string()))?
        .is_none();

    // For a new key, resolve its birthday before opening the transaction, since the birthday
    // fetch is async and may query the chain.
    let birthday = if is_new_key {
        // Determine the birthday height based on the rescan parameter:
        // - "yes" or "whenkeyisnew" → use start_height so the sync engine scans
        //   historical blocks from that point.
        // - "no" → use the current chain tip so the sync engine only tracks new
        //   transactions going forward.
        //
        // TODO: When rescan is "yes" and the key already exists, zcashd would force a
        // rescan from start_height. `WalletWrite::rewind_to_height` could now drive this,
        // but it rewinds the *entire* wallet (every account) rather than just this key, so
        // we defer wiring it up until that global side effect is the desired behaviour.
        let effective_height = match rescan {
            "yes" | "whenkeyisnew" => start_height,
            "no" => chain_tip.unwrap_or_else(|| {
                tracing::warn!(
                    "z_importkey with rescan=\"no\" but no chain tip is known yet; \
                     using genesis (height 0) as the imported key's birthday"
                );
                BlockHeight::from_u32(0)
            }),
            _ => unreachable!(),
        };

        let chain_view = chain.snapshot().await.map_err(|e| {
            LegacyCode::Database.with_message(format!("Failed to obtain a chain snapshot: {e}"))
        })?;
        Some(fetch_account_birthday(&chain_view, effective_height, None).await?)
    } else {
        None
    };

    // Import the account (for a new key) and store its encrypted spending key in a single
    // wallet-database transaction: the account and its key commit together or not at all, so
    // the wallet can never track an account whose key is missing, nor hold a key for an
    // account it doesn't scan.
    wallet
        .with_mut(|mut db_data| {
            db_data.transactionally_with_extension(|wdb, ext| -> Result<(), ImportError> {
                if let Some(birthday) = &birthday {
                    // Re-check existence inside the transaction: a concurrent import of the same
                    // new key may have created the account since the outer check. If so, skip the
                    // import and just (re)store the key — the same idempotent result as a
                    // re-import.
                    if wdb
                        .get_account_for_ufvk(&ufvk)
                        .map_err(ImportError::Database)?
                        .is_none()
                    {
                        wdb.import_account_ufvk(
                            &account_name,
                            &ufvk,
                            birthday,
                            AccountPurpose::Spending { derivation: None },
                            None,
                        )
                        .map_err(ImportError::Database)?;
                    }
                }
                encrypted_key.insert(ext).map_err(ImportError::Keystore)?;
                Ok(())
            })
        })
        .map_err(|e| match e {
            ImportError::Database(e) => LegacyCode::Database.with_message(e.to_string()),
            ImportError::Keystore(e) => LegacyCode::Wallet.with_message(e.to_string()),
        })?;

    // Reload viewing keys so the key is scanned without a restart. Run this unconditionally:
    // a re-import must be able to repair an account the sync engine never loaded. Don't wait
    // for the reload to be processed; the marker is queued behind any blocks already in the
    // decryptor, so awaiting it could block this call for a long time during sync.
    if decryptor.reload_keys().await.is_none() {
        tracing::warn!("sync engine has shut down; imported key won't be scanned until restart");
    }

    Ok(ResultType {
        address_type: address_type.to_string(),
        address,
    })
}

/// Validates the `rescan` parameter.
///
/// Returns the validated rescan value, or an RPC error if the value is invalid.
fn validate_rescan(rescan: Option<&str>) -> RpcResult<&str> {
    match rescan {
        None | Some("whenkeyisnew") => Ok("whenkeyisnew"),
        Some("yes") => Ok("yes"),
        Some("no") => Ok("no"),
        Some(_) => Err(LegacyCode::InvalidParameter
            .with_static("Invalid rescan value. Must be \"yes\", \"no\", or \"whenkeyisnew\".")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_keys::encoding::encode_extended_spending_key;
    use zcash_keys::keys::Era;
    use zcash_protocol::constants;

    // Test vector: ExtendedSpendingKey derived from master key with seed [0; 32].
    // From zcash_keys::encoding tests.
    const MAINNET_ENCODED_EXTSK: &str = "secret-extended-key-main1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjs87qvlj";
    const TESTNET_ENCODED_EXTSK: &str = "secret-extended-key-test1qqqqqqqqqqqqqq8n3zjjmvhhr854uy3qhpda3ml34haf0x388z5r7h4st4kpsf6qysqws3xh6qmha7gna72fs2n4clnc9zgyd22s658f65pex4exe56qjk5pqj9vfdq7dfdhjc2rs9jdwq0zl99uwycyrxzp86705rk687spn44e2uhm7h0hsagfvkk4n7n6nfer6u57v9cac84t7nl2zth0xpyfeg0w2p2wv2yn6jn923aaz0vdaml07l60ahapk6efchyxwysrvjsvzyw8j";

    fn mainnet() -> zcash_protocol::consensus::Network {
        zcash_protocol::consensus::Network::MainNetwork
    }

    fn testnet() -> zcash_protocol::consensus::Network {
        zcash_protocol::consensus::Network::TestNetwork
    }

    // A deterministic Orchard spending key (the scalar 7) for format tests.
    fn orchard_spending_key() -> orchard::keys::SpendingKey {
        let mut bytes = [0u8; 32];
        bytes[0] = 7;
        Option::from(orchard::keys::SpendingKey::from_bytes(bytes))
            .expect("the scalar 7 is a valid Orchard spending key")
    }

    // A deterministic unified spending key (Sapling + Orchard components) for format tests.
    fn unified_spending_key() -> UnifiedSpendingKey {
        UnifiedSpendingKey::from_seed(&mainnet(), &[7u8; 64], zip32::AccountId::ZERO)
            .expect("any 64-byte seed yields a unified spending key")
    }

    // -- validate_rescan tests --

    #[test]
    fn rescan_none_defaults_to_whenkeyisnew() {
        assert_eq!(validate_rescan(None).unwrap(), "whenkeyisnew");
    }

    #[test]
    fn rescan_whenkeyisnew() {
        assert_eq!(
            validate_rescan(Some("whenkeyisnew")).unwrap(),
            "whenkeyisnew"
        );
    }

    #[test]
    fn rescan_yes() {
        assert_eq!(validate_rescan(Some("yes")).unwrap(), "yes");
    }

    #[test]
    fn rescan_no() {
        assert_eq!(validate_rescan(Some("no")).unwrap(), "no");
    }

    #[test]
    fn rescan_invalid_value() {
        assert!(validate_rescan(Some("always")).is_err());
        assert!(validate_rescan(Some("")).is_err());
        assert!(validate_rescan(Some("true")).is_err());
    }

    // -- decode_key_and_address tests --

    #[test]
    fn decode_valid_mainnet_sapling_key() {
        let (key, address) = decode_key_and_address(&mainnet(), MAINNET_ENCODED_EXTSK).unwrap();

        assert!(matches!(key, DecodedSpendingKey::Sapling(_)));
        // The address should be a valid Sapling address starting with "zs1".
        assert!(address.starts_with("zs1"));
    }

    #[test]
    fn decode_valid_testnet_sapling_key() {
        let (key, address) = decode_key_and_address(&testnet(), TESTNET_ENCODED_EXTSK).unwrap();

        assert!(matches!(key, DecodedSpendingKey::Sapling(_)));
        // Testnet Sapling addresses start with "ztestsapling1".
        assert!(address.starts_with("ztestsapling1"));
    }

    #[test]
    fn decode_same_key_produces_same_address_across_calls() {
        let (_, addr1) = decode_key_and_address(&mainnet(), MAINNET_ENCODED_EXTSK).unwrap();
        let (_, addr2) = decode_key_and_address(&mainnet(), MAINNET_ENCODED_EXTSK).unwrap();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn decode_sapling_roundtrip() {
        let (key, _) = decode_key_and_address(&mainnet(), MAINNET_ENCODED_EXTSK).unwrap();
        let DecodedSpendingKey::Sapling(extsk) = key else {
            panic!("expected a Sapling key");
        };

        let re_encoded = encode_extended_spending_key(
            constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
            &extsk,
        );
        assert_eq!(re_encoded, MAINNET_ENCODED_EXTSK);
    }

    #[test]
    fn decode_invalid_key() {
        assert!(decode_key_and_address(&mainnet(), "not-a-valid-key").is_err());
    }

    #[test]
    fn decode_wrong_network_sapling_key() {
        // A testnet key with mainnet parameters must fail: the Bech32 HRP does not match,
        // and the string is not valid hex either.
        assert!(decode_key_and_address(&mainnet(), TESTNET_ENCODED_EXTSK).is_err());
    }

    #[test]
    fn decode_empty_key() {
        assert!(decode_key_and_address(&mainnet(), "").is_err());
    }

    #[test]
    fn decode_orchard_key() {
        use crate::components::keystore::encode_orchard_spending_key;

        let sk = orchard_spending_key();
        let encoded = encode_orchard_spending_key(&sk);
        assert_eq!(encoded.len(), 64);

        let (key, address) = decode_key_and_address(&mainnet(), &encoded).unwrap();
        let DecodedSpendingKey::Orchard(decoded) = key else {
            panic!("expected an Orchard key");
        };
        assert_eq!(decoded.to_bytes(), sk.to_bytes());

        // The reported address is a unified address carrying the key's Orchard receiver.
        let parsed = zcash_keys::address::Address::decode(&mainnet(), &address)
            .expect("the reported address must parse");
        assert!(matches!(parsed, zcash_keys::address::Address::Unified(_)));
    }

    #[test]
    fn decode_unified_key() {
        use crate::components::keystore::encode_unified_spending_key;

        let usk = unified_spending_key();
        let encoded = encode_unified_spending_key(&usk);

        let (key, address) = decode_key_and_address(&mainnet(), &encoded).unwrap();
        let DecodedSpendingKey::Unified(decoded) = key else {
            panic!("expected a unified key");
        };
        assert_eq!(
            decoded.to_unified_full_viewing_key().encode(&mainnet()),
            usk.to_unified_full_viewing_key().encode(&mainnet())
        );

        // The reported address is a unified address.
        let parsed = zcash_keys::address::Address::decode(&mainnet(), &address)
            .expect("the reported address must parse");
        assert!(matches!(parsed, zcash_keys::address::Address::Unified(_)));
    }

    #[test]
    fn decode_rejects_malformed_unified_key() {
        // A version byte this wallet does not know must not decode.
        let mut bad = vec![0x7fu8];
        bad.extend_from_slice(&unified_spending_key().to_bytes(Era::Orchard));
        assert!(decode_key_and_address(&mainnet(), &hex::encode(bad)).is_err());

        // Truncated payloads must not decode either.
        let encoded =
            crate::components::keystore::encode_unified_spending_key(&unified_spending_key());
        assert!(decode_key_and_address(&mainnet(), &encoded[..encoded.len() - 2]).is_err());
    }

    #[test]
    fn decode_rejects_wrong_length_orchard_key() {
        // 64 hex characters of the wrong length must not decode as an Orchard key,
        // and are too short to be a versioned unified key.
        let wrong_length = "00".repeat(31);
        assert!(decode_key_and_address(&mainnet(), &wrong_length).is_err());
    }

    #[test]
    fn decode_formats_are_disjoint() {
        use crate::components::keystore::{
            encode_orchard_spending_key, encode_unified_spending_key,
        };

        // A Sapling key never decodes as Orchard or unified.
        let (key, _) = decode_key_and_address(&mainnet(), MAINNET_ENCODED_EXTSK).unwrap();
        assert!(matches!(key, DecodedSpendingKey::Sapling(_)));

        // A raw Orchard key (exactly 32 bytes) never decodes as unified.
        let orchard_encoded = encode_orchard_spending_key(&orchard_spending_key());
        let (key, _) = decode_key_and_address(&mainnet(), &orchard_encoded).unwrap();
        assert!(matches!(key, DecodedSpendingKey::Orchard(_)));

        // A versioned unified key never decodes as Orchard.
        let unified_encoded = encode_unified_spending_key(&unified_spending_key());
        let (key, _) = decode_key_and_address(&mainnet(), &unified_encoded).unwrap();
        assert!(matches!(key, DecodedSpendingKey::Unified(_)));
    }
}
