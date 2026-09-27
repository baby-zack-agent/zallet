use documented::Documented;
use jsonrpsee::core::RpcResult;
use schemars::JsonSchema;
use serde::Serialize;
use zcash_keys::{
    address::{Address, UnifiedAddress},
    encoding::encode_extended_spending_key,
};
use zcash_protocol::consensus::NetworkConstants;

use crate::{
    components::{
        database::DbConnection,
        json_rpc::{server::LegacyCode, utils::ensure_wallet_is_unlocked},
        keystore::{
            KeyStore, encode_orchard_spending_key, encode_unified_spending_key,
            unified_spending_key_matches_address,
        },
    },
    network::Network,
};

/// Response to a `z_exportkey` RPC request.
pub(crate) type Response = RpcResult<ResultType>;

/// The exported spending key.
///
/// - A Sapling payment address yields the Sapling extended spending key, as a Bech32 string.
/// - A unified address yields a unified spending key if the wallet holds one for it (the
///   versioned hex encoding `z_importkey` accepts), otherwise the raw Orchard spending key
///   (64 hex characters) if the wallet holds a standalone Orchard key for its Orchard
///   receiver, otherwise the Sapling extended spending key if it holds a standalone Sapling
///   key for its Sapling receiver.
#[derive(Clone, Debug, Serialize, Documented, JsonSchema)]
#[serde(transparent)]
pub(crate) struct ResultType(pub(crate) String);

pub(super) const PARAM_ADDRESS_DESC: &str =
    "The Sapling payment address or unified address corresponding to the spending key to export.";

/// Exports the standalone Sapling spending key for a Sapling payment address.
async fn export_sapling_key(
    params: &Network,
    keystore: &KeyStore,
    payment_address: &sapling::PaymentAddress,
) -> Response {
    let extsk = keystore
        .decrypt_standalone_sapling_key(payment_address)
        .await
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?
        .ok_or_else(|| {
            LegacyCode::InvalidAddressOrKey
                .with_static("Wallet does not hold the spending key for this Sapling address")
        })?;

    let encoded = encode_extended_spending_key(params.hrp_sapling_extended_spending_key(), &extsk);

    Ok(ResultType(encoded))
}

/// Exports the most complete spending key the wallet holds for a unified address.
///
/// A unified spending key covers every receiver in the address and is returned first; a
/// standalone Orchard key covers only the Orchard receiver and comes next; a standalone
/// Sapling key covers only the Sapling receiver and is last. This ordering means the
/// exported key always authorizes at least the receivers the wallet holds keys for, and
/// prefers the key with the widest authority.
pub(crate) async fn export_unified_key(
    params: &Network,
    keystore: &KeyStore,
    address: &UnifiedAddress,
) -> Response {
    if let Some(usk) = keystore
        .decrypt_standalone_unified_key(address)
        .await
        .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?
    {
        debug_assert!(unified_spending_key_matches_address(&usk, address));
        return Ok(ResultType(encode_unified_spending_key(&usk)));
    }

    if let Some(orchard_receiver) = address.orchard()
        && let Some(spending_key) = keystore
            .decrypt_standalone_orchard_key(orchard_receiver)
            .await
            .map_err(|e| LegacyCode::Wallet.with_message(e.to_string()))?
    {
        return Ok(ResultType(encode_orchard_spending_key(&spending_key)));
    }

    if let Some(sapling_receiver) = address.sapling() {
        return export_sapling_key(params, keystore, sapling_receiver).await;
    }

    Err(LegacyCode::InvalidAddressOrKey
        .with_static("Wallet does not hold a spending key for this unified address"))
}

pub(crate) async fn call(wallet: &DbConnection, keystore: &KeyStore, address: &str) -> Response {
    ensure_wallet_is_unlocked(keystore).await?;

    let address = Address::decode(wallet.params(), address)
        .ok_or_else(|| LegacyCode::InvalidAddressOrKey.with_static("Invalid address"))?;

    match address {
        Address::Sapling(payment_address) => {
            export_sapling_key(wallet.params(), keystore, &payment_address).await
        }
        Address::Unified(unified_address) => {
            export_unified_key(wallet.params(), keystore, &unified_address).await
        }
        Address::Transparent(_) | Address::Tex(_) => Err(LegacyCode::InvalidAddressOrKey
            .with_static("Only Sapling and unified addresses are supported")),
    }
}

#[cfg(test)]
mod tests {
    use zcash_keys::encoding::{decode_payment_address, encode_payment_address};
    use zcash_protocol::constants;

    #[test]
    fn decode_valid_mainnet_sapling_address() {
        // From zcash_keys::encoding tests — address derived from seed [0; 32].
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z",
        );
        assert!(addr.is_ok());
    }

    #[test]
    fn decode_valid_testnet_sapling_address() {
        let addr = decode_payment_address(
            constants::testnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
        );
        assert!(addr.is_ok());
    }

    #[test]
    fn decode_invalid_address() {
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "not-a-valid-address",
        );
        assert!(addr.is_err());
    }

    #[test]
    fn decode_wrong_network_address() {
        // Testnet address decoded with mainnet HRP should fail.
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "ztestsapling1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75ss7jnk",
        );
        assert!(addr.is_err());
    }

    #[test]
    fn address_encode_decode_roundtrip() {
        let addr = decode_payment_address(
            constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z",
        )
        .unwrap();

        let re_encoded =
            encode_payment_address(constants::mainnet::HRP_SAPLING_PAYMENT_ADDRESS, &addr);
        assert_eq!(
            re_encoded,
            "zs1qqqqqqqqqqqqqqqqqqcguyvaw2vjk4sdyeg0lc970u659lvhqq7t0np6hlup5lusxle75c8v35z"
        );
    }
}
