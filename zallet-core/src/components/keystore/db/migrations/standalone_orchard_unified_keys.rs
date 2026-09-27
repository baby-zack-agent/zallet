use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;
use zcash_client_sqlite::wallet::init::WalletMigrationError;

use super::initial_setup;
use crate::components::keystore::db::{
    TABLE_STANDALONE_ORCHARD_KEYS, TABLE_STANDALONE_UNIFIED_KEYS,
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x841cb5a5_8371_44f5_98f1_11b35d769368);

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        [initial_setup::MIGRATION_ID].into_iter().collect()
    }

    fn description(&self) -> &'static str {
        "Adds keystore tables for standalone Orchard and unified spending keys."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        transaction.execute_batch(TABLE_STANDALONE_ORCHARD_KEYS)?;
        transaction.execute_batch(TABLE_STANDALONE_UNIFIED_KEYS)?;
        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction<'_>) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP TABLE ext_zallet_keystore_standalone_unified_keys;
             DROP TABLE ext_zallet_keystore_standalone_orchard_keys;",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;
    use schemerz_rusqlite::RusqliteMigration;

    use super::Migration;

    fn tables(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
            .unwrap();
        let names = stmt.query_map([], |row| row.get(0)).unwrap();
        names.collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn the_key_tables_are_created_and_removed_again() {
        let mut conn = Connection::open_in_memory().unwrap();

        let tx = conn.transaction().unwrap();
        Migration.up(&tx).unwrap();
        tx.commit().unwrap();
        let table_names = tables(&conn);
        assert!(table_names.contains(&"ext_zallet_keystore_standalone_orchard_keys".to_string()));
        assert!(table_names.contains(&"ext_zallet_keystore_standalone_unified_keys".to_string()));

        // A stored row must survive only while the migration is applied: reverting drops the
        // tables and their contents.
        conn.execute(
            "INSERT INTO ext_zallet_keystore_standalone_orchard_keys VALUES (:fvk, :sk)",
            rusqlite::named_params! {":fvk": vec![7u8; 96], ":sk": vec![1u8, 2, 3]},
        )
        .unwrap();

        let tx = conn.transaction().unwrap();
        Migration.down(&tx).unwrap();
        tx.commit().unwrap();
        let table_names = tables(&conn);
        assert!(!table_names.contains(&"ext_zallet_keystore_standalone_orchard_keys".to_string()));
        assert!(!table_names.contains(&"ext_zallet_keystore_standalone_unified_keys".to_string()));
    }
}
