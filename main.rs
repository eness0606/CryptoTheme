use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::str::FromStr;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bip32::{XPrv, DerivationPath};
use hex::encode;
use keccak_hash::keccak;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use sqlx::{sqlite::SqlitePool};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use rayon::prelude::*;
use tokio::runtime::Runtime;

fn main() {
    let mut input = String::new();
    println!("Введите желаемое количество потоков(Минимум 2):");
    io::stdin().read_line(&mut input);
    let num_threads: usize = input.trim().parse().unwrap();
    input.clear();
    println!("Введите путь к базе данных:");
    io::stdin().read_line(&mut input);
    let db_path = input.trim().to_string();
    input.clear();
    println!("Введите путь к файлу log.txt:");
    io::stdin().read_line(&mut input);
    let log_path = input.trim().to_string();
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let pool = SqlitePool::connect(&format!("sqlite://{}", db_path))
            .await
            .unwrap();
        let counter = Arc::new(AtomicUsize::new(1));
        save_startup_message(&log_path).await;
        loop {
            let pool = pool.clone();
            let counter_clone = Arc::clone(&counter);
            let log_path_clone = log_path.clone();
            (0..num_threads).into_par_iter().for_each(|_| {
                let pool = pool.clone();
                let counter_thread = Arc::clone(&counter_clone);
                let log_path_thread = log_path_clone.clone();
                rt.block_on(async {
                    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
                    let seed = Seed::new(&mnemonic, "");
                    let (address, private_key) = get_eth_address(seed.as_bytes());
                    let current_count = counter_thread.fetch_add(1, Ordering::SeqCst);
                    println!("{}: Ethereum Address: {}", current_count, address);
                    if check_address_in_db(&pool, &address).await {
                        save_to_file(&log_path_thread, &mnemonic.phrase(), &address, &private_key).await;
                    }
                });
            });
        }
    });
}
async fn save_startup_message(log_path: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)
        .await
        .unwrap();
    file.write_all(b"The correct path\n").await.unwrap();
}
async fn check_address_in_db(pool: &SqlitePool, address: &str) -> bool {
    let row = sqlx::query("SELECT 1 FROM addresses WHERE address = ?")
        .bind(address)
        .fetch_optional(pool)
        .await
        .unwrap();
    row.is_some()
}
async fn save_to_file(log_path: &str, phrase: &str, address: &str, private_key: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)
        .await
        .unwrap();
    file.write_all(format!("Mnemonic phrase: {}\n", phrase).as_bytes())
        .await
        .unwrap();
    file.write_all(format!("Ethereum Address: {}\n", address).as_bytes())
        .await
        .unwrap();
    file.write_all(format!("Private Key: {}\n", private_key).as_bytes())
        .await
        .unwrap();
    file.write_all(b"-----------------------------\n")
        .await
        .unwrap();
}
fn get_eth_address(seed: &[u8]) -> (String, String) {
    let xprv = XPrv::new(seed).unwrap();
    let derivation_path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
    let mut child_xprv = xprv;
    for index in derivation_path.into_iter() {
        child_xprv = child_xprv.derive_child(index).unwrap();
    }
    let private_key_bytes = child_xprv.private_key().to_bytes();
    let private_key = SecretKey::from_slice(&private_key_bytes).unwrap();
    let secp = Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &private_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    let address = keccak(&public_key_bytes[1..]).0;
    let address_hex = to_checksum_address(&address[12..]);
    let private_key_hex = format!("0x{}", encode(private_key.secret_bytes()));
    (address_hex, private_key_hex)
}
fn to_checksum_address(address: &[u8]) -> String {
    let address_hex = encode(address);
    let address_lower = address_hex.to_lowercase();
    let hash = encode(keccak(address_lower.as_bytes()).0);
    let mut checksum_address = String::from("0x");
    for (i, c) in address_hex.chars().enumerate() {
        if hash.chars().nth(i).unwrap() >= '8' {
            checksum_address.push(c.to_ascii_uppercase());
        } else {
            checksum_address.push(c);
        }
    }
    checksum_address
}
