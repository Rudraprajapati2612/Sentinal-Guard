use anyhow::{Context, Result};
use futures::StreamExt;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use yellowstone_grpc_client::GeyserGrpcClient;
use yellowstone_grpc_proto::prelude::{
    subscribe_update::UpdateOneof, SubscribeRequest, SubscribeRequestAccountsDataSlice,
    SubscribeRequestFilterTransactions,
};

use crate::config::Config;
use crate::types::{ParsedTransaction, TokenDelta, TvlCache};

// Known flash loan program IDs on Solana mainnet
const FLASH_LOAN_PROGRAMS: &[&str] = &[
    "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo", // Solend
    "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD", // Marginfi
    "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", // Orca Whirlpool (flash)
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", // Jupiter (flash swap)
];

// Known bridge program IDs
const BRIDGE_PROGRAMS: &[&str] = &[
    "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth", // Wormhole core
    "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5", // Wormhole token bridge
    "LayerZeroEndpointV2",                         // LayerZero (placeholder)
];

// USDC mint
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

pub async fn run(
    cfg: Config,
    tx_sender: broadcast::Sender<ParsedTransaction>,
    redis: ConnectionManager,
) -> Result<()> {
    info!("Connecting to Geyser at {}", cfg.geyser_endpoint);

    // Build Yellowstone gRPC client with TLS + auth token
    let mut client = GeyserGrpcClient::build_from_shared(cfg.geyser_endpoint.clone())?
        .x_token(Some(cfg.helius_api_key.clone()))?
        .connect()
        .await
        .with_context(|| format!("Failed to connect to Geyser at {}", cfg.geyser_endpoint))?;

    info!("Geyser connected ✓");

    // Build transaction filter — only subscribe to txs touching our watched programs
    let tx_filter = cfg
        .watched_programs
        .iter()
        .enumerate()
        .map(|(i, program_id)| {
            (
                format!("filter_{}", i),
                SubscribeRequestFilterTransactions {
                    vote: Some(false),   // skip vote transactions
                    failed: Some(false), // skip failed transactions
                    account_include: vec![program_id.clone()],
                    account_exclude: vec![],
                    account_required: vec![],
                    signature: None,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    let subscribe_request = SubscribeRequest {
        transactions: tx_filter,
        // We don't need account updates or slot updates here
        accounts: HashMap::new(),
        slots: HashMap::new(),
        transactions_status: HashMap::new(),
        blocks: HashMap::new(),
        blocks_meta: HashMap::new(),
        entry: HashMap::new(),
        commitment: Some(0), // 0 = Processed (fastest, not yet confirmed)
        accounts_data_slice: vec![],
        ping: None,
        from_slot: None,
    };

    let (mut _subscribe_tx, mut stream) = client
        .subscribe_with_request(Some(subscribe_request))
        .await
        .context("Failed to start Geyser subscription")?;

    info!(
        "Geyser subscription active — watching {} programs",
        cfg.watched_programs.len()
    );
    for p in &cfg.watched_programs {
        info!("  → {}", p);
    }

    let mut redis = redis;
    let mut processed: u64 = 0;
    let mut errors: u64 = 0;

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(update) => {
                let Some(update_oneof) = update.update_oneof else {
                    continue;
                };

                match update_oneof {
                    UpdateOneof::Transaction(tx_update) => {
                        match parse_geyser_transaction(tx_update) {
                            Ok(parsed) => {
                                processed += 1;

                                if processed % 1000 == 0 {
                                    debug!("Processed {} txs ({} errors)", processed, errors);
                                }

                                // Write TVL to Redis for fast detection engine reads
                                // Fire-and-forget — don't block the stream on Redis latency
                                let tvl_approx = approx_tvl_from_tx(&parsed);
                                if tvl_approx > 0.0 {
                                    let protocol = parsed
                                        .program_ids
                                        .iter()
                                        .find(|id| cfg.watched_programs.contains(id))
                                        .cloned();

                                    if let Some(protocol) = protocol {
                                        let cache = TvlCache {
                                            protocol: protocol.clone(),
                                            tvl_usd: tvl_approx,
                                            slot: parsed.slot,
                                            updated_at: parsed.timestamp,
                                        };
                                        let key = format!("tvl:{}", protocol);
                                        let val = serde_json::to_string(&cache).unwrap_or_default();
                                        // Non-blocking Redis SET with 30s TTL
                                        let mut r = redis.clone();
                                        tokio::spawn(async move {
                                            let _: Result<(), _> = redis::cmd("SET")
                                                .arg(&key)
                                                .arg(&val)
                                                .arg("EX")
                                                .arg(30u64)
                                                .query_async(&mut r)
                                                .await;
                                        });
                                    }
                                }

                                // Send to detection engine
                                // If all receivers have dropped, shut down
                                if tx_sender.receiver_count() == 0 {
                                    warn!(
                                        "No receivers on tx channel — stopping Geyser subscriber"
                                    );
                                    break;
                                }

                                if let Err(e) = tx_sender.send(parsed) {
                                    // Channel lagged — detection engine is too slow
                                    // This means the channel is full (broadcast drops old msgs)
                                    debug!("Tx channel send error (lagged?): {}", e);
                                }
                            }
                            Err(e) => {
                                errors += 1;
                                if errors % 100 == 0 {
                                    warn!("Parse errors: {} total — last: {}", errors, e);
                                }
                            }
                        }
                    }
                    UpdateOneof::Ping(_) => {
                        debug!("Geyser ping received");
                    }
                    _ => {} // ignore account updates, slot updates etc.
                }
            }
            Err(e) => {
                error!("Geyser stream error: {} — attempting to reconnect", e);
                // The outer retry loop in main.rs will restart this task
                return Err(anyhow::anyhow!("Geyser stream failed: {}", e));
            }
        }
    }

    warn!("Geyser stream ended unexpectedly");
    Ok(())
}

// ─── Transaction Parser ───────────────────────────────────────────────────────

fn parse_geyser_transaction(
    update: yellowstone_grpc_proto::prelude::SubscribeUpdateTransaction,
) -> Result<ParsedTransaction> {
    let tx_info = update
        .transaction
        .context("Missing transaction in update")?;

    let slot = update.slot;

    // Extract signature
    let signature = bs58::encode(&tx_info.signature).into_string();

    // Extract the inner transaction
    let tx = tx_info.transaction.context("Missing transaction data")?;

    let meta = tx_info.meta.context("Missing transaction meta")?;

    // Program IDs — from account keys
    let message = tx.message.context("Missing message")?;

    let account_keys: Vec<String> = message
        .account_keys
        .iter()
        .map(|k| bs58::encode(k).into_string())
        .collect();

    // Fee payer is always first account
    let fee_payer = account_keys.first().cloned().unwrap_or_default();

    // All program IDs = all account keys that are programs
    // In practice: parse instructions for program_id_index
    let program_ids: Vec<String> = message
        .instructions
        .iter()
        .filter_map(|ix| account_keys.get(ix.program_id_index as usize))
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // CPI depth = max nesting in inner_instructions
    let cpi_depth = meta
        .inner_instructions
        .iter()
        .map(|ii| ii.instructions.len() as u8)
        .max()
        .unwrap_or(0);

    // Token balance deltas
    let token_deltas = parse_token_deltas(&meta, &account_keys);

    // Log messages
    let log_messages = meta.log_messages.clone();

    // Flash loan detection:
    // 1. Program ID is a known flash loan program
    // 2. OR log messages contain "flash" keyword
    let is_flash_loan = program_ids
        .iter()
        .any(|id| FLASH_LOAN_PROGRAMS.contains(&id.as_str()))
        || log_messages.iter().any(|log| {
            let lower = log.to_lowercase();
            lower.contains("flash_loan")
                || lower.contains("flashloan")
                || lower.contains("flash loan")
        });

    Ok(ParsedTransaction {
        slot,
        signature,
        program_ids,
        token_deltas,
        cpi_depth,
        log_messages,
        is_flash_loan,
        fee_payer,
        timestamp: chrono::Utc::now().timestamp(), // block time not always in Geyser stream
    })
}

fn parse_token_deltas(
    meta: &yellowstone_grpc_proto::prelude::TransactionStatusMeta,
    account_keys: &[String],
) -> Vec<TokenDelta> {
    let mut deltas = Vec::new();

    // pre_token_balances and post_token_balances are parallel arrays
    // indexed by account_index
    let pre_map: HashMap<u32, &yellowstone_grpc_proto::prelude::TokenBalance> = meta
        .pre_token_balances
        .iter()
        .map(|b| (b.account_index, b))
        .collect();

    for post in &meta.post_token_balances {
        let account_idx = post.account_index;
        let account = account_keys
            .get(account_idx as usize)
            .cloned()
            .unwrap_or_default();

        let mint = post.mint.clone();

        let post_amount: u64 = post
            .ui_token_amount
            .as_ref()
            .and_then(|a| a.amount.parse::<u64>().ok())
            .unwrap_or(0);

        let pre_amount: u64 = pre_map
            .get(&account_idx)
            .and_then(|b| b.ui_token_amount.as_ref())
            .and_then(|a| a.amount.parse::<u64>().ok())
            .unwrap_or(0);

        let delta = post_amount as i64 - pre_amount as i64;

        // Only record non-zero deltas
        if delta != 0 {
            deltas.push(TokenDelta {
                account,
                mint,
                before: pre_amount,
                after: post_amount,
                delta,
            });
        }
    }

    deltas
}

/// Quick TVL approximation from a single transaction.
/// For USDC only — treats 1 USDC = 1 USD.
/// Phase 2: Replace with Pyth oracle price feeds.
fn approx_tvl_from_tx(tx: &ParsedTransaction) -> f64 {
    tx.token_deltas
        .iter()
        .filter(|d| d.mint == USDC_MINT && d.after > 0)
        .map(|d| d.after as f64 / 1_000_000.0) // USDC = 6 decimals
        .sum()
}
