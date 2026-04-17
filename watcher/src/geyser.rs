// watcher/src/geyser.rs
//
// Temporary subscriber implementation for environments without Yellowstone
// gRPC access. This uses Solana/Helius WebSocket log subscriptions plus
// per-signature JSON-RPC transaction fetches to reconstruct ParsedTransaction.

use anyhow::{Context, Result};
use futures::StreamExt;
use redis::aio::ConnectionManager;
use solana_client::{
    nonblocking::{pubsub_client::PubsubClient, rpc_client::RpcClient},
    rpc_config::{RpcTransactionConfig, RpcTransactionLogsConfig, RpcTransactionLogsFilter},
    rpc_response::RpcLogsResponse,
};
use solana_sdk::{commitment_config::CommitmentConfig, signature::Signature};
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, EncodedConfirmedTransactionWithStatusMeta,
    EncodedTransaction, UiInnerInstructions, UiInstruction, UiMessage, UiParsedInstruction,
    UiTransactionEncoding, UiTransactionStatusMeta,
};
use std::{
    collections::{HashMap, HashSet},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::types::{CpiMetrics, FlashLoanEvidence, ParsedTransaction, TokenDelta, TvlCache};

/// Known flash loan program IDs on Solana mainnet.
const FLASH_LOAN_PROGRAMS: &[(&str, &str)] = &[
    ("So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo", "Solend"),
    ("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD", "Marginfi"),
    ("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc", "Orca Whirlpool"),
    ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4", "Jupiter"),
];

/// Known bridge program IDs — used in engine.rs for bridge outflow detection.
pub const BRIDGE_PROGRAMS: &[&str] = &[
    "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
    "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5",
];

/// USDC mint address — only stablecoin we track for TVL right now.
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Minimum borrow amount to count as a flash loan in Method 3 (delta pattern).
const FLASH_LOAN_MIN_BORROW_RAW: u64 = 500_000_000;

#[derive(Debug)]
enum SubscriberEvent {
    Log(RpcLogsResponse),
    Error(anyhow::Error),
}

pub async fn run(
    cfg: Config,
    tx_sender: broadcast::Sender<ParsedTransaction>,
    redis: ConnectionManager,
) -> Result<()> {
    let ws_url = websocket_url(&cfg);
    let rpc_url = subscriber_rpc_url(&cfg);

    info!("Connecting to WebSocket at {}", ws_url);
    info!("Using RPC fetch endpoint {}", rpc_url);

    let pubsub = Arc::new(
        PubsubClient::new(&ws_url)
            .await
            .with_context(|| format!("Failed to connect to WebSocket at {}", ws_url))?,
    );
    let rpc = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<SubscriberEvent>();
    let mut join_set = JoinSet::new();

    for program_id in cfg.watched_programs.clone() {
        let pubsub = Arc::clone(&pubsub);
        let event_tx = event_tx.clone();

        join_set.spawn(async move {
            let filter = RpcTransactionLogsFilter::All;
            let config = RpcTransactionLogsConfig {
                commitment: Some(CommitmentConfig::processed()),
            };

            let (mut stream, unsubscribe) = match pubsub.logs_subscribe(filter, config).await {
                Ok(parts) => parts,
                Err(e) => {
                    let _ = event_tx.send(SubscriberEvent::Error(anyhow::anyhow!(
                        "WebSocket subscribe failed for {}: {}",
                        program_id,
                        e
                    )));
                    return;
                }
            };

            info!("WebSocket subscription active for {}", program_id);

            while let Some(resp) = stream.next().await {
                if resp.value.err.is_none() {
                    let _ = event_tx.send(SubscriberEvent::Log(resp.value));
                }
            }

            unsubscribe().await;
            let _ = event_tx.send(SubscriberEvent::Error(anyhow::anyhow!(
                "WebSocket stream ended for {}",
                program_id
            )));
        });
    }

    drop(event_tx);

    let mut redis = redis;
    let mut processed: u64 = 0;
    let mut errors: u64 = 0;
    let mut seen_signatures: HashMap<String, Instant> = HashMap::new();

    loop {
        tokio::select! {
            maybe_event = event_rx.recv() => {
                let Some(event) = maybe_event else {
                    return Err(anyhow::anyhow!("All WebSocket subscriptions ended unexpectedly"));
                };

                match event {
                    SubscriberEvent::Log(logs) => {
                        println!("TX received: {}", logs.signature);        
                        prune_seen_signatures(&mut seen_signatures);
                        if seen_signatures.contains_key(&logs.signature) {
                            continue;
                        }
                        seen_signatures.insert(logs.signature.clone(), Instant::now());

                        match fetch_transaction_via_rpc(&rpc, &logs).await {
                            Ok(parsed) => {
                                println!("Parsed Tx:{}",parsed.signature);
                                processed += 1;
                                
                                if processed % 100 == 0 {
                                    debug!("Processed {} txs ({} errors)", processed, errors);
                                }

                                write_tvl_to_redis(&parsed, &cfg, &mut redis);

                                if tx_sender.receiver_count() == 0 {
                                    warn!("No receivers on tx channel — stopping subscriber");
                                    break;
                                }

                                if let Err(e) = tx_sender.send(parsed) {
                                    debug!("Tx channel lagged: {}", e);
                                }
                            }
                            Err(e) => {
                                errors += 1;
                                if errors % 25 == 0 {
                                    warn!("Parse/fetch errors: {} total — last: {}", errors, e);
                                }
                            }
                        }
                    }
                    SubscriberEvent::Error(e) => {
                        error!("WebSocket subscriber error: {}", e);
                        return Err(e);
                    }
                }
            }
            maybe_joined = join_set.join_next(), if !join_set.is_empty() => {
                if let Some(Err(e)) = maybe_joined {
                    return Err(anyhow::anyhow!("WebSocket subscription task panicked: {}", e));
                }
            }
        }
    }

    warn!("WebSocket subscriber ended unexpectedly");
    Ok(())
}

fn prune_seen_signatures(seen_signatures: &mut HashMap<String, Instant>) {
    const KEEP_FOR: Duration = Duration::from_secs(90);
    let now = Instant::now();
    seen_signatures.retain(|_, inserted_at| now.duration_since(*inserted_at) < KEEP_FOR);
}

async fn fetch_transaction_via_rpc(
    rpc: &RpcClient,
    logs: &RpcLogsResponse,
) -> Result<ParsedTransaction> {
    let signature = Signature::from_str(&logs.signature)
        .with_context(|| format!("Invalid signature from WebSocket: {}", logs.signature))?;

    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::JsonParsed),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let mut last_error = None;
    for attempt in 0..6 {
        match rpc.get_transaction_with_config(&signature, config).await {
            Ok(tx) => return parse_rpc_transaction(tx, logs),
            Err(e) => {
                last_error = Some(e);
                tokio::time::sleep(Duration::from_millis(250 * (attempt + 1) as u64)).await;
            }
        }
    }

    Err(anyhow::anyhow!(
        "Failed to fetch transaction {} over RPC: {}",
        logs.signature,
        last_error
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown RPC error".to_string())
    ))
}

fn parse_rpc_transaction(
    tx: EncodedConfirmedTransactionWithStatusMeta,
    logs: &RpcLogsResponse,
) -> Result<ParsedTransaction> {
    let meta = tx
        .transaction
        .meta
        .as_ref()
        .context("Missing transaction meta from RPC response")?;

    let ui_tx = match &tx.transaction.transaction {
        EncodedTransaction::Json(ui_tx) => ui_tx,
        _ => return Err(anyhow::anyhow!("RPC response did not return JSON transaction data")),
    };

    let account_keys = extract_account_keys(&ui_tx.message);
    let fee_payer = account_keys.first().cloned().unwrap_or_default();

    let mut program_ids = extract_program_ids(&ui_tx.message, &account_keys);
    program_ids.extend(extract_inner_program_ids(meta, &account_keys));
    let program_ids: Vec<String> = program_ids.into_iter().collect();

    let token_deltas = parse_token_deltas(meta, &account_keys);
    let log_messages = extract_log_messages(meta).unwrap_or_else(|| logs.logs.clone());
    let cpi = compute_cpi_metrics(extract_inner_instructions(meta));
    let flash_evidence = detect_flash_loan(&program_ids, &log_messages, &token_deltas);
    let signature = ui_tx
        .signatures
        .first()
        .cloned()
        .unwrap_or_else(|| logs.signature.clone());

    Ok(ParsedTransaction {
        slot: tx.slot,
        signature,
        program_ids,
        token_deltas,
        cpi,
        log_messages,
        flash_evidence,
        fee_payer,
        timestamp: tx
            .block_time
            .unwrap_or_else(|| chrono::Utc::now().timestamp()),
    })
}

fn extract_account_keys(message: &UiMessage) -> Vec<String> {
    match message {
        UiMessage::Raw(raw) => raw.account_keys.clone(),
        UiMessage::Parsed(parsed) => parsed.account_keys.iter().map(|k| k.pubkey.clone()).collect(),
    }
}

fn extract_program_ids(message: &UiMessage, account_keys: &[String]) -> HashSet<String> {
    let mut program_ids = HashSet::new();

    match message {
        UiMessage::Raw(raw) => {
            for ix in &raw.instructions {
                if let Some(program_id) = account_keys.get(ix.program_id_index as usize) {
                    program_ids.insert(program_id.clone());
                }
            }
        }
        UiMessage::Parsed(parsed) => {
            for ix in &parsed.instructions {
                if let Some(program_id) = ui_instruction_program_id(ix, account_keys) {
                    program_ids.insert(program_id);
                }
            }
        }
    }

    program_ids
}

fn extract_inner_program_ids(meta: &UiTransactionStatusMeta, account_keys: &[String]) -> HashSet<String> {
    let mut program_ids = HashSet::new();

    for group in extract_inner_instructions(meta) {
        for ix in &group.instructions {
            if let Some(program_id) = ui_instruction_program_id(ix, account_keys) {
                program_ids.insert(program_id);
            }
        }
    }

    program_ids
}

fn ui_instruction_program_id(ix: &UiInstruction, account_keys: &[String]) -> Option<String> {
    match ix {
        UiInstruction::Compiled(ix) => account_keys.get(ix.program_id_index as usize).cloned(),
        UiInstruction::Parsed(UiParsedInstruction::Parsed(ix)) => Some(ix.program_id.clone()),
        UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ix)) => Some(ix.program_id.clone()),
    }
}

fn extract_inner_instructions(meta: &UiTransactionStatusMeta) -> &[UiInnerInstructions] {
    match meta.inner_instructions.as_ref() {
        OptionSerializer::Some(inner) => inner,
        _ => &[],
    }
}

fn extract_log_messages(meta: &UiTransactionStatusMeta) -> Option<Vec<String>> {
    match meta.log_messages.as_ref() {
        OptionSerializer::Some(logs) => Some(logs.clone()),
        _ => None,
    }
}

fn write_tvl_to_redis(
    parsed: &ParsedTransaction,
    cfg: &Config,
    redis: &mut ConnectionManager,
) {
    let protocol = parsed
        .program_ids
        .iter()
        .find(|id| cfg.watched_programs.contains(id))
        .cloned();

    let Some(protocol) = protocol else { return };

    let net_delta_usd = net_usdc_delta_from_tx(parsed);
    if net_delta_usd == 0.0 {
        return;
    }

    let cache = TvlCache {
        protocol: protocol.clone(),
        tvl_usd: net_delta_usd,
        slot: parsed.slot,
        updated_at: parsed.timestamp,
    };

    let key = format!("tvl:{}", protocol);
    let val = serde_json::to_string(&cache).unwrap_or_default();
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

fn detect_flash_loan(
    program_ids: &[String],
    log_messages: &[String],
    token_deltas: &[TokenDelta],
) -> FlashLoanEvidence {
    let mut methods_fired: u8 = 0;
    let mut confidence: u8 = 0;
    let mut matched_program: Option<String> = None;

    for pid in program_ids {
        if let Some((_, name)) = FLASH_LOAN_PROGRAMS
            .iter()
            .find(|(id, _)| *id == pid.as_str())
        {
            methods_fired |= 0b001;
            confidence = confidence.max(95);
            matched_program = Some(format!("{} ({})", pid, name));
            break;
        }
    }

    let flash_keywords = [
        "flash_loan",
        "flashloan",
        "flash loan",
        "borrow_flash",
        "flash_borrow",
        "flash_swap",
    ];

    'log_scan: for log in log_messages {
        if log.starts_with("Program ")
            && (log.contains(" invoke ") || log.contains(" success") || log.contains(" failed"))
        {
            continue;
        }
        let lower = log.to_lowercase();
        for kw in &flash_keywords {
            if lower.contains(kw) {
                methods_fired |= 0b010;
                confidence = confidence.max(70);
                break 'log_scan;
            }
        }
    }

    let (m3_fired, max_borrow_amount) = detect_by_delta_pattern(token_deltas);
    if m3_fired {
        methods_fired |= 0b100;
        confidence = confidence.max(55);
    }

    let method_count = methods_fired.count_ones() as u8;
    if method_count >= 2 {
        confidence = (confidence + 10 * (method_count - 1)).min(98);
    }

    if methods_fired == 0 {
        return FlashLoanEvidence::none();
    }

    FlashLoanEvidence {
        detected: true,
        confidence,
        methods_fired,
        program_id: matched_program,
        max_borrow_amount,
    }
}

fn detect_by_delta_pattern(token_deltas: &[TokenDelta]) -> (bool, u64) {
    let mut by_mint: HashMap<&str, (i128, u64)> = HashMap::new();

    for d in token_deltas {
        let entry = by_mint.entry(d.mint.as_str()).or_default();
        entry.0 += d.delta as i128;
        if d.delta < 0 {
            entry.1 = entry.1.max((-d.delta) as u64);
        }
    }

    let mut max_borrow: u64 = 0;

    for (_mint, (net_delta, max_outflow)) in &by_mint {
        if *max_outflow < FLASH_LOAN_MIN_BORROW_RAW {
            continue;
        }

        let net_abs = net_delta.unsigned_abs() as u64;
        let tolerance = max_outflow / 100;
        let is_repaid = net_abs <= tolerance;

        if is_repaid {
            max_borrow = max_borrow.max(*max_outflow);
        }
    }

    (max_borrow > 0, max_borrow)
}

fn compute_cpi_metrics(inner_instructions: &[UiInnerInstructions]) -> CpiMetrics {
    if inner_instructions.is_empty() {
        return CpiMetrics::zero();
    }

    let mut max_depth: u8 = 0;
    let mut max_width: u8 = 0;
    let mut total_cpi_count: u16 = 0;
    let mut stack_height_available = false;

    for group in inner_instructions {
        let width = group.instructions.len() as u8;
        max_width = max_width.max(width);
        total_cpi_count += group.instructions.len() as u16;

        for ix in &group.instructions {
            if let Some(sh) = ui_instruction_stack_height(ix) {
                stack_height_available = true;
                max_depth = max_depth.max(sh as u8);
            }
        }
    }

    if !stack_height_available {
        max_depth = max_width;
    }

    CpiMetrics {
        max_depth,
        max_width,
        total_cpi_count,
    }
}

fn ui_instruction_stack_height(ix: &UiInstruction) -> Option<u32> {
    match ix {
        UiInstruction::Compiled(ix) => ix.stack_height,
        UiInstruction::Parsed(UiParsedInstruction::Parsed(ix)) => ix.stack_height,
        UiInstruction::Parsed(UiParsedInstruction::PartiallyDecoded(ix)) => ix.stack_height,
    }
}

fn parse_token_deltas(
    meta: &UiTransactionStatusMeta,
    account_keys: &[String],
) -> Vec<TokenDelta> {
    let empty_balances = Vec::new();
    let pre_balances = match meta.pre_token_balances.as_ref() {
        OptionSerializer::Some(balances) => balances,
        _ => &empty_balances,
    };
    let post_balances = match meta.post_token_balances.as_ref() {
        OptionSerializer::Some(balances) => balances,
        _ => &empty_balances,
    };

    let pre_map: HashMap<u8, _> = pre_balances
        .iter()
        .map(|b| (b.account_index, b))
        .collect();

    let mut deltas = Vec::new();
    for post in post_balances {
        let account = account_keys
            .get(post.account_index as usize)
            .cloned()
            .unwrap_or_default();

        let post_amount = post.ui_token_amount.amount.parse::<u64>().unwrap_or(0);
        let pre_amount = pre_map
            .get(&post.account_index)
            .and_then(|b| b.ui_token_amount.amount.parse::<u64>().ok())
            .unwrap_or(0);
        let delta = post_amount as i64 - pre_amount as i64;

        if delta != 0 {
            deltas.push(TokenDelta {
                account,
                mint: post.mint.clone(),
                before: pre_amount,
                after: post_amount,
                delta,
            });
        }
    }

    deltas
}

pub fn net_usdc_delta_from_tx(tx: &ParsedTransaction) -> f64 {
    tx.token_deltas
        .iter()
        .filter(|d| d.mint == USDC_MINT)
        .map(|d| d.delta as f64 / 1_000_000.0)
        .sum()
}

fn subscriber_rpc_url(cfg: &Config) -> String {
    if looks_like_helius_host(&cfg.solana_rpc_url) {
        return ensure_api_key_query(http_url(&cfg.solana_rpc_url), &cfg.helius_api_key);
    }

    if looks_like_helius_host(&cfg.geyser_endpoint) {
        return ensure_api_key_query(http_url(&cfg.geyser_endpoint), &cfg.helius_api_key);
    }

    cfg.solana_rpc_url.clone()
}

fn websocket_url(cfg: &Config) -> String {
    if looks_like_helius_host(&cfg.geyser_endpoint) {
        return ensure_api_key_query(ws_url(&cfg.geyser_endpoint), &cfg.helius_api_key);
    }

    if looks_like_helius_host(&cfg.solana_rpc_url) {
        return ensure_api_key_query(ws_url(&cfg.solana_rpc_url), &cfg.helius_api_key);
    }

    ws_url(&cfg.solana_rpc_url)
}

fn looks_like_helius_host(url: &str) -> bool {
    url.contains("helius-rpc.com")
}

fn http_url(url: &str) -> String {
    if url.starts_with("wss://") {
        url.replacen("wss://", "https://", 1)
    } else if url.starts_with("ws://") {
        url.replacen("ws://", "http://", 1)
    } else {
        url.to_string()
    }
}

fn ws_url(url: &str) -> String {
    if url.starts_with("https://") {
        url.replacen("https://", "wss://", 1)
    } else if url.starts_with("http://") {
        url.replacen("http://", "ws://", 1)
    } else {
        url.to_string()
    }
}

fn ensure_api_key_query(url: String, api_key: &str) -> String {
    if api_key.is_empty() || url.contains("api-key=") {
        return url;
    }

    if url.contains('?') {
        format!("{}&api-key={}", url, api_key)
    } else {
        format!("{}?api-key={}", url, api_key)
    }
}
