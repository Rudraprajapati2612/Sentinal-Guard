// watcher/src/geyser.rs
//
// Production Geyser gRPC subscriber using Yellowstone (Helius fork).
//
// Architecture decision — NO Kafka here:
//   The Geyser stream → broadcast channel path must be sub-millisecond.
//   Kafka adds 5–20ms per message. For the detection critical path (Rule 1
//   fires in the same slot as the flash loan), we cannot afford that latency.
//
//   Kafka IS used after detection fires an AlertEvent (see responder/webhooks.rs).
//   That path is NOT latency-sensitive — the pause tx already landed.
//
// Redis IS used here for one thing only:
//   TVL net-delta is written to Redis (key: tvl:{protocol}) so the detection
//   engine can read the latest TVL without a DB round-trip on every slot.

use anyhow::{Context, Result};
use futures::StreamExt;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use yellowstone_grpc_client::GeyserGrpcClient;
use yellowstone_grpc_proto::prelude::{
    subscribe_update::UpdateOneof, SubscribeRequest, SubscribeRequestFilterTransactions,
};

use crate::config::Config;
use crate::types::{CpiMetrics, FlashLoanEvidence, ParsedTransaction, TokenDelta, TvlCache};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Known flash loan program IDs on Solana mainnet.
/// Tuple: (program_id, human_readable_name)
///
/// Phase 2: pull this from a remote config endpoint so new protocols
/// can be added without redeployment.
const FLASH_LOAN_PROGRAMS: &[(&str, &str)] = &[
    ("So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo", "Solend"),
    ("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD",  "Marginfi"),
    ("whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",  "Orca Whirlpool"),
    ("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",  "Jupiter"),
];

/// Known bridge program IDs — used in engine.rs for bridge outflow detection.
/// Kept here as the canonical source.
pub const BRIDGE_PROGRAMS: &[&str] = &[
    "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",   // Wormhole core
    "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5",  // Wormhole token bridge
];

/// USDC mint address — only stablecoin we track for TVL right now.
/// Phase 2: add USDT, PYUSD, and use Pyth oracle prices for non-stable tokens.
const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/// Minimum borrow amount to count as a flash loan in Method 3 (delta pattern).
/// $500 USDC = 500_000_000 raw (6 decimals). Filters out small test transactions.
const FLASH_LOAN_MIN_BORROW_RAW: u64 = 500_000_000;

// ─── Main subscriber loop ─────────────────────────────────────────────────────

pub async fn run(
    cfg: Config,
    tx_sender: broadcast::Sender<ParsedTransaction>,
    redis: ConnectionManager,
) -> Result<()> {
    info!("Connecting to Geyser at {}", cfg.geyser_endpoint);

    let mut client = GeyserGrpcClient::build_from_shared(cfg.geyser_endpoint.clone())?
        .x_token(Some(cfg.helius_api_key.clone()))?
        .connect()
        .await
        .with_context(|| format!("Failed to connect to Geyser at {}", cfg.geyser_endpoint))?;

    info!("Geyser connected ✓");

    // Build transaction filter — one filter entry per watched program.
    // Filters are ORed on the validator side: any tx touching ANY watched program
    // will be streamed to us.
    let tx_filter = cfg
        .watched_programs
        .iter()
        .enumerate()
        .map(|(i, program_id)| {
            (
                format!("filter_{}", i),
                SubscribeRequestFilterTransactions {
                    vote: Some(false),   // skip vote transactions — very high volume, not useful
                    failed: Some(false), // skip failed transactions — can't drain if it failed
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
        accounts: HashMap::new(),
        slots: HashMap::new(),
        transactions_status: HashMap::new(),
        blocks: HashMap::new(),
        blocks_meta: HashMap::new(),
        entry: HashMap::new(),
        commitment: Some(0), // 0 = Processed (fastest — before Confirmed/Finalized)
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

                                // Write TVL net-delta to Redis.
                                // Fire-and-forget — don't block the gRPC stream on Redis latency.
                                // The engine reads this on every slot to get current TVL.
                                write_tvl_to_redis(&parsed, &cfg, &mut redis);

                                // Check receivers before sending — if detection engine
                                // crashed and dropped its receiver, no point continuing.
                                if tx_sender.receiver_count() == 0 {
                                    warn!("No receivers on tx channel — stopping Geyser subscriber");
                                    break;
                                }

                                if let Err(e) = tx_sender.send(parsed) {
                                    // Broadcast channel is full — engine is too slow.
                                    // Old messages are silently dropped by Tokio broadcast.
                                    // This is intentional — we never want to backpressure the stream.
                                    debug!("Tx channel lagged: {}", e);
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
                    _ => {} // ignore account updates, slot updates, block meta etc.
                }
            }
            Err(e) => {
                error!("Geyser stream error: {} — outer loop will reconnect", e);
                return Err(anyhow::anyhow!("Geyser stream failed: {}", e));
            }
        }
    }

    warn!("Geyser stream ended unexpectedly");
    Ok(())
}

// ─── TVL Redis writer ─────────────────────────────────────────────────────────

fn write_tvl_to_redis(
    parsed: &ParsedTransaction,
    cfg: &Config,
    redis: &mut ConnectionManager,
) {
    // Find which watched protocol this tx belongs to
    let protocol = parsed
        .program_ids
        .iter()
        .find(|id| cfg.watched_programs.contains(id))
        .cloned();

    let Some(protocol) = protocol else { return };

    // Compute net USDC delta for this tx only (not a running sum — Redis value
    // is the delta of this tx, engine accumulates across the window)
    let net_delta_usd = net_usdc_delta_from_tx(parsed);

    // We only write if there was actual USDC movement — avoids overwriting
    // a valid TVL with 0.0 on non-USDC txs
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

// ─── Transaction Parser ───────────────────────────────────────────────────────

fn parse_geyser_transaction(
    update: yellowstone_grpc_proto::prelude::SubscribeUpdateTransaction,
) -> Result<ParsedTransaction> {
    let tx_info = update
        .transaction
        .context("Missing transaction in update")?;

    let slot = update.slot;

    // Signature: raw bytes → bs58 string
    let signature = bs58::encode(&tx_info.signature).into_string();

    let tx   = tx_info.transaction.context("Missing transaction data")?;
    let meta = tx_info.meta.context("Missing transaction meta")?;
    let message = tx.message.context("Missing message")?;

    // Account keys: raw bytes → bs58 strings, preserving index order.
    // Index order matters: fee_payer = index 0, program_id_index references these.
    let account_keys: Vec<String> = message
        .account_keys
        .iter()
        .map(|k| bs58::encode(k).into_string())
        .collect();

    let fee_payer = account_keys.first().cloned().unwrap_or_default();

    // Program IDs: each top-level instruction has a program_id_index pointing
    // into account_keys. We resolve and deduplicate.
    // Note: inner instruction programs are NOT captured here — they're in
    // meta.inner_instructions. For flash loan detection we use log scanning
    // and delta patterns to catch CPI-routed flash loans.
    let program_ids: Vec<String> = message
        .instructions
        .iter()
        .filter_map(|ix| account_keys.get(ix.program_id_index as usize))
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Token deltas: diff pre/post balances per account
    let token_deltas = parse_token_deltas(&meta, &account_keys);

    // Log messages: raw strings from the Solana runtime
    let log_messages = meta.log_messages.clone();

    // CPI metrics: replaces the old single cpi_depth: u8
    let cpi = compute_cpi_metrics(&meta.inner_instructions);

    // Flash loan detection: runs three methods, returns structured evidence
    let flash_evidence = detect_flash_loan(&program_ids, &log_messages, &token_deltas);

    Ok(ParsedTransaction {
        slot,
        signature,
        program_ids,
        token_deltas,
        cpi,
        log_messages,
        flash_evidence,
        fee_payer,
        timestamp: chrono::Utc::now().timestamp(),
    })
}

// ─── Flash Loan Detection ─────────────────────────────────────────────────────

/// Runs three detection methods and returns structured evidence.
///
/// Method 1 — Program ID match (confidence 95):
///   Looks for known flash loan program IDs in the transaction's program list.
///   Most reliable: if Solend's ID is there, the tx definitely used Solend flash loan.
///   Blind spot: flash loans routed through a proxy program hide the real program ID.
///
/// Method 2 — Log keyword scan (confidence 70):
///   Scans program log messages for flash loan keywords.
///   Fallback for protocols not in our hardcoded list.
///   Blind spot: protocols that use non-standard log strings (e.g. "borrow_execute").
///
/// Method 3 — Borrow+repay delta pattern (confidence 55):
///   Detects flash loans structurally: within the same tx, the same mint has both
///   a large outflow AND a large inflow, with near-zero net delta (borrow was repaid).
///   Catches proxy-routed and unknown-protocol flash loans.
///   Blind spot: large arbitrage without flash loan can look similar, but arb typically
///   has a non-zero net delta (they keep the profit).
///
/// Multiple methods agreeing boosts confidence (capped at 98 — never 100%).
fn detect_flash_loan(
    program_ids: &[String],
    log_messages: &[String],
    token_deltas: &[TokenDelta],
) -> FlashLoanEvidence {
    let mut methods_fired: u8 = 0;
    let mut confidence: u8 = 0;
    let mut matched_program: Option<String> = None;

    // ── Method 1: Known program ID ────────────────────────────────────────────
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

    // ── Method 2: Log keyword scan ────────────────────────────────────────────
    // Skip Solana runtime lines — they are not program logs and add noise.
    // Runtime lines look like: "Program <id> invoke [2]" / "Program <id> success"
    let flash_keywords = [
        "flash_loan",
        "flashloan",
        "flash loan",
        "borrow_flash",
        "flash_borrow",
        "flash_swap",   // Jupiter uses this term
    ];

    'log_scan: for log in log_messages {
        // Skip runtime invoke/success/failure lines
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

    // ── Method 3: Borrow+repay delta pattern ──────────────────────────────────
    let (m3_fired, max_borrow_amount) = detect_by_delta_pattern(token_deltas);
    if m3_fired {
        methods_fired |= 0b100;
        confidence = confidence.max(55);
    }

    // ── Confidence boost: multiple methods agreeing ───────────────────────────
    let method_count = methods_fired.count_ones() as u8;
    if method_count >= 2 {
        // Each additional agreeing method adds 10 points, capped at 98.
        // (Never 100% — on-chain data can always be crafted to spoof signals.)
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

/// Method 3 implementation: detect borrow+repay structural pattern.
///
/// A flash loan always results in — within the same tx:
///   - A large outflow for some mint from some account (the borrow)
///   - A large inflow for that same mint (the repayment)
///   - Net delta across ALL accounts for that mint ≈ 0 (the loan is repaid)
///
/// Key insight: net delta ≈ 0 separates flash loans from arbitrage.
/// Arbitrage keeps the profit, so net delta for the traded token is non-zero.
///
/// Returns (detected: bool, max_borrow_amount_raw: u64)
fn detect_by_delta_pattern(token_deltas: &[TokenDelta]) -> (bool, u64) {
    // Group by mint: (net_delta_across_all_accounts, largest_single_outflow)
    let mut by_mint: HashMap<&str, (i128, u64)> = HashMap::new();

    for d in token_deltas {
        let entry = by_mint.entry(d.mint.as_str()).or_default();
        entry.0 += d.delta as i128; // accumulate net delta
        if d.delta < 0 {
            // Track largest single outflow (the borrow leg)
            entry.1 = entry.1.max((-d.delta) as u64);
        }
    }

    let mut max_borrow: u64 = 0;

    for (_mint, (net_delta, max_outflow)) in &by_mint {
        // Filter out small amounts — below $500 USDC equivalent
        if *max_outflow < FLASH_LOAN_MIN_BORROW_RAW {
            continue;
        }

        // Net delta near zero = loan was repaid.
        // Allow up to 1% tolerance for protocol fees.
        // e.g. borrowed $1M, repaid $1.003M (0.3% fee) → net = +$3k = 0.3% → pass
        let net_abs = net_delta.unsigned_abs() as u64;
        let tolerance = max_outflow / 100; // 1%
        let is_repaid = net_abs <= tolerance;

        if is_repaid {
            max_borrow = max_borrow.max(*max_outflow);
        }
    }

    (max_borrow > 0, max_borrow)
}

// ─── CPI Metrics ─────────────────────────────────────────────────────────────

/// Compute accurate CPI metrics from transaction inner instructions.
///
/// The old code did:
///   meta.inner_instructions.iter().map(|ii| ii.instructions.len()).max()
///
/// This measured WIDTH (how many CPIs in one group), not DEPTH (how nested).
/// Solana's protobuf flattens all CPIs per top-level instruction into one list.
/// Actual depth is encoded in the `stack_height` field on each InnerInstruction,
/// available since Solana/Agave 1.14.
///
/// stack_height meaning:
///   1 = top-level instruction (not a CPI)
///   2 = first-level CPI (called by a top-level ix)
///   3 = second-level CPI (CPI inside a CPI)
///   etc.
fn compute_cpi_metrics(
    inner_instructions: &[yellowstone_grpc_proto::prelude::InnerInstructions],
) -> CpiMetrics {
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
            if let Some(sh) = ix.stack_height {
                stack_height_available = true;
                max_depth = max_depth.max(sh as u8);
            }
        }
    }

    // If stack_height was not populated (older validator nodes),
    // fall back to using max_width as a proxy for depth.
    // This matches the old behavior but is clearly labeled as approximate.
    if !stack_height_available {
        max_depth = max_width; // approximate — same as old cpi_depth
    }

    CpiMetrics {
        max_depth,
        max_width,
        total_cpi_count,
    }
}

// ─── Token Delta Parser ───────────────────────────────────────────────────────

fn parse_token_deltas(
    meta: &yellowstone_grpc_proto::prelude::TransactionStatusMeta,
    account_keys: &[String],
) -> Vec<TokenDelta> {
    let mut deltas = Vec::new();

    // Build a lookup map: account_index → pre-balance
    // pre and post arrays are indexed by account_index, not by array position
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

        // Skip zero-delta entries — saves memory and speeds engine processing
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

// ─── TVL Helpers ─────────────────────────────────────────────────────────────

/// Compute the NET USDC flow from a single transaction.
///
/// OLD approach (wrong): summed `after` balances of all USDC accounts touched.
/// This inflates TVL because it includes user wallets, not just protocol vaults,
/// and counts the same liquidity multiple times if it touched multiple accounts.
///
/// NEW approach: sum the signed deltas. Positive = USDC entered accounts (deposits).
/// Negative = USDC left accounts (withdrawals). Net = change in total USDC
/// in the accounts this tx touched.
///
/// This is written to Redis by geyser.rs and read by engine.rs.
/// Still imperfect (doesn't distinguish vault vs user wallet), but far more
/// accurate than summing `after` balances.
///
/// Phase 2: Replace with a separate account subscription that tracks
/// only the protocol vault pubkeys.
pub fn net_usdc_delta_from_tx(tx: &ParsedTransaction) -> f64 {
    tx.token_deltas
        .iter()
        .filter(|d| d.mint == USDC_MINT)
        .map(|d| d.delta as f64 / 1_000_000.0) // USDC has 6 decimals
        .sum()
}
