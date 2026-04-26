// watcher/src/parser.rs
//
// Shared detection and parsing logic used by BOTH:
//   - geyser.rs      (WebSocket/RPC fallback — devnet/local)
//   - geyser_grpc.rs (Yellowstone gRPC — mainnet production)
//
// Nothing in this file knows about transport. It only receives
// already-extracted slices and returns typed structs.

use std::collections::HashMap;
use yellowstone_grpc_proto::prelude::{
    InnerInstructions as GrpcInnerInstructions,
    TokenBalance as GrpcTokenBalance,
};

use crate::types::{CpiMetrics, FlashLoanEvidence, TokenDelta};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Known flash loan program IDs on Solana mainnet.
pub const FLASH_LOAN_PROGRAMS: &[(&str, &str)] = &[
    ("So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo", "Solend"),
    ("MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD", "Marginfi"),
    (
        "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc",
        "Orca Whirlpool",
    ),
];

pub const BRIDGE_PROGRAMS: &[&str] = &[
    "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth",
    "3u8hJUVTA4jH1wYAyUur7FFZVQ8H635K3tSHHF4ssjQ5",
];

/// Minimum outflow to qualify as a flash loan borrow in Method 3.
/// $50k USDC (6 decimals) — real exploits borrow millions.
const FLASH_LOAN_MIN_BORROW_RAW: u64 = 10_000_000_000;

// ─── Flash Loan Detection ─────────────────────────────────────────────────────
//
// Three-method cascade — identical logic to the original geyser.rs.
// Extracted here so both transports share exactly the same detection.

pub fn detect_flash_loan(
    program_ids: &[String],
    log_messages: &[String],
    token_deltas: &[TokenDelta],
) -> FlashLoanEvidence {
    let mut methods_fired: u8 = 0;
    let mut confidence: u8 = 0;
    let mut matched_program: Option<String> = None;

    // ── Method 1: Known flash loan program ID (confidence 95) ─────────────────
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

    // ── Method 2: Log keyword scan (confidence 70) ───────────────────────────
    let flash_keywords = [
        "flash_loan",
        "flashloan",
        "flash loan",
        "borrow_flash",
        "flash_borrow",
        "flash_swap",
    ];

    'log_scan: for log in log_messages {
        // Skip Program runtime lines — they're noise
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

    // ── Method 3: Delta pattern — ONLY as corroborating signal ───────────────
    // Must NOT run standalone — balanced in/out deltas happen in every AMM swap.
    if methods_fired != 0 {
        let (m3_fired, borrow_amount) = detect_by_delta_pattern(token_deltas);
        if m3_fired {
            methods_fired |= 0b100;
            confidence = confidence.max(55);
        }

        // Confidence boost when multiple methods agree
        let method_count = methods_fired.count_ones() as u8;
        if method_count >= 2 {
            confidence = (confidence + 10 * (method_count - 1)).min(98);
        }

        return FlashLoanEvidence {
            detected: true,
            confidence,
            methods_fired,
            program_id: matched_program,
            max_borrow_amount: if methods_fired & 0b100 != 0 {
                borrow_amount
            } else {
                0
            },
        };
    }

    FlashLoanEvidence::none()
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
        let tolerance = max_outflow / 100; // 1% fee tolerance
        if net_abs <= tolerance {
            max_borrow = max_borrow.max(*max_outflow);
        }
    }

    (max_borrow > 0, max_borrow)
}

// ─── Token Delta Parser — gRPC variant ───────────────────────────────────────
//
// Yellowstone's TokenBalance proto has the same fields as the RPC JSON
// (account_index, mint, ui_token_amount.amount) just in protobuf form.

pub fn parse_token_deltas_from_grpc(
    pre_balances: &[GrpcTokenBalance],
    post_balances: &[GrpcTokenBalance],
    account_keys: &[String],
) -> Vec<TokenDelta> {
    // Build pre-balance lookup by account_index
    let pre_map: HashMap<u32, &GrpcTokenBalance> =
        pre_balances.iter().map(|b| (b.account_index, b)).collect();

    let mut deltas = Vec::new();

    for post in post_balances {
        let account = account_keys
            .get(post.account_index as usize)
            .cloned()
            .unwrap_or_default();

        // ui_token_amount.amount is a string like "1000000"
        let post_amount = post
            .ui_token_amount
            .as_ref()
            .and_then(|a| a.amount.parse::<u64>().ok())
            .unwrap_or(0);

        let pre_amount = pre_map
            .get(&post.account_index)
            .and_then(|b| b.ui_token_amount.as_ref())
            .and_then(|a| a.amount.parse::<u64>().ok())
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

// ─── CPI Metrics — gRPC variant ──────────────────────────────────────────────
//
// Yellowstone inner instructions use the same logical structure as the RPC
// JSON form — groups of instructions with stack_height.

pub fn compute_cpi_metrics_from_grpc(
    inner_instructions: &[GrpcInnerInstructions],
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
            // stack_height is an Option<u32> in the proto
            if let Some(sh) = ix.stack_height {
                stack_height_available = true;
                max_depth = max_depth.max(sh as u8);
            }
        }
    }

    // Fallback: use width as depth proxy when stack_height isn't available
    if !stack_height_available {
        max_depth = max_width;
    }

    CpiMetrics {
        max_depth,
        max_width,
        total_cpi_count,
    }
}
