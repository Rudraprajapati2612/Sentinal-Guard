use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ─── Flash Loan Evidence ──────────────────────────────────────────────────────

/// Structured flash loan detection result.
/// Replaces the old `is_flash_loan: bool` — carries confidence and method info
/// so the engine can weight Rule 1 score instead of treating all detections equally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlashLoanEvidence {
    /// Was a flash loan detected at all
    pub detected: bool,
    /// Confidence 0–100.
    ///   95 = known program ID matched (Method 1)
    ///   70 = log keyword matched    (Method 2)
    ///   55 = borrow+repay delta pattern (Method 3)
    /// Multiple methods agreeing boosts confidence, capped at 98.
    pub confidence: u8,
    /// Bitmask of which methods fired:
    ///   0b001 = Method 1 (program ID)
    ///   0b010 = Method 2 (log keyword)
    ///   0b100 = Method 3 (delta pattern)
    pub methods_fired: u8,
    /// The matched flash loan program ID + name, if Method 1 fired
    pub program_id: Option<String>,
    /// Largest single-mint borrow+repay seen (raw token units, not USD)
    /// For USDC: divide by 1_000_000 to get dollars
    pub max_borrow_amount: u64,
}

impl FlashLoanEvidence {
    pub fn none() -> Self {
        Self {
            detected: false,
            confidence: 0,
            methods_fired: 0,
            program_id: None,
            max_borrow_amount: 0,
        }
    }

    /// Check if a specific method bit is set
    pub fn method_fired(&self, bit: u8) -> bool {
        self.methods_fired & bit != 0
    }

    /// Convenience: did Method 1 (program ID) fire?
    pub fn by_program_id(&self) -> bool {
        self.method_fired(0b001)
    }

    /// Convenience: did Method 2 (log keyword) fire?
    pub fn by_log_keyword(&self) -> bool {
        self.method_fired(0b010)
    }

    /// Convenience: did Method 3 (delta pattern) fire?
    pub fn by_delta_pattern(&self) -> bool {
        self.method_fired(0b100)
    }
}

// ─── CPI Metrics ─────────────────────────────────────────────────────────────

/// Cross-Program Invocation metrics extracted from transaction meta.
/// Replaces the old `cpi_depth: u8` which only measured width, not depth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpiMetrics {
    /// Deepest nesting level seen (from stack_height field, Solana >= 1.14)
    /// 1 = top-level only, 2 = one CPI deep, 3 = CPI inside CPI, etc.
    pub max_depth: u8,
    /// Most CPIs inside any single top-level instruction (width)
    /// High width = many parallel CPIs, common in complex DeFi
    pub max_width: u8,
    /// Total CPI count across ALL top-level instructions in this tx
    pub total_cpi_count: u16,
}

impl CpiMetrics {
    pub fn zero() -> Self {
        Self { max_depth: 0, max_width: 0, total_cpi_count: 0 }
    }

    /// Heuristic suspicion score 0–100 based purely on CPI complexity.
    /// Used as a supplemental signal in the engine, not a standalone rule.
    pub fn suspicion_score(&self) -> u8 {
        // Exploit txs typically have both high depth AND high total count
        let depth_score = match self.max_depth {
            0..=2  => 0u8,
            3..=5  => 20,
            6..=9  => 50,
            10..=14 => 75,
            _      => 90,
        };
        let count_score = match self.total_cpi_count {
            0..=5   => 0u8,
            6..=15  => 10,
            16..=30 => 30,
            31..=50 => 60,
            _       => 80,
        };
        depth_score.max(count_score)
    }
}

// ─── Raw Geyser Output ────────────────────────────────────────────────────────

/// One token account balance change within a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDelta {
    /// Token account address (base58)
    pub account: String,
    /// Mint address (base58) — use to identify USDC, SOL, etc.
    pub mint: String,
    /// Balance before this transaction (raw units, not USD)
    pub before: u64,
    /// Balance after this transaction (raw units)
    pub after: u64,
    /// Signed delta: positive = tokens entered this account, negative = left
    pub delta: i64,
}

/// Normalized transaction coming out of the Geyser subscriber.
/// This is the canonical type on the internal broadcast channel.
/// geyser.rs writes this → engine.rs reads it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTransaction {
    pub slot: u64,
    /// Base58 transaction signature
    pub signature: String,
    /// All program IDs invoked in this transaction (top-level + CPIs), deduplicated
    pub program_ids: Vec<String>,
    /// Token account balance changes (non-zero deltas only)
    pub token_deltas: Vec<TokenDelta>,
    /// CPI complexity metrics (replaces bare cpi_depth: u8)
    pub cpi: CpiMetrics,
    /// Raw program log messages from the transaction
    pub log_messages: Vec<String>,
    /// Structured flash loan detection result (replaces is_flash_loan: bool)
    pub flash_evidence: FlashLoanEvidence,
    /// Source wallet / signer (first account key in the transaction)
    pub fee_payer: String,
    /// Unix timestamp — chrono::Utc::now() at parse time
    /// (block time not reliably present in Geyser stream)
    pub timestamp: i64,
}

impl ParsedTransaction {
    /// Backward-compat helper — true if any flash loan method fired
    pub fn is_flash_loan(&self) -> bool {
        self.flash_evidence.detected
    }
}

// ─── Detection Window ─────────────────────────────────────────────────────────

/// Aggregated state of a single Solana slot for one protocol.
/// The rolling window holds `cfg.window_size` of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotSnapshot {
    pub slot: u64,
    /// Program ID of the monitored protocol
    pub protocol: String,
    /// Total value locked in USD at this slot (from Redis, written by geyser.rs)
    pub tvl_usd: f64,
    /// All transactions in this slot touching this protocol
    pub transactions: Vec<ParsedTransaction>,
    /// Aggregate outflow via known bridge programs in this slot (USD)
    pub bridge_outflow_usd: f64,
    /// Unix timestamp of first tx seen in this slot
    pub timestamp: i64,
}

impl SlotSnapshot {
    /// Highest flash loan confidence seen across all txs in this slot.
    /// Used by Rule 1 to find the most credible flash loan signal.
    pub fn max_flash_confidence(&self) -> u8 {
        self.transactions
            .iter()
            .map(|tx| tx.flash_evidence.confidence)
            .max()
            .unwrap_or(0)
    }

    /// True if any tx in this slot detected a flash loan
    pub fn has_flash_loan(&self) -> bool {
        self.transactions.iter().any(|tx| tx.flash_evidence.detected)
    }

    /// Net USDC outflow from this slot (sum of negative deltas across all txs)
    pub fn net_usdc_outflow(&self) -> f64 {
        const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        self.transactions
            .iter()
            .flat_map(|tx| &tx.token_deltas)
            .filter(|d| d.mint == USDC_MINT && d.delta < 0)
            .map(|d| (-d.delta) as f64 / 1_000_000.0)
            .sum()
    }
}

/// Per-protocol rolling window of SlotSnapshots.
/// New slots push to back, old slots pop from front.
pub type ProtocolWindow = VecDeque<SlotSnapshot>;

// ─── Alert Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    FlashLoanDrain,
    TvlVelocity,
    BridgeOutflowSpike,
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::FlashLoanDrain     => write!(f, "FLASH_LOAN_DRAIN"),
            RuleType::TvlVelocity        => write!(f, "TVL_VELOCITY"),
            RuleType::BridgeOutflowSpike => write!(f, "BRIDGE_OUTFLOW_SPIKE"),
        }
    }
}

/// Fired by the detection engine when a rule threshold is crossed.
/// Broadcast to Responder and Feed API simultaneously via alert_channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    /// sha256(tx_signature_bytes ++ slot.to_le_bytes()) — used as on-chain PDA seed
    pub alert_id: [u8; 32],
    /// Hex string of alert_id (for display / Redis dedup keys)
    pub alert_id_hex: String,
    /// Protocol program ID that triggered the alert
    pub protocol: String,
    /// Severity score 0–100
    pub severity: u8,
    /// Which rule fired (highest-scoring if multiple)
    pub rule_triggered: RuleType,
    /// Estimated USD at risk at time of alert
    pub estimated_at_risk_usd: f64,
    /// Transaction signatures that contributed to the alert
    pub trigger_tx_signatures: Vec<String>,
    pub slot: u64,
    pub timestamp: i64,
    /// Base58 pubkey of the watcher that detected this
    pub watcher_pubkey: String,
}

// ─── Redis Cache Types ────────────────────────────────────────────────────────

/// Lightweight TVL record stored in Redis for fast lookups.
/// Key: `tvl:{protocol_id}` — TTL 30s — serialized as JSON.
/// Written by geyser.rs on every tx, read by engine.rs on every slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TvlCache {
    pub protocol: String,
    pub tvl_usd: f64,
    pub slot: u64,
    pub updated_at: i64,
}

/// Alert dedup record stored in Redis with TTL.
/// Key: `alert_sent:{alert_id_hex}` — presence = already dispatched.
/// TTL: 5 minutes — prevents re-firing on engine restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDedupRecord {
    pub alert_id_hex: String,
    pub fired_at: i64,
    pub severity: u8,
}
