use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
 
// ─── Raw Geyser Output ────────────────────────────────────────────────────────
 
/// One token account balance change within a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDelta {
    /// Token account address (base58)
    pub account: String,
    /// Mint address (base58) — use to identify USDC, SOL, etc.
    pub mint: String,
    /// Balance before this transaction (raw, not USD)
    pub before: u64,
    /// Balance after this transaction
    pub after: u64,
    /// Signed delta (negative = outflow from this account)
    pub delta: i64,
}

/// Normalized transaction coming out of the Geyser subscriber.
/// This is the type sent on the internal broadcast channel.
/// this goes input to the engine (means output of gyser plugin data is input to the engine)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedTransaction {
    pub slot: u64,
    /// Base58 transaction signature
    pub signature: String,
    /// All program IDs invoked in this transaction (including CPIs)
    pub program_ids: Vec<String>,
    /// Token account balance changes
    pub token_deltas: Vec<TokenDelta>,
    /// How deep the CPI call chain went (0 = top-level only)
    pub cpi_depth: u8,
    /// Raw program log messages from the transaction
    pub log_messages: Vec<String>,
    /// True if we detected a flash loan pattern in the logs or program IDs
    pub is_flash_loan: bool,
    /// Source wallet / signer (first account in tx)
    pub fee_payer: String,
    /// Unix timestamp (from block time, NOT wall clock)
    pub timestamp: i64,
}

// ─── Detection Window ─────────────────────────────────────────────────────────
 
/// Aggregated state of a single Solana slot for one protocol.
/// The rolling window holds `WINDOW_SIZE` of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotSnapshot {
    pub slot: u64,
    /// Program ID of the monitored protocol
    pub protocol: String,
    /// Total value locked in USD (from Pyth prices × token balances)
    pub tvl_usd: f64,
    /// All transactions in this slot touching this protocol
    pub transactions: Vec<ParsedTransaction>,
    /// Aggregate outflow via known bridge programs in this slot (USD)
    pub bridge_outflow_usd: f64,
    /// Unix timestamp of first tx in this slot
    pub timestamp: i64,
}
// this is a double ended queue for a rolling window (in which new snapshot add forwards and old
// will be remove from backward)

pub type protocolWindow = VecDeque<SlotSnapshot>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RuleType {
    FlashLoanDrain,
    TvlVelocity,
    BridgeOutflowSpike,
}
 
impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::FlashLoanDrain    => write!(f, "FLASH_LOAN_DRAIN"),
            RuleType::TvlVelocity       => write!(f, "TVL_VELOCITY"),
            RuleType::BridgeOutflowSpike => write!(f, "BRIDGE_OUTFLOW_SPIKE"),
        }
    }
}

/// Fired by the detection engine when a rule threshold is crossed.
/// Broadcast to Responder and Feed API simultaneously.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertEvent {
    /// sha256(tx_signature_bytes + slot.to_le_bytes()) — 32 bytes, used as on-chain PDA seed
    pub alert_id: [u8; 32],
    /// Hex string of alert_id (for display / Redis keys)
    pub alert_id_hex: String,
    /// Protocol program ID that triggered the alert
    pub protocol: String,
    /// Severity score 0–100
    pub severity: u8,
    /// Which rule fired (highest-scoring if multiple)
    pub rule_triggered: RuleType,
    /// Estimated USD at risk at time of alert
    pub estimated_at_risk_usd: f64,
    /// Transaction signatures that triggered the alert
    pub trigger_tx_signatures: Vec<String>,
    pub slot: u64,
    pub timestamp: i64,
    /// Base58 pubkey of the watcher that detected this
    pub watcher_pubkey: String,
}
 
 
// ─── Redis Cache Types ────────────────────────────────────────────────────────
 
/// Lightweight TVL record stored in Redis for fast lookups.
/// Key: `tvl:{protocol}` — serialized as JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TvlCache {
    pub protocol: String,
    pub tvl_usd: f64,
    pub slot: u64,
    pub updated_at: i64,
}
 
/// Alert dedup record stored in Redis with TTL.
/// Key: `alert_sent:{alert_id_hex}` — presence = already fired.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertDedupRecord {
    pub alert_id_hex: String,
    pub fired_at: i64,
    pub severity: u8,
}
