// watcher/src/db.rs
//
// PostgreSQL connection pool and all query functions.
// Uses sqlx with compile-time query checking (sqlx::query_as!).
// Run `sqlx migrate run` before using — see scripts/schema.sql.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::info;
use uuid::Uuid;

use crate::config::Config;

pub type DbPool = PgPool;

// ─── Row types ────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
pub struct AlertRow {
    pub id: Uuid,
    pub alert_id_hex: String,
    pub protocol: String,
    pub severity: i16,
    pub rule_triggered: String,
    pub estimated_at_risk_usd: f64,
    pub trigger_signatures: serde_json::Value,
    pub slot: i64,
    pub watcher_pubkey: String,
    pub on_chain_tx: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct TvlSnapshotRow {
    pub id: Uuid,
    pub protocol: String,
    pub tvl_usd: f64,
    pub slot: i64,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct BridgeOutflowRow {
    pub id: Uuid,
    pub protocol: String,
    pub outflow_usd: f64,
    pub slot: i64,
    pub source_wallet: String,
    pub captured_at: DateTime<Utc>,
}

// ─── Connection ───────────────────────────────────────────────────────────────

pub async fn connect(cfg: &Config) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.db_pool_size)
        .connect(&cfg.database_url)
        .await?;

    // Run any pending migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    info!("PostgreSQL pool ready ({} max connections)", cfg.db_pool_size);
    Ok(pool)
}

// ─── Writes ───────────────────────────────────────────────────────────────────

/// Persist a fired alert. Called by detection engine before dispatching.
/// This is the crash-safe write — alert is in DB before any response fires.
pub async fn insert_alert(
    pool: &DbPool,
    alert: &crate::types::AlertEvent,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let severity = alert.severity as i16;
    let slot = alert.slot as i64;
    let rule = alert.rule_triggered.to_string();
    let sigs = serde_json::to_value(&alert.trigger_tx_signatures)?;

    sqlx::query!(
        r#"
        INSERT INTO alerts (
            id, alert_id_hex, protocol, severity, rule_triggered,
            estimated_at_risk_usd, trigger_signatures, slot, watcher_pubkey
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (alert_id_hex) DO NOTHING
        "#,
        id,
        alert.alert_id_hex,
        alert.protocol,
        severity,
        rule,
        alert.estimated_at_risk_usd,
        sigs,
        slot,
        alert.watcher_pubkey,
    )
    .execute(pool)
    .await?;

    Ok(id)
}

/// Update alert with the on-chain pause transaction signature after it lands.
pub async fn update_alert_on_chain_tx(
    pool: &DbPool,
    alert_id_hex: &str,
    tx_signature: &str,
) -> Result<()> {
    sqlx::query!(
        "UPDATE alerts SET on_chain_tx = $1 WHERE alert_id_hex = $2",
        tx_signature,
        alert_id_hex,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a TVL snapshot for Rule 2 historical baseline.
pub async fn insert_tvl_snapshot(
    pool: &DbPool,
    protocol: &str,
    tvl_usd: f64,
    slot: u64,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO tvl_snapshots (id, protocol, tvl_usd, slot)
        VALUES ($1, $2, $3, $4)
        "#,
        Uuid::new_v4(),
        protocol,
        tvl_usd,
        slot as i64,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a bridge outflow for Rule 3 baseline computation.
pub async fn insert_bridge_outflow(
    pool: &DbPool,
    protocol: &str,
    outflow_usd: f64,
    slot: u64,
    source_wallet: &str,
) -> Result<()> {
    sqlx::query!(
        r#"
        INSERT INTO bridge_outflows (id, protocol, outflow_usd, slot, source_wallet)
        VALUES ($1, $2, $3, $4, $5)
        "#,
        Uuid::new_v4(),
        protocol,
        outflow_usd,
        slot as i64,
        source_wallet,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ─── Reads ────────────────────────────────────────────────────────────────────

/// Fetch last N alerts for the REST feed endpoint.
pub async fn get_recent_alerts(pool: &DbPool, limit: i64) -> Result<Vec<AlertRow>> {
    let rows = sqlx::query_as!(
        AlertRow,
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetch alerts for a specific protocol.
pub async fn get_alerts_for_protocol(
    pool: &DbPool,
    protocol: &str,
    limit: i64,
) -> Result<Vec<AlertRow>> {
    let rows = sqlx::query_as!(
        AlertRow,
        "SELECT * FROM alerts WHERE protocol = $1 ORDER BY created_at DESC LIMIT $2",
        protocol,
        limit,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Get the 10-minute rolling average bridge outflow for a source wallet.
/// Used by Rule 3 to compute spike ratio.
pub async fn get_bridge_outflow_avg(
    pool: &DbPool,
    source_wallet: &str,
    window_minutes: i64,
) -> Result<f64> {
    let avg = sqlx::query_scalar!(
        r#"
        SELECT COALESCE(AVG(outflow_usd), 0.0)
        FROM bridge_outflows
        WHERE source_wallet = $1
          AND captured_at > NOW() - ($2 || ' minutes')::INTERVAL
        "#,
        source_wallet,
        window_minutes.to_string(),
    )
    .fetch_one(pool)
    .await?;

    Ok(avg.unwrap_or(0.0))
}
