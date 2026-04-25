use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tracing::info;
use uuid::Uuid;
use serde::Serialize;
use crate::config::Config;

pub type DbPool = PgPool;

// ─── Row types ─────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow, Serialize)]
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

// ─── Connection ────────────────────────────────────────────

pub async fn connect(cfg: &Config) -> Result<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.db_pool_size)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .idle_timeout(std::time::Duration::from_secs(30))
        .max_lifetime(std::time::Duration::from_secs(300))
        .connect(&cfg.database_url)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    info!("PostgreSQL pool ready ({} max connections)", cfg.db_pool_size);
    Ok(pool)
}

// ─── Writes ────────────────────────────────────────────────

pub async fn insert_alert(
    pool: &DbPool,
    alert: &crate::types::AlertEvent,
) -> Result<Uuid> {
    let id = Uuid::new_v4();
    let trigger_signatures = serde_json::to_value(&alert.trigger_tx_signatures)?;
    let rule_triggered = alert.rule_triggered.to_string();

   sqlx::query(
    r#"
    INSERT INTO alerts (
        id, alert_id_hex, protocol, severity, rule_triggered,
        estimated_at_risk_usd, trigger_signatures, slot, watcher_pubkey
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    ON CONFLICT DO NOTHING
    "#,
)
    .bind(id)
    .bind(&alert.alert_id_hex)
    .bind(&alert.protocol)
    .bind(alert.severity as i16)
    .bind(rule_triggered.as_str())
    .bind(alert.estimated_at_risk_usd)
    .bind(trigger_signatures)
    .bind(alert.slot as i64)
    .bind(&alert.watcher_pubkey)
    .execute(pool)
    .await?;

    Ok(id)
}

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

pub async fn insert_tvl_snapshot(
    pool: &DbPool,
    protocol: &str,
    tvl_usd: f64,
    slot: u64,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO tvl_snapshots (id, protocol, tvl_usd, slot)
        VALUES ($1,$2,$3,$4)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(protocol)
    .bind(tvl_usd)
    .bind(slot as i64)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_bridge_outflow(
    pool: &DbPool,
    protocol: &str,
    outflow_usd: f64,
    slot: u64,
    source_wallet: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO bridge_outflows (id, protocol, outflow_usd, slot, source_wallet)
        VALUES ($1,$2,$3,$4,$5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(protocol)
    .bind(outflow_usd)
    .bind(slot as i64)
    .bind(source_wallet)
    .execute(pool)
    .await?;

    Ok(())
}

// ─── Reads ────────────────────────────────────────────────

pub async fn get_recent_alerts(
    pool: &DbPool,
    limit: i64,
) -> Result<Vec<AlertRow>> {
    let rows = sqlx::query_as!(
        AlertRow,
        "SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1",
        limit,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

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

/// ✅ FIXED: proper scalar query
pub async fn get_bridge_outflow_avg(
    pool: &DbPool,
    source_wallet: &str,
    window_minutes: i64,
) -> Result<f64> {
    let avg = sqlx::query_scalar::<_, Option<f64>>(
        r#"
        SELECT AVG(outflow_usd)
        FROM bridge_outflows
        WHERE source_wallet = $1
          AND captured_at > NOW() - make_interval(mins => $2)
        "#
    )
    .bind(source_wallet)
    .bind(window_minutes as i32)
    .fetch_one(pool)
    .await?;

    Ok(avg.unwrap_or(0.0))
}

pub async fn get_tvl_history(
    pool: &DbPool,
    protocol: &str,
    limit: i64,
) -> Result<Vec<TvlSnapshotRow>> {
    let rows = sqlx::query_as!(
        TvlSnapshotRow,
        r#"
        SELECT id, protocol, tvl_usd, slot, captured_at
        FROM tvl_snapshots
        WHERE protocol = $1
        ORDER BY captured_at DESC
        LIMIT $2
        "#,
        protocol,
        limit
    )
    .fetch_all(pool)
    .await?;

    Ok(rows)
}