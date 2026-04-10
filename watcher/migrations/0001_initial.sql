-- migrations/0001_initial.sql
-- Run with: sqlx migrate run

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Alerts ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id_hex         VARCHAR(64) UNIQUE NOT NULL,
    protocol             VARCHAR(64) NOT NULL,
    severity             SMALLINT NOT NULL CHECK (severity BETWEEN 0 AND 100),
    rule_triggered       VARCHAR(32) NOT NULL,
    estimated_at_risk_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
    trigger_signatures   JSONB NOT NULL DEFAULT '[]',
    slot                 BIGINT NOT NULL,
    watcher_pubkey       VARCHAR(64) NOT NULL,
    on_chain_tx          VARCHAR(128),        -- pause tx signature (set after confirm)
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_protocol   ON alerts (protocol);
CREATE INDEX idx_alerts_severity   ON alerts (severity);
CREATE INDEX idx_alerts_created_at ON alerts (created_at DESC);

-- ── TVL Snapshots (Rule 2 historical baseline) ────────────────────────────────
CREATE TABLE IF NOT EXISTS tvl_snapshots (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    protocol     VARCHAR(64) NOT NULL,
    tvl_usd      DOUBLE PRECISION NOT NULL,
    slot         BIGINT NOT NULL,
    captured_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tvl_protocol_time ON tvl_snapshots (protocol, captured_at DESC);

-- Auto-delete snapshots older than 24 hours (keep DB lean)
-- In production: use TimescaleDB or pg_partman for better retention management

-- ── Bridge Outflows (Rule 3 rolling average) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS bridge_outflows (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    protocol       VARCHAR(64) NOT NULL,
    outflow_usd    DOUBLE PRECISION NOT NULL,
    slot           BIGINT NOT NULL,
    source_wallet  VARCHAR(64) NOT NULL,
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_bridge_wallet_time ON bridge_outflows (source_wallet, captured_at DESC);
