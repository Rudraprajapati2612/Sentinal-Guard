# SentinelGuard 🛡️

> **Real-time on-chain exploit detection and automated protocol pause system for Solana DeFi**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Built on Solana](https://img.shields.io/badge/Built%20on-Solana-9945FF)](https://solana.com)
[![Anchor](https://img.shields.io/badge/Anchor-0.32.1-green)](https://www.anchor-lang.com/)
[![Network](https://img.shields.io/badge/Network-Devnet-orange)](https://explorer.solana.com/?cluster=devnet)
[![Hackathon](https://img.shields.io/badge/Colosseum-Frontier%202026-black)](https://arena.colosseum.org/hackathon)
[![npm](https://img.shields.io/badge/npm-%40sentinelguard%2Fsdk-red)](https://www.npmjs.com/package/@sentinelguard/sdk)

---

Drift lost $232M on April 1st. The attack ran across 12 transactions. The data to stop it was public from slot one. Nobody had built the automated response layer.

**SentinelGuard closes that window — from 22 minutes to under 400ms.**

---

## 🔴 Live Links

| | |
|---|---|
| **Live Dashboard** | [sentinel-guard-three.vercel.app](https://sentinel-guard-three.vercel.app) |
| **Documentation** | [sentinel-guard-three.vercel.app/docs/detection-rules](https://sentinel-guard-three.vercel.app/docs/detection-rules) |
| **Demo Video (90s)** | [Watch on Loom](https://www.loom.com/share/3859ee6e1fa748a4afd9c2a5ac7ab0fd) |
| **Pitch Video** | [Watch on Loom](https://www.loom.com/share/ffab1cb121194d8093d54562052c71c2) |
| **npm SDK** | [@sentinelguard/sdk](https://www.npmjs.com/package/@sentinelguard/sdk) |

## ✅ On-Chain Proof (Devnet)

| Event | Explorer Link |
|---|---|
| **Pause tx — Scenario 2 (TVL Velocity)** | [View on Solana Explorer](https://explorer.solana.com/tx/3BtKhbumvRwPhDaAbhGiRPbA3iWGfbMH66Fsu8SkrSHDPx7gmau6vet8cMccbzAKuEttMMBXXNkhNg4QSo423kHQ?cluster=devnet) |
| **Pause tx — Scenario 3 (Flash Loan Drain)** | [View on Solana Explorer](https://explorer.solana.com/tx/2QdTiQKEgBaF53Hk29ek75eo6mnaD3Cfv2fTimcUtMeDN48gbqwoLi9PsZ7Wa1nekoMoVZaajN9RQbkTMvwjNeDo?cluster=devnet) |

Both transactions confirm `pause_withdrawals` fired on-chain autonomously — no human triggered them.

---

## Table of Contents

- [Overview](#overview)
- [Problem Statement](#problem-statement)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Detection Rules](#detection-rules)
- [SDK Integration](#sdk-integration)
- [Monorepo Structure](#monorepo-structure)
- [Program IDs](#program-ids)
- [Prerequisites](#prerequisites)
- [Environment Configuration](#environment-configuration)
- [Setup & Running](#setup--running)
- [API Reference](#api-reference)
- [Dashboard](#dashboard)
- [Testing & Demo Verification](#testing--demo-verification)
- [Security Model](#security-model)
- [Alert Severity Thresholds](#alert-severity-thresholds)
- [Failure Handling](#failure-handling)
- [Data Stores & Retention](#data-stores--retention)
- [Deployment Topology](#deployment-topology)
- [Monitoring & Logging](#monitoring--logging)
- [Incident Response & Unpause Workflow](#incident-response--unpause-workflow)
- [Known Limitations](#known-limitations)
- [License](#license)
- [Security Disclosure](#security-disclosure)

---

## Overview

SentinelGuard is a production-grade, real-time threat detection and automated circuit-breaking system built for Solana DeFi protocols. It streams on-chain activity through Yellowstone/Helius Geyser, scores transactions against configurable exploit detection rules, and — when threat severity crosses a threshold — automatically triggers an on-chain `pause_withdrawals` instruction to halt protocol outflows before losses can compound.

The system is designed for sub-400ms detection-to-response times and includes a full operational stack: detection engine, threat feed API, webhook fan-out service, and a live monitoring dashboard.

**Built solo in 4 weeks for the Colosseum Frontier Hackathon 2026.**

---

## Problem Statement

DeFi exploits on Solana are fast. Flash loan attacks, TVL drain events, and bridge outflow spikes can drain millions within a single block. Protocol teams have no automated line of defense — by the time a human operator sees an alert and manually intervenes, damage is already done.

| Current State | With SentinelGuard |
|---|---|
| Protocol team finds out via Twitter | Automated alert fires within 1 slot |
| Manual pause requires multisig coordination | On-chain pause fires in <400ms |
| USDC already bridged before Circle is called | Circle webhook fires automatically |
| 0 protocols have circuit-breakers | Protocols integrate via 3-line SDK |
| 4–22 minute response window | Under one Solana slot |

SentinelGuard closes this gap by:

- Monitoring every transaction touching watched programs in real time
- Scoring threat signals against rule-based detection logic
- Triggering an on-chain protective pause autonomously, with no human in the loop
- Fanning out structured alerts to Discord, Telegram, Circle, and Wormhole integrations
- Providing a live dashboard for operators to monitor, analyze, and manually override

---

## How It Works

```
Solana / Geyser
     │
     ▼
Rust Watcher (yellowstone-grpc)
     │   ├── Transaction Subscriber
     │   ├── Detection Engine  ──► Rule scoring (FlashLoanDrain / TvlVelocity / BridgeOutflowSpike)
     │   ├── Responder         ──► on-chain pause_withdrawals (Anchor CPI)
     │   └── Threat Feed API   ──► HTTP + WebSocket endpoints
     │
     ▼
PostgreSQL / Redis / Kafka
     │   ├── PostgreSQL  — alerts, TVL history, outflow history
     │   ├── Redis       — hot state cache, alert deduplication
     │   └── Kafka       — durable alert/event log
     │
     ▼
Webhook Dispatcher (Bun / Elysia)
     │   ├── Discord
     │   ├── Telegram
     │   ├── Circle API
     │   └── Wormhole API
     │
     ▼
Next.js Dashboard
     ├── Live Alerts
     ├── Analytics
     ├── Protocol Controls
     └── Live Monitoring
```

### Watcher Task Topology

The Rust watcher runs four concurrent async tasks:

| Task | Responsibility |
|---|---|
| `transaction_subscriber` | Subscribes to Yellowstone gRPC stream, filters by watched programs |
| `detection_engine` | Parses transactions, applies scoring rules, emits alerts when threshold met |
| `responder` | Receives high-severity alerts, builds and signs `pause_withdrawals` CPI |
| `threat_feed_api` | Serves HTTP REST + WebSocket endpoints for dashboard and external consumers |

---

## Architecture

### On-Chain Programs (Anchor / Rust)

| Program | Address | Role |
|---|---|---|
| `sentinel_guardian` | `2Fi9UPVbD77Cr2SerjKkpPtbejYXdaa6D4R3Pjor4kQs` | Pause logic and bounty distribution |
| `mock_protocol` | `HyUb8Ffara4byitYExmbjbA37Ja7By8fECpG6dFyg8Ln` | Test target for attack simulation |

### Off-Chain Services

| Service | Tech | Role |
|---|---|---|
| `watcher` | Rust + Axum + Tokio | Detection engine and threat feed API |
| `apps/webhook-dispatcher` | Bun + Elysia | Notification fan-out to external channels |
| `apps/sentinel-frontend` | Next.js + Recharts + shadcn/ui | Operator dashboard and landing page |

### Data Layer

| Store | Usage |
|---|---|
| PostgreSQL | Persistent alert storage, TVL history, bridge outflow history |
| Redis | Hot state (current TVL, vault balances), alert deduplication |
| Kafka | Durable event log for transactions and alerts |

---

## Detection Rules

SentinelGuard ships three built-in detection rules. Each rule contributes a severity score; alerts are published and/or on-chain pause is triggered based on configurable thresholds.

### Rule 1 — `FlashLoanDrain`

Detects flash loan–funded drain attacks: large borrows immediately followed by vault withdrawals within the same transaction or closely adjacent slots.

- Detection via known program IDs (Solend, Marginfi, Orca — confidence 95)
- Detection via log keywords `flash_loan` / `flash_borrow` (confidence 70)
- Delta pattern corroboration (never standalone — prevents AMM false positives)
- Same-signer bonus: +15 score if flash and drain share the same fee payer
- Uses `peak_tvl` as baseline, not `oldest_tvl`
- **Score:** `40 + drop*100*confidence_factor + same_signer_bonus` — capped at 99

### Rule 2 — `TvlVelocity`

Detects abnormally fast TVL decline over a rolling slot window.

- TVL drop ≥ 20% in last 3 slots
- Guards: TVL must be above $50k, absolute drop above $10k
- **Score:** `75 + (drop - 0.20) * 100` — capped at 99

### Rule 3 — `BridgeOutflowSpike`

Detects anomalous spikes in bridge outflow volume indicating funds being moved cross-chain.

- Outflow exceeds 10× rolling average
- **Score:** 85 at 10–20×, 95 at 20×+

---

## SDK Integration

Install the npm SDK and add SentinelGuard to your protocol in minutes.

```bash
npm install @sentinelguard/sdk
```

```typescript
import { SentinelClient } from "@sentinelguard/sdk";

const sentinel = new SentinelClient();

// Subscribe to live alerts for your protocol
const unsubscribe = sentinel.subscribe(
  "your_protocol_address",
  (alert) => {
    console.log(`Alert: ${alert.rule_triggered} — severity ${alert.severity}`);
    if (alert.severity >= 90) triggerEmergencyProtocol();
  }
);

// Fetch historical alerts
const alerts = await sentinel.getAlerts("your_protocol_address");

// Public threat feed — no API key required
const threats = await sentinel.getThreats();
```

Full SDK docs: [npmjs.com/package/@sentinelguard/sdk](https://www.npmjs.com/package/@sentinelguard/sdk)

---

## Monorepo Structure

```
sentinelguard/
├── programs/
│   ├── sentinel_guardian/      # On-chain pause and bounty logic (Anchor)
│   └── mock_protocol/          # Test protocol for attack simulation (Anchor)
├── watcher/
│   ├── src/
│   │   ├── subscriber.rs       # Yellowstone gRPC transaction subscriber
│   │   ├── detection/          # Rule engine and scoring logic
│   │   ├── responder.rs        # On-chain pause_withdrawals executor
│   │   └── api/                # Axum HTTP + WebSocket threat feed
│   ├── migrations/             # PostgreSQL schema migrations
│   └── Cargo.toml
├── apps/
│   ├── sentinel-frontend/      # Next.js dashboard and landing page
│   │   ├── app/
│   │   └── components/
│   └── webhook-dispatcher/     # Bun/Elysia notification fan-out
├── tests/
│   └── attack_scenarios.ts     # End-to-end exploit simulation tests
├── docker-services/
│   └── docker-compose.yml      # Local Redis, Kafka, PostgreSQL
└── README.md
```

---

## Program IDs

| Program | Network | Address |
|---|---|---|
| `sentinel_guardian` | Devnet | `2Fi9UPVbD77Cr2SerjKkpPtbejYXdaa6D4R3Pjor4kQs` |
| `mock_protocol` | Devnet | `HyUb8Ffara4byitYExmbjbA37Ja7By8fECpG6dFyg8Ln` |

> Both programs are deployed to **Devnet**. Mainnet deployment requires additional multisig authority setup and a formal audit.

---

## Prerequisites

| Dependency | Version | Notes |
|---|---|---|
| Rust | stable | Install via `rustup` |
| Anchor CLI | 0.32.1 | `cargo install --git https://github.com/coral-xyz/anchor anchor-cli` |
| Solana CLI | ≥ 1.18 | `sh -c "$(curl -sSfL https://release.solana.com/stable/install)"` |
| Bun | ≥ 1.1 | `curl -fsSL https://bun.sh/install \| bash` |
| Node.js | ≥ 20 | For frontend |
| Docker + Compose | Latest | For local infra stack |
| Helius / Yellowstone gRPC | — | API key required |

---

## Environment Configuration

### Watcher (`watcher/.env`)

| Variable | Description | Example |
|---|---|---|
| `HELIUS_API_KEY` | Helius API key for Geyser access | `abc123...` |
| `SENTINEL_PROGRAM_ID` | Deployed sentinel_guardian program ID | `2Fi9UPVbD77...` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/sentinel` |
| `PROTOCOL_AUTHORITY` | Authority pubkey for on-chain pause CPI | `YourPubkey...` |
| `GEYSER_ENDPOINT` | Yellowstone gRPC endpoint URL | `https://mainnet.helius-rpc.com` |
| `SOLANA_RPC_URL` | Solana RPC URL | `https://api.devnet.solana.com` |
| `WATCHER_KEYPAIR_PATH` | Path to watcher signing keypair | `~/.config/solana/watcher.json` |
| `WATCHED_PROGRAMS` | Comma-separated program IDs to monitor | `HyUb8Ff...,TokenkegQ...` |
| `TRACKED_MINT` | Token mint address to track for TVL | `So11111...` |
| `VAULT_ACCOUNTS` | Comma-separated vault account addresses | `vault1,vault2` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379` |
| `KAFKA_BROKERS` | Kafka broker addresses | `localhost:9092` |
| `KAFKA_TX_TOPIC` | Kafka topic for raw transactions | `sentinel.transactions` |
| `KAFKA_ALERT_TOPIC` | Kafka topic for published alerts | `sentinel.alerts` |
| `API_PORT` | Port for threat feed HTTP API | `8080` |
| `WEBHOOK_DISPATCHER_URL` | Internal URL of webhook dispatcher | `http://localhost:3001` |
| `TVL_DROP_THRESHOLD` | TVL drop % to trigger TvlVelocity rule | `0.15` |
| `BRIDGE_SPIKE_MULTIPLIER` | Outflow multiplier for BridgeOutflowSpike | `3.0` |
| `MIN_SEVERITY_TO_PAUSE` | Minimum score to trigger on-chain pause | `85` |
| `MIN_SEVERITY_TO_PUBLISH` | Minimum score to publish an alert | `50` |
| `WINDOW_SIZE` | Rolling window for velocity checks (seconds) | `60` |

### Frontend (`apps/sentinel-frontend/.env.local`)

| Variable | Description | Example |
|---|---|---|
| `NEXT_PUBLIC_WATCHER_HTTP_URL` | Watcher API base URL | `http://localhost:8080` |
| `NEXT_PUBLIC_WATCHER_WS_URL` | Watcher WebSocket URL | `ws://localhost:8080/ws` |

### Webhook Dispatcher (`apps/webhook-dispatcher/.env`)

| Variable | Description | Example |
|---|---|---|
| `PORT` | Dispatcher HTTP port | `3001` |
| `DISPATCHER_API_SECRET` | Shared secret for watcher → dispatcher auth | `super_secret` |
| `DISCORD_WEBHOOK_URL` | Discord webhook URL | `https://discord.com/api/webhooks/...` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | `1234567890:ABC...` |
| `TELEGRAM_CHAT_ID` | Telegram chat/channel ID | `-1001234567890` |
| `CIRCLE_API_KEY` | Circle API key | `circle_...` |
| `WORMHOLE_API_KEY` | Wormhole API key | `whorm_...` |

---

## Setup & Running

### 1. Start Infrastructure

```bash
cd docker-services
docker compose up -d
docker compose ps
```

### 2. Run Database Migrations

```bash
cd watcher
sqlx migrate run --database-url "$DATABASE_URL"
```

### 3. Deploy Anchor Programs

If deploying fresh to Devnet:

```bash
cd programs
anchor build
anchor deploy --provider.cluster devnet
```

If using the already-deployed program IDs above, update your `.env` and skip this step.

### 4. Start the Watcher

```bash
cd watcher
cargo run --release
```

### 5. Start the Webhook Dispatcher

```bash
cd apps/webhook-dispatcher
bun install
bun run start
```

### 6. Start the Frontend Dashboard

```bash
cd apps/sentinel-frontend
npm install
npm run dev
```

Dashboard available at `http://localhost:3000`.

---

## API Reference

| Endpoint | Method | Description |
|---|---|---|
| `/api/alerts` | `GET` | List recent alerts with severity, rule, and timestamps |
| `/api/stats` | `GET` | Current system stats: alert count, pause count, uptime |
| `/api/unpause` | `POST` | Manually trigger on-chain unpause (requires operator auth) |
| `/api/config` | `GET` / `POST` | View or update runtime detection thresholds |
| `/api/protocol-status` | `GET` | Current protocol pause state from on-chain account |
| `/api/tvl` | `GET` | Current TVL and historical TVL data series |
| `/api/dispatch` | `POST` | Manually trigger a webhook dispatch (internal use) |

**WebSocket:** Connect to `NEXT_PUBLIC_WATCHER_WS_URL` for a live stream of alert events and TVL updates without polling.

---

## Dashboard

The Next.js dashboard provides four main operational areas:

**Alerts** — Live feed of all scored alerts with rule name, severity score, affected accounts, and timestamp. Color-coded by severity. Links to Solana Explorer for each transaction.

**Analytics** — Time-series charts for TVL, bridge outflow volume, and alert frequency. Useful for baselining normal protocol behavior and reviewing post-incident timelines.

**Controls** — Manual override panel: trigger `unpause_withdrawals`, adjust thresholds at runtime without restarting the watcher.

**Live Monitoring** — Real-time feed of incoming transactions being scored, with per-rule signal breakdown.

---

## Testing & Demo Verification

### Run Attack Simulations

```bash
cd tests
bun install
bun run attack_scenarios.ts
```

Executes 5 exploit simulations against `mock_protocol` on Devnet:

| Scenario | Attack Type | Expected |
|---|---|---|
| 1 | Normal deposits + small withdraw | NO alert |
| 2 | Rapid 80% drain | Rule 2 fires — TVL_VELOCITY |
| 3 | Flash borrow + drain | Rule 1 fires — FLASH_LOAN_DRAIN |
| 4 | 10% drain below threshold | NO alert |
| 5 | Slow cumulative drain | Rule 2 fires cumulatively |

**Scenario 3 is the recommended demo scenario** — shows a flash loan attack detected and the vault paused on-chain before the attacker can withdraw.

### Confirm Pause Execution

```bash
solana account HyUb8Ffara4byitYExmbjbA37Ja7By8fECpG6dFyg8Ln --url devnet
```

The `withdrawals_paused` field will be `true`. Confirmed pause transactions on Solana Explorer:

- [Pause tx 1 — TVL Velocity](https://explorer.solana.com/tx/3BtKhbumvRwPhDaAbhGiRPbA3iWGfbMH66Fsu8SkrSHDPx7gmau6vet8cMccbzAKuEttMMBXXNkhNg4QSo423kHQ?cluster=devnet)
- [Pause tx 2 — Flash Loan Drain](https://explorer.solana.com/tx/2QdTiQKEgBaF53Hk29ek75eo6mnaD3Cfv2fTimcUtMeDN48gbqwoLi9PsZ7Wa1nekoMoVZaajN9RQbkTMvwjNeDo?cluster=devnet)

---

## Security Model

- The watcher keypair (`WATCHER_KEYPAIR_PATH`) has authority to call `pause_withdrawals` on the `sentinel_guardian` program and must be stored securely.
- The `DISPATCHER_API_SECRET` is kept confidential between the watcher and dispatcher. The dispatcher rejects requests without a valid `Authorization` header.
- Detection rule thresholds are the primary defense-tuning surface. Misconfigured thresholds (too low) may cause false-positive pauses; (too high) may miss real attacks.
- The system is defense-in-depth — it adds a first automated layer, but does not replace protocol-level security audits or multisig governance.
- On-chain pause authority is held by a single keypair for hackathon demo purposes. A production deployment should use a multisig (Squads Protocol) for pause authority.

---

## Alert Severity Thresholds

| Score Range | Level | Default Action |
|---|---|---|
| 0 – 49 | INFO | No action. Logged to PostgreSQL. |
| 50 – 74 | WARNING | Alert published to dashboard and Kafka. Webhook notification sent. |
| 75 – 84 | HIGH | Alert published. All webhook channels notified with urgency flag. |
| 85 – 100 | CRITICAL | Alert published + on-chain `pause_withdrawals` triggered automatically. |

Thresholds are controlled by `MIN_SEVERITY_TO_PUBLISH` and `MIN_SEVERITY_TO_PAUSE` and can be updated at runtime via `POST /api/config` without restarting the watcher.

---

## Failure Handling

| Failure Mode | Behavior |
|---|---|
| Geyser connection drop | Reconnects with exponential backoff; no alerts lost during gap |
| PostgreSQL unavailable | Continues in-memory; alerts buffered in Redis; DB writes retried |
| Redis unavailable | Falls back to in-process state; dedup disabled temporarily |
| Kafka unavailable | Alert publishing continues to dashboard and webhooks; Kafka writes retried on reconnect |
| Webhook dispatcher down | Retries dispatch with exponential backoff; alerts still published to dashboard |
| On-chain pause CPI fails | Error logged with full context; operator notified via all webhook channels |

---

## Data Stores & Retention

| Store | Data | Default Retention |
|---|---|---|
| PostgreSQL `alerts` | All scored alerts ≥ `MIN_SEVERITY_TO_PUBLISH` | Indefinite |
| PostgreSQL `tvl_history` | TVL snapshots at configurable intervals | 90 days rolling |
| PostgreSQL `outflow_history` | Bridge outflow volume per window | 90 days rolling |
| Redis | Hot TVL state, vault balances, alert dedup keys | 24-hour TTL on dedup keys |
| Kafka `sentinel.transactions` | Raw transaction payloads | 7 days (default) |
| Kafka `sentinel.alerts` | Alert event log | 30 days (default) |

---

## Deployment Topology

```
                     ┌─────────────────┐
                     │   Solana RPC /  │
                     │ Yellowstone gRPC│
                     └────────┬────────┘
                              │
                     ┌────────▼────────┐
                     │  Watcher (Rust) │
                     │  + Axum API     │
                     └───┬─────────┬───┘
                         │         │
           ┌─────────────▼┐       ┌▼──────────────┐
           │  PostgreSQL  │       │     Redis      │
           └──────────────┘       └────────────────┘
                                          │
                               ┌──────────▼──────────┐
                               │        Kafka         │
                               └──────────┬───────────┘
                                          │
                               ┌──────────▼──────────┐
                               │  Webhook Dispatcher  │
                               │  (Bun, stateless)    │
                               └─────────────────────┘
```

---

## Monitoring & Logging

The watcher emits structured JSON logs at configurable verbosity (`RUST_LOG=info` for production, `debug` for development). Every alert, CPI call, and rule scoring event is logged with:

- `timestamp` (ISO 8601)
- `rule` (detection rule name)
- `severity` (integer score)
- `tx_signature` (Solana transaction signature)
- `accounts_involved` (affected account pubkeys)
- `action_taken` (`published` / `paused` / `none`)

---

## Incident Response & Unpause Workflow

1. **Triage** — Review the triggering alert in the dashboard Alerts panel. Examine the linked transaction on Solana Explorer.
2. **Investigate** — Use the Analytics panel to inspect TVL trends and outflow history around the incident timestamp.
3. **Neutralize** — Coordinate with the protocol team to identify and close the exploit vector before unpausing.
4. **Unpause** — Execute unpause via the dashboard Controls panel or CLI:

```bash
anchor run unpause --provider.cluster devnet
```

5. **Post-mortem** — Export the incident alert timeline from `/api/alerts` and TVL history from `/api/tvl`.

---

## Known Limitations

- **Devnet only** — Mainnet deployment requires a formal security audit of `sentinel_guardian` and production-grade key management.
- **Single watcher keypair** — Production systems should use Squads multisig for pause authority.
- **Detection rules are heuristic** — The three built-in rules cover known exploit patterns but cannot detect novel attack vectors without rule updates.
- **No historical backfill** — The watcher only processes transactions received after startup.
- **Kafka is single-broker in demo mode** — Not fault-tolerant; a 3-broker cluster is required for production.
- **No audit** — `sentinel_guardian` has not been independently audited. Do not use in production with real protocol funds without a full audit.

---

## License

MIT License. See [LICENSE](LICENSE) for full terms.

---

## Security Disclosure

If you discover a security vulnerability in SentinelGuard, please disclose responsibly. Do not open a public GitHub issue for security findings.

**Contact:** rudraprajapati2612@gmail.com

Please include a description of the vulnerability, steps to reproduce, potential impact, and any suggested mitigations. We aim to respond within 48 hours.

---

*Built for the [Colosseum Frontier Hackathon 2026](https://arena.colosseum.org/hackathon) by [@0xRudraSol](https://x.com/0xRudraSol)*