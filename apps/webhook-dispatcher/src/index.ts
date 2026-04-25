// src/index.ts
//
// SentinelGuard Webhook Dispatcher
//
// Receives AlertEvent from the Rust watcher (POST /dispatch)
// and fans out to all configured targets in parallel:
//
//   1. Discord     — rich embed with severity color + explorer link (REAL, fires during demo)
//   2. Circle      — USDC freeze request (integration point, logs intent)
//   3. Wormhole    — bridge halt request (integration point, logs intent)
//   4. Telegram    — optional mobile notification
//
// Why a separate Bun service instead of doing this in Rust?
//   - Fan-out targets change frequently (new bridges, new notification channels)
//   - TypeScript is better for HTTP/webhook work than Rust
//   - Keeps the Rust watcher focused on the critical path
//   - Can be deployed independently without recompiling the watcher
//
// The Rust watcher publishes to Kafka (durable) AND POSTs here (fast).
// If this service is down, Kafka still has the alert. No data loss.

import { Elysia, t } from "elysia";
import {cors} from '@elysia/cors';
import { sendDiscordAlert } from "./targets/discord.ts";
import { requestCircleFreeze } from "./targets/circle.ts";
import { requestWormholeHalt } from "./targets/wormhole.ts";
import { sendTelegramAlert } from "./targets/telegram.ts";
import type { AlertEvent, DispatchResult } from "./types.ts";

// ─── Config ───────────────────────────────────────────────────────────────────

const PORT = parseInt(process.env.PORT ?? "3001");
const API_SECRET = process.env.DISPATCHER_API_SECRET ?? "";

// ─── In-memory alert log (last 100 alerts for the /alerts endpoint) ───────────
const alertLog: Array<AlertEvent & { received_at: string; dispatch_results: DispatchResult }> = [];
const MAX_LOG = 100;

// ─── Dispatch orchestrator ────────────────────────────────────────────────────

async function dispatchAlert(alert: AlertEvent): Promise<DispatchResult> {
  const start = Date.now();
  const dispatched: string[] = [];
  const failed: string[] = [];

  console.log(`\n${"═".repeat(60)}`);
  console.log(`⚡ ALERT RECEIVED`);
  console.log(`   Rule:     ${alert.rule_triggered}`);
  console.log(`   Severity: ${alert.severity}/99`);
  console.log(`   Protocol: ${alert.protocol.slice(0, 16)}...`);
  console.log(`   At Risk:  $${alert.estimated_at_risk_usd.toLocaleString("en-US", { maximumFractionDigits: 0 })} USDC`);
  console.log(`   Slot:     ${alert.slot}`);
  console.log(`   Alert ID: ${alert.alert_id_hex.slice(0, 32)}...`);
  console.log(`${"─".repeat(60)}`);

  // Fan out to all targets in parallel — don't let one failure block others
  const results = await Promise.allSettled([
    sendDiscordAlert(alert).then(() => dispatched.push("discord")).catch(e => {
      console.error(`[Discord] Failed: ${e}`);
      failed.push("discord");
    }),

    requestCircleFreeze(alert).then(r => {
      if (r.attempted || !r.attempted) dispatched.push("circle");
    }).catch(e => {
      console.error(`[Circle] Failed: ${e}`);
      failed.push("circle");
    }),

    requestWormholeHalt(alert).then(r => {
      if (r.attempted || !r.attempted) dispatched.push("wormhole");
    }).catch(e => {
      console.error(`[Wormhole] Failed: ${e}`);
      failed.push("wormhole");
    }),

    sendTelegramAlert(alert).then(() => dispatched.push("telegram")).catch(e => {
      // Telegram is optional — warn but don't fail
      if (process.env.TELEGRAM_BOT_TOKEN) {
        console.warn(`[Telegram] Failed: ${e}`);
        failed.push("telegram");
      }
    }),
  ]);

  const elapsed = Date.now() - start;
  console.log(`${"─".repeat(60)}`);
  console.log(`✅ Dispatch complete in ${elapsed}ms`);
  console.log(`   Sent to:  ${dispatched.join(", ") || "none"}`);
  if (failed.length > 0) {
    console.log(`   Failed:   ${failed.join(", ")}`);
  }
  console.log(`${"═".repeat(60)}\n`);

  return {
    alert_id_hex: alert.alert_id_hex,
    dispatched_to: dispatched,
    failed,
    timestamp: new Date().toISOString(),
  };
}

// ─── Elysia server ────────────────────────────────────────────────────────────

const app = new Elysia()
  .use(cors())
  // ── Health check ──────────────────────────────────────────────────────────
  .get("/health", () => ({
    status: "ok",
    service: "sentinel-webhook-dispatcher",
    version: "0.1.0",
    uptime_seconds: Math.floor(process.uptime()),
    alerts_dispatched: alertLog.length,
    targets: {
      discord:  !!process.env.DISCORD_WEBHOOK_URL,
      circle:   !!process.env.CIRCLE_API_KEY,
      wormhole: !!process.env.WORMHOLE_API_KEY,
      telegram: !!(process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_CHAT_ID),
    },
  }))

  // ── Main dispatch endpoint — called by the Rust watcher ──────────────────
  .post(
    "/dispatch",
    async ({ body, headers, set }) => {
      // Optional API secret auth
      if (API_SECRET) {
        const auth = headers["x-sentinel-secret"];
        if (auth !== API_SECRET) {
          set.status = 401;
          return { error: "Unauthorized" };
        }
      }

      const alert = body as AlertEvent;

      // Basic validation
      if (!alert.alert_id_hex || !alert.protocol || !alert.rule_triggered) {
        set.status = 400;
        return { error: "Invalid AlertEvent — missing required fields" };
      }

      // Dispatch (non-blocking — return 202 immediately, dispatch in background)
      const dispatchPromise = dispatchAlert(alert);

      // Await the dispatch but with a 10s timeout so the watcher doesn't hang
      const result = await Promise.race([
        dispatchPromise,
        new Promise<DispatchResult>((_, reject) =>
          setTimeout(() => reject(new Error("Dispatch timeout")), 10_000)
        ),
      ]).catch(err => ({
        alert_id_hex: alert.alert_id_hex,
        dispatched_to: [],
        failed: ["timeout"],
        timestamp: new Date().toISOString(),
        error: String(err),
      }));

      // Append to in-memory log
      alertLog.unshift({
        ...alert,
        received_at: new Date().toISOString(),
        dispatch_results: result,
      });
      if (alertLog.length > MAX_LOG) alertLog.pop();

      set.status = 202;
      return result;
    },
    {
      // Elysia body schema — loose validation, Rust watcher serializes the full struct
      body: t.Object({
        alert_id_hex:           t.String(),
        protocol:               t.String(),
        severity:               t.Number(),
        rule_triggered:         t.String(),
        estimated_at_risk_usd:  t.Number(),
        trigger_tx_signatures:  t.Array(t.String()),
        slot:                   t.Number(),
        timestamp:              t.Number(),
        watcher_pubkey:         t.String(),
        // Optional fields
        alert_id:               t.Optional(t.Array(t.Number())),
      }, { additionalProperties: true }),
    }
  )

  // ── Alert log — last 100 dispatched alerts ─────────────────────────────────
  .get("/alerts", ({ query }) => {
    const limit = Math.min(parseInt(String(query.limit ?? "20")), 100);
    return {
      total: alertLog.length,
      alerts: alertLog.slice(0, limit),
    };
  })

  // ── Test endpoint — fire a fake alert to verify Discord is working ─────────
  .post("/test", async ({ set }) => {
    const fakeAlert: AlertEvent = {
      alert_id: Array(32).fill(0),
      alert_id_hex: "test_" + Date.now().toString(16).padStart(60, "0"),
      protocol:     "3Eue3cN8zMkeCHLiy6KNNSi6AjKdDfJTBsME4md3xcaC",
      severity:     85,
      rule_triggered: "FlashLoanDrain",
      estimated_at_risk_usd: 1_234_567,
      trigger_tx_signatures: [
        "4nEoycGR8CvCZh12xyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234567890",
      ],
      slot:         9_828,
      timestamp:    Math.floor(Date.now() / 1000),
      watcher_pubkey: "EbVbJDyHdwoFZLxK7Ak8M4ta7hvJQthmBaGehd2VYa7m",
    };

    console.log("[Test] Firing test alert to all targets...");
    const result = await dispatchAlert(fakeAlert);
    set.status = 200;
    return { message: "Test alert fired", result };
  })

  // ── Stats endpoint ─────────────────────────────────────────────────────────
  .get("/stats", () => {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byRule: Record<string, number> = {};

    for (const a of alertLog) {
      if (a.severity >= 90)      bySeverity.critical++;
      else if (a.severity >= 75) bySeverity.high++;
      else if (a.severity >= 60) bySeverity.medium++;
      else                       bySeverity.low++;

      byRule[a.rule_triggered] = (byRule[a.rule_triggered] ?? 0) + 1;
    }

    return {
      total_alerts: alertLog.length,
      by_severity: bySeverity,
      by_rule: byRule,
    };
  })

  .listen(PORT);

// ─── Startup ──────────────────────────────────────────────────────────────────

console.log(`
╔══════════════════════════════════════════════╗
║   SentinelGuard Webhook Dispatcher v0.1.0    ║
╚══════════════════════════════════════════════╝

Listening on http://localhost:${PORT}

Endpoints:
  POST /dispatch   ← watcher sends AlertEvent here
  POST /test       ← fire a test alert (verify Discord)
  GET  /alerts     ← last 100 dispatched alerts
  GET  /stats      ← alert counts by severity/rule
  GET  /health     ← service status + target config

Targets:
  Discord:   ${process.env.DISCORD_WEBHOOK_URL  ? "✅ configured" : "⚠️  DISCORD_WEBHOOK_URL not set"}
  Circle:    ${process.env.CIRCLE_API_KEY        ? "✅ configured" : "⚠️  CIRCLE_API_KEY not set (integration point)"}
  Wormhole:  ${process.env.WORMHOLE_API_KEY      ? "✅ configured" : "⚠️  WORMHOLE_API_KEY not set (integration point)"}
  Telegram:  ${process.env.TELEGRAM_BOT_TOKEN    ? "✅ configured" : "⚠️  TELEGRAM_BOT_TOKEN not set (optional)"}

To test Discord: curl -X POST http://localhost:${PORT}/test
`);
