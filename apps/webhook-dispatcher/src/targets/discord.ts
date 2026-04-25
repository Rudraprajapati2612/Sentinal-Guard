// src/targets/discord.ts
//
// Sends a rich Discord embed when an alert fires.
// Get a webhook URL from: Discord server → channel settings → Integrations → Webhooks
// Set DISCORD_WEBHOOK_URL in .env — this actually fires during the demo.

import type { AlertEvent } from "../types.ts";

// Severity → Discord embed color (hex integer)
function severityColor(severity: number): number {
  if (severity >= 90) return 0xFF2020; // red — critical
  if (severity >= 75) return 0xFF8C00; // orange — high
  if (severity >= 60) return 0xFFD700; // yellow — medium
  return 0x36A0F4;                     // blue — low
}

// Severity → label
function severityLabel(severity: number): string {
  if (severity >= 90) return "🔴 CRITICAL";
  if (severity >= 75) return "🟠 HIGH";
  if (severity >= 60) return "🟡 MEDIUM";
  return "🔵 LOW";
}

// Rule → human readable
function ruleLabel(rule: string): string {
  switch (rule) {
    case "FlashLoanDrain":    return "Flash Loan + Drain";
    case "TvlVelocity":       return "TVL Velocity Drop";
    case "BridgeOutflowSpike": return "Bridge Outflow Spike";
    default: return rule;
  }
}

// Rule → emoji
function ruleEmoji(rule: string): string {
  switch (rule) {
    case "FlashLoanDrain":    return "⚡";
    case "TvlVelocity":       return "📉";
    case "BridgeOutflowSpike": return "🌉";
    default: return "⚠️";
  }
}

export async function sendDiscordAlert(alert: AlertEvent): Promise<void> {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;

  if (!webhookUrl) {
    console.warn("[Discord] DISCORD_WEBHOOK_URL not set — skipping");
    return;
  }

  // Build explorer links for the first trigger tx
  const txSig = alert.trigger_tx_signatures[0] ?? "unknown";
  const explorerUrl = `https://explorer.solana.com/tx/${txSig}`;
  const protocolShort = alert.protocol.slice(0, 8) + "...";

  const embed = {
    title: `${ruleEmoji(alert.rule_triggered)} SentinelGuard Alert`,
    description: `**${ruleLabel(alert.rule_triggered)}** detected on protocol \`${protocolShort}\`\n\nAn exploit pattern was detected. The protocol has been automatically paused.`,
    color: severityColor(alert.severity),
    fields: [
      {
        name: "Severity",
        value: `${severityLabel(alert.severity)} (${alert.severity}/99)`,
        inline: true,
      },
      {
        name: "Rule",
        value: ruleLabel(alert.rule_triggered),
        inline: true,
      },
      {
        name: "Est. At Risk",
        value: `$${alert.estimated_at_risk_usd.toLocaleString("en-US", { maximumFractionDigits: 0 })} USDC`,
        inline: true,
      },
      {
        name: "Protocol",
        value: `\`${alert.protocol}\``,
        inline: false,
      },
      {
        name: "Slot",
        value: `#${alert.slot.toLocaleString()}`,
        inline: true,
      },
      {
        name: "Detected at",
        value: new Date(alert.timestamp * 1000).toISOString(),
        inline: true,
      },
      {
        name: "Alert ID",
        value: `\`${alert.alert_id_hex.slice(0, 16)}...\``,
        inline: false,
      },
      {
        name: "Trigger Transaction",
        value: `[View on Explorer](${explorerUrl})\n\`${txSig.slice(0, 32)}...\``,
        inline: false,
      },
    ],
    footer: {
      text: `SentinelGuard Watcher · ${alert.watcher_pubkey.slice(0, 8)}...`,
    },
    timestamp: new Date(alert.timestamp * 1000).toISOString(),
  };

  const payload = {
    username: "SentinelGuard",
    avatar_url: "https://avatars.githubusercontent.com/u/35608259?s=200", // Solana logo
    embeds: [embed],
  };

  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`Discord webhook failed: ${response.status} ${body}`);
  }

  console.log(`[Discord] Alert sent: ${alert.alert_id_hex.slice(0, 16)}... severity=${alert.severity}`);
}
