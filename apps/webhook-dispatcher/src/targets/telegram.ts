import type { AlertEvent } from "../types.ts";

function ruleLabel(rule: string): string {
  switch (rule) {
    case "FlashLoanDrain":     return "Flash Loan + Drain";
    case "TvlVelocity":        return "TVL Velocity Drop";
    case "BridgeOutflowSpike": return "Bridge Outflow Spike";
    default: return rule;
  }
}

export async function sendTelegramAlert(alert: AlertEvent): Promise<void> {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) return; // silently skip if not configured

  const severity = alert.severity >= 90 ? "🔴 CRITICAL"
    : alert.severity >= 75 ? "🟠 HIGH"
    : alert.severity >= 60 ? "🟡 MEDIUM" : "🔵 LOW";

  const txSig = alert.trigger_tx_signatures[0] ?? "";
  const explorerLink = txSig
    ? `https://explorer.solana.com/tx/${txSig}`
    : null;

  const text = [
    `⚡ *SentinelGuard Alert*`,
    ``,
    `*Rule:* ${ruleLabel(alert.rule_triggered)}`,
    `*Severity:* ${severity} (${alert.severity}/99)`,
    `*At Risk:* $${alert.estimated_at_risk_usd.toLocaleString("en-US", { maximumFractionDigits: 0 })} USDC`,
    `*Protocol:* \`${alert.protocol.slice(0, 16)}...\``,
    `*Slot:* ${alert.slot}`,
    explorerLink ? `*Tx:* [View on Explorer](${explorerLink})` : null,
    `*Alert ID:* \`${alert.alert_id_hex.slice(0, 16)}...\``,
  ].filter(Boolean).join("\n");

  await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      disable_web_page_preview: false,
    }),
  });

  console.log(`[Telegram] Alert sent to chat ${chatId}`);
}
