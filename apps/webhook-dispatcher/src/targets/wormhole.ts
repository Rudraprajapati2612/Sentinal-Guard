import type { AlertEvent } from "../types.ts";

export interface WormholeHaltResult {
  attempted: boolean;
  success: boolean;
  message: string;
  vaa_block_request_id?: string;
}

export async function requestWormholeHalt(alert: AlertEvent): Promise<WormholeHaltResult> {
  const apiKey = process.env.WORMHOLE_API_KEY;
  const baseUrl = process.env.WORMHOLE_API_URL ?? "https://api.wormholescan.io";

  // Only halt for high severity bridge outflow or flash loan drain
  if (alert.severity < 75) {
    return { attempted: false, success: false, message: "Severity below halt threshold" };
  }

  if (!apiKey) {
    console.warn("[Wormhole] WORMHOLE_API_KEY not set");
    console.log(`[Wormhole] ⚠️  WOULD request bridge halt for protocol ${alert.protocol.slice(0, 8)}...`);
    console.log(`[Wormhole] ⚠️  This would block VAA signatures for transactions from this protocol`);
    console.log(`[Wormhole] ⚠️  Alert: ${alert.alert_id_hex.slice(0, 16)}... | Rule: ${alert.rule_triggered}`);
    console.log(`[Wormhole] ⚠️  Set WORMHOLE_API_KEY in .env to enable real halt requests`);
    return {
      attempted: false,
      success: false,
      message: "WORMHOLE_API_KEY not configured — halt logged but not submitted",
    };
  }

  const haltPayload = {
    requestId: alert.alert_id_hex,
    sourceChain: "solana",
    sourceAddress: alert.protocol,
    reason: "sentinel_guard_exploit_detection",
    severity: alert.severity,
    ruleTriggered: alert.rule_triggered,
    estimatedAtRiskUsd: alert.estimated_at_risk_usd,
    detectedAtSlot: alert.slot,
    triggerSignatures: alert.trigger_tx_signatures,
  };

  try {
    const response = await fetch(`${baseUrl}/v1/guardian/halt-request`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(haltPayload),
      signal: AbortSignal.timeout(5000),
    });

    if (response.ok) {
      const data = await response.json() as { requestId?: string };
      console.log(`[Wormhole] ✅ Halt request submitted: ${data.requestId}`);
      return {
        attempted: true,
        success: true,
        message: "Bridge halt request submitted",
        vaa_block_request_id: data.requestId,
      };
    } else {
      const body = await response.text();
      return { attempted: true, success: false, message: `Wormhole API ${response.status}: ${body}` };
    }
  } catch (err) {
    return { attempted: true, success: false, message: `Network error: ${err}` };
  }
}
