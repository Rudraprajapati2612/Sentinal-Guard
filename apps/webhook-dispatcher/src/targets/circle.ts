import type { AlertEvent } from "../types.ts";

export interface CircleFreezeResult {
  attempted: boolean;
  success: boolean;
  message: string;
  freeze_request_id?: string;
}

export async function requestCircleFreeze(alert: AlertEvent): Promise<CircleFreezeResult> {
  const apiKey = process.env.CIRCLE_API_KEY;
  const baseUrl = process.env.CIRCLE_API_URL ?? "https://api.circle.com";

  // Only attempt if high severity (above 75) — Circle freeze is a nuclear option
  if (alert.severity < 75) {
    console.log(`[Circle] Severity ${alert.severity} < 75 — skipping freeze request`);
    return { attempted: false, success: false, message: "Severity below freeze threshold" };
  }

  if (!apiKey) {
    console.warn("[Circle] CIRCLE_API_KEY not set");
    console.log(`[Circle] ⚠️  WOULD freeze USDC associated with protocol ${alert.protocol.slice(0, 8)}...`);
    console.log(`[Circle] ⚠️  Estimated frozen amount: $${alert.estimated_at_risk_usd.toFixed(0)} USDC`);
    console.log(`[Circle] ⚠️  Alert ID: ${alert.alert_id_hex.slice(0, 16)}...`);
    console.log(`[Circle] ⚠️  Set CIRCLE_API_KEY in .env to enable real freeze requests`);
    return {
      attempted: false,
      success: false,
      message: "CIRCLE_API_KEY not configured — freeze logged but not submitted",
    };
  }

  // Construct freeze request
  // NOTE: Circle's actual compliance API endpoint may differ.
  // This follows Circle's documented REST API patterns.
  const freezePayload = {
    idempotencyKey: alert.alert_id_hex,
    reason: "exploit_detection",
    description: `SentinelGuard detected ${alert.rule_triggered} on Solana protocol ${alert.protocol}. Severity: ${alert.severity}/99. Estimated at-risk: $${alert.estimated_at_risk_usd.toFixed(0)} USDC.`,
    associatedAddresses: [alert.protocol, ...alert.trigger_tx_signatures],
    alertId: alert.alert_id_hex,
    severity: alert.severity,
    detectedAtSlot: alert.slot,
    detectedAtTimestamp: new Date(alert.timestamp * 1000).toISOString(),
  };

  try {
    const response = await fetch(`${baseUrl}/v1/compliance/freeze`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "X-Request-Id": alert.alert_id_hex,
      },
      body: JSON.stringify(freezePayload),
      signal: AbortSignal.timeout(5000), // 5s timeout
    });

    if (response.ok) {
      const data = await response.json() as { id?: string };
      console.log(`[Circle] ✅ Freeze request submitted: ${data.id}`);
      return {
        attempted: true,
        success: true,
        message: "Freeze request submitted successfully",
        freeze_request_id: data.id,
      };
    } else {
      const body = await response.text();
      console.error(`[Circle] Freeze request failed: ${response.status} ${body}`);
      return {
        attempted: true,
        success: false,
        message: `Circle API returned ${response.status}: ${body}`,
      };
    }
  } catch (err) {
    console.error(`[Circle] Freeze request error: ${err}`);
    return {
      attempted: true,
      success: false,
      message: `Network error: ${err}`,
    };
  }
}
