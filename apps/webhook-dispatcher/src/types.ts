export type RuleType= |"FlashLoanDrain" | "TvlVelocity" | "BridgeOutFlowSpike" ;

export interface AlertEvent{
  alert_id : number[],   // [u8;32] -> Json Entry  
  alert_id_hex : string,
  protocol : string,
  severity : number,
  rule_triggered : RuleType,
  estimated_at_risk_usd : number,
  trigger_tx_signatures: string[];
  slot: number;
  timestamp: number;           // unix seconds
  watcher_pubkey: string;


}


export interface DispatchResult {
  alert_id_hex: string;
  dispatched_to: string[];
  failed: string[];
  timestamp: string;
}
