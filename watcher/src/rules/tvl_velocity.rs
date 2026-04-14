// watcher/src/rules/tvl_velocity.rs
//
// Rule 2 — TVL Velocity Check
//
// Fires if TVL drops more than `threshold` fraction in 3 slots (~1.2 seconds).
// Score scales with the severity of the drop, capped at 99.

use crate::types::SlotSnapshot;

pub fn score(window: &[&SlotSnapshot], threshold: f64) -> u8 {
    if window.len() < 3 {
        return 0;
    }

    // Look at the last 3 slots only
    let recent_start = window.len().saturating_sub(3);
    let recent = &window[recent_start..];

    let oldest_tvl = recent.first().map(|s| s.tvl_usd).unwrap_or(0.0);
    let newest_tvl = recent.last().map(|s| s.tvl_usd).unwrap_or(0.0);

    if oldest_tvl <= 0.0 {
        return 0;
    }

    let drop_fraction = (oldest_tvl - newest_tvl) / oldest_tvl;

    if drop_fraction > threshold {
        // Base score 75 at threshold, scales up with drop severity
        let raw = 75.0 + (drop_fraction - threshold) * 100.0;
        raw.min(99.0) as u8
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SlotSnapshot;

    fn snap(slot: u64, tvl: f64) -> SlotSnapshot {
        SlotSnapshot {
            slot,
            protocol: "test".into(),
            tvl_usd: tvl,
            transactions: vec![],
            bridge_outflow_usd: 0.0,
            timestamp: 0,
        }
    }

    #[test]
    fn small_drop_returns_zero() {
        let s = vec![snap(0, 1_000_000.0), snap(1, 990_000.0), snap(2, 985_000.0)];
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        assert_eq!(score(&r, 0.20), 0);
    }

    #[test]
    fn exact_threshold_fires() {
        let s = vec![snap(0, 1_000_000.0), snap(1, 900_000.0), snap(2, 800_000.0)];
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        let sc = score(&r, 0.20);
        assert!(sc >= 75, "expected >= 75, got {}", sc);
    }

    #[test]
    fn catastrophic_drop_caps_at_99() {
        let s = vec![snap(0, 1_000_000.0), snap(1, 500_000.0), snap(2, 10_000.0)];
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        assert_eq!(score(&r, 0.20), 99);
    }
}
