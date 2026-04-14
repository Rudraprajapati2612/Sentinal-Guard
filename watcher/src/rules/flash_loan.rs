
use crate::types::SlotSnapshot;

pub fn score(window: &[&SlotSnapshot]) -> u8 {
    if window.len() < 2 {
        return 0;
    }

    // Check last 5 slots (or all if window is shorter)
    let recent_start = window.len().saturating_sub(5);
    let recent = &window[recent_start..];

    let has_flash_loan = recent
        .iter()
        .any(|snap| snap.transactions.iter().any(|tx| tx.is_flash_loan));

    if !has_flash_loan {
        return 0;
    }

    let oldest_tvl = recent.first().map(|s| s.tvl_usd).unwrap_or(0.0);
    let newest_tvl = recent.last().map(|s| s.tvl_usd).unwrap_or(0.0);

    if oldest_tvl <= 0.0 {
        return 0;
    }

    let drop_fraction = (oldest_tvl - newest_tvl) / oldest_tvl;

    if drop_fraction > 0.15 {
        90
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ParsedTransaction, SlotSnapshot};

    fn make_snap(slot: u64, tvl: f64, flash: bool) -> SlotSnapshot {
        SlotSnapshot {
            slot,
            protocol: "test".into(),
            tvl_usd: tvl,
            transactions: vec![ParsedTransaction {
                slot,
                signature: format!("SIG{}", slot),
                program_ids: vec![],
                token_deltas: vec![],
                cpi_depth: 0,
                log_messages: vec![],
                is_flash_loan: flash,
                fee_payer: "FEE".into(),
                timestamp: 0,
            }],
            bridge_outflow_usd: 0.0,
            timestamp: 0,
        }
    }

    #[test]
    fn no_flash_loan_returns_zero() {
        let s: Vec<_> = (0..5).map(|i| make_snap(i, 1_000_000.0, false)).collect();
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        assert_eq!(score(&r), 0);
    }

    #[test]
    fn flash_loan_no_tvl_drop_returns_zero() {
        let s: Vec<_> = (0..5).map(|i| make_snap(i, 1_000_000.0, i == 2)).collect();
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        assert_eq!(score(&r), 0);
    }

    #[test]
    fn flash_loan_with_drain_fires_90() {
        let tvls = [1_000_000.0, 950_000.0, 850_000.0, 750_000.0, 700_000.0];
        let s: Vec<_> = tvls.iter().enumerate()
            .map(|(i, &t)| make_snap(i as u64, t, i == 1))
            .collect();
        let r: Vec<&SlotSnapshot> = s.iter().collect();
        assert_eq!(score(&r), 90);
    }
}
