// watcher/src/rules/bridge_spike.rs
//
// Rule 3 — Bridge Outflow Spike
//
// Fires if the current slot's bridge_outflow_usd exceeds the rolling
// average from the window by `multiplier` times.
//
// In production (Phase 2), replace the window-average with the 10-minute
// rolling average from PostgreSQL via db::get_bridge_outflow_avg().

use crate::types::SlotSnapshot;

pub fn score(window: &[&SlotSnapshot], multiplier: f64) -> u8 {
    if window.len() < 5 {
        return 0; // need enough history for a meaningful average
    }

    let current_outflow = window.last()
        .map(|s| s.bridge_outflow_usd)
        .unwrap_or(0.0);

    if current_outflow < 10_000.0 {
        return 0; // ignore noise below $10k
    }

    // Average outflow across all but the last slot
    let history = &window[..window.len() - 1];
    let avg = history.iter().map(|s| s.bridge_outflow_usd).sum::<f64>()
        / history.len() as f64;

    if avg < 1_000.0 {
        // No meaningful baseline — large outflow from cold wallet is 80
        if current_outflow > 500_000.0 {
            return 80;
        }
        return 0;
    }

    let ratio = current_outflow / avg;

    if ratio > multiplier * 2.0 {
        95
    } else if ratio > multiplier {
        85
    } else {
        0
    }
}
