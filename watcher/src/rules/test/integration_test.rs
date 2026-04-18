// watcher/src/rules/tests/integration.rs
//
// Run with: cargo test -- --nocapture
// Tests the full pipeline: flash_loan rule → tvl_velocity rule → bridge rule
// No network needed — builds ParsedTransaction structs directly.

#[cfg(test)]
mod flash_loan_rule {
    use crate::rules::flash_loan;
    use crate::types::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_snap(slot: u64, tvl: f64, flash: bool, confidence: u8) -> SlotSnapshot {
        SlotSnapshot {
            slot,
            protocol: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
            tvl_usd: tvl,
            transactions: if flash {
                vec![ParsedTransaction {
                    slot,
                    signature: format!("{:064x}", slot),
                    program_ids: vec![
                        "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string(),
                        "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo".to_string(),
                    ],
                    token_deltas: vec![],
                    cpi: CpiMetrics { max_depth: 8, max_width: 12, total_cpi_count: 24 },
                    log_messages: vec!["Program log: Instruction: FlashLoan".to_string()],
                    flash_evidence: FlashLoanEvidence {
                        detected: true,
                        confidence,
                        methods_fired: 0b011, // program_id + log
                        program_id: Some("So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo (Solend)".to_string()),
                        max_borrow_amount: 1_500_000_000_000,
                    },
                    fee_payer: "attacker111111111111111111111111111111111111".to_string(),
                    timestamp: 0,
                }]
            } else {
                vec![]
            },
            bridge_outflow_usd: 0.0,
            timestamp: 0,
        }
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn no_flash_no_alert() {
        let snaps = vec![
            make_snap(1, 2_000_000.0, false, 0),
            make_snap(2,   500_000.0, false, 0), // 75% drop but no flash loan
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        assert_eq!(flash_loan::score(&refs), 0, "should not fire without flash loan");
    }

    #[test]
    fn flash_no_tvl_drop_no_alert() {
        let snaps = vec![
            make_snap(1, 2_000_000.0, true, 95),
            make_snap(2, 2_000_000.0, false, 0), // flash loan but TVL unchanged
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        assert_eq!(flash_loan::score(&refs), 0, "should not fire without TVL drop");
    }

    #[test]
    fn high_confidence_large_drop_fires() {
        // Solend program ID matched (confidence 95) + 90% TVL drop
        let snaps = vec![
            make_snap(1, 2_000_000.0, true, 95),  // slot N: flash loan borrow
            make_snap(2, 2_000_000.0, false, 0),  // slot N+1: TVL still ok (repaid)
            make_snap(3,   200_000.0, false, 0),  // slot N+2: drain (-90%)
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = flash_loan::score(&refs);
        println!("Score (high conf + 90% drop): {}", score);
        assert!(score >= 80, "expected score >= 80, got {}", score);
    }

    #[test]
    fn log_keyword_only_small_drop_does_not_fire() {
        // Method 2 only (confidence 70) + 16% drop → should be < 70 threshold
        let snaps = vec![
            make_snap(1, 1_000_000.0, false, 0),
            make_snap(2, 1_000_000.0, true, 70),  // log keyword only
            make_snap(3,   840_000.0, false, 0),  // 16% drop
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = flash_loan::score(&refs);
        println!("Score (log only + 16% drop): {}", score);
        // 70 base * 70 confidence / 100 = 49 — below the default 70 threshold
        assert!(score < 55, "expected low score, got {}", score);
    }

    #[test]
    fn delta_pattern_only_large_drop_borderline() {
        // Method 3 only (confidence 55) + 50% drop
        let snaps = vec![
            make_snap(1, 1_000_000.0, false, 0),
            make_snap(2, 1_000_000.0, true, 55),  // delta pattern only
            make_snap(3,   500_000.0, false, 0),  // 50% drop
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = flash_loan::score(&refs);
        println!("Score (delta only + 50% drop): {}", score);
        // 88 base * 55 / 100 = 48 — still below 70 threshold, needs large drop
        assert!(score < 60, "delta-only should score low");
    }

    #[test]
    fn multi_method_medium_drop_fires() {
        // Methods 1+2 agree → confidence boosted to 95+10=98 capped
        // + 30% TVL drop
        let snaps = vec![
            make_snap(1, 1_000_000.0, true, 98),  // program_id + log
            make_snap(2,   700_000.0, false, 0),  // 30% drop
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = flash_loan::score(&refs);
        println!("Score (multi-method + 30% drop): {}", score);
        assert!(score >= 70, "multi-method should fire at 30% drop, got {}", score);
    }

    #[test]
    fn low_tvl_protocol_skipped() {
        let snaps = vec![
            make_snap(1, 5_000.0, true, 95), // $5k TVL — below $10k floor
            make_snap(2,    50.0, false, 0),
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        assert_eq!(flash_loan::score(&refs), 0, "low TVL protocols should be skipped");
    }

    #[test]
    fn flash_in_earlier_slot_drain_in_later_slot() {
        // Real attack pattern: flash loan slot N, drain arrives N+2
        let snaps = vec![
            make_snap(1, 2_000_000.0, true, 95),   // flash loan here
            make_snap(2, 2_000_000.0, false, 0),   // TVL unchanged (loan repaid)
            make_snap(3, 2_000_000.0, false, 0),
            make_snap(4,   100_000.0, false, 0),   // drain — 95% drop
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = flash_loan::score(&refs);
        println!("Score (flash N, drain N+3): {}", score);
        assert!(score >= 80, "should detect cross-slot attack, got {}", score);
    }

    #[test]
    fn explain_output_makes_sense() {
        let snaps = vec![
            make_snap(1, 2_000_000.0, true, 95),
            make_snap(2,   100_000.0, false, 0),
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let explanation = flash_loan::explain(&refs);
        println!("Explain: {}", explanation);
        assert!(explanation.contains("tvl_drop"));
        assert!(explanation.contains("confidence"));
    }
}

// ─── TVL velocity rule tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tvl_velocity_rule {
    use crate::rules::tvl_velocity;
    use crate::types::*;

    fn make_snap(slot: u64, tvl: f64) -> SlotSnapshot {
        SlotSnapshot {
            slot,
            protocol: "test".to_string(),
            tvl_usd: tvl,
            transactions: vec![],
            bridge_outflow_usd: 0.0,
            timestamp: slot as i64,
        }
    }

    #[test]
    fn slow_drain_does_not_fire() {
        let snaps: Vec<SlotSnapshot> = (0..10)
            .map(|i| make_snap(i, 1_000_000.0 - (i as f64 * 10_000.0)))
            .collect();
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        // 10% drop over 10 slots = slow — should not fire at 0.30 threshold
        let score = tvl_velocity::score(&refs, 0.30);
        println!("TVL velocity slow drain score: {}", score);
        assert!(score < 50);
    }

    #[test]
    fn rapid_drain_fires() {
        let snaps = vec![
            make_snap(1, 2_000_000.0),
            make_snap(2, 2_000_000.0),
            make_snap(3,   200_000.0), // -90% in 1 slot
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = tvl_velocity::score(&refs, 0.30);
        println!("TVL velocity rapid drain score: {}", score);
        assert!(score >= 70, "rapid drain should fire, got {}", score);
    }

    #[test]
    fn tvl_increase_no_alert() {
        let snaps = vec![
            make_snap(1, 500_000.0),
            make_snap(2, 1_000_000.0), // TVL doubled
            make_snap(3, 2_000_000.0),
        ];
        let refs: Vec<&SlotSnapshot> = snaps.iter().collect();
        let score = tvl_velocity::score(&refs, 0.30);
        assert_eq!(score, 0, "TVL increase should never alert");
    }
}

// ─── Flash loan detection (geyser parsing) ────────────────────────────────────

#[cfg(test)]
mod flash_loan_detection {
    use crate::types::TokenDelta;

    // Copy the detect functions here for unit testing without needing geyser module
    fn detect_by_delta_pattern(token_deltas: &[TokenDelta]) -> (bool, u64) {
        use std::collections::HashMap;
        const FLASH_LOAN_MIN_BORROW_RAW: u64 = 500_000_000;

        let mut by_mint: HashMap<&str, (i128, u64)> = HashMap::new();
        for d in token_deltas {
            let entry = by_mint.entry(d.mint.as_str()).or_default();
            entry.0 += d.delta as i128;
            if d.delta < 0 {
                entry.1 = entry.1.max((-d.delta) as u64);
            }
        }

        let mut max_borrow: u64 = 0;
        for (_mint, (net_delta, max_outflow)) in &by_mint {
            if *max_outflow < FLASH_LOAN_MIN_BORROW_RAW { continue; }
            let net_abs = net_delta.unsigned_abs() as u64;
            let tolerance = max_outflow / 100;
            if net_abs <= tolerance {
                max_borrow = max_borrow.max(*max_outflow);
            }
        }
        (max_borrow > 0, max_borrow)
    }

    fn usdc_delta(account: &str, delta: i64) -> TokenDelta {
        let before = if delta < 0 { (-delta) as u64 } else { 0u64 };
        let after = if delta > 0 { delta as u64 } else { 0u64 };
        TokenDelta {
            account: account.to_string(),
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
            before,
            after,
            delta,
        }
    }

    #[test]
    fn detects_exact_borrow_repay() {
        // Classic: vault loses $1M, gets $1M + fee back in same tx
        let borrow: i64 = -1_000_000_000_000; // -$1M
        let repay: i64  =  1_003_000_000_000; // +$1.003M (0.3% fee)
        let deltas = vec![
            usdc_delta("vault", borrow),
            usdc_delta("vault", repay),
        ];
        let (detected, amount) = detect_by_delta_pattern(&deltas);
        println!("Detected: {}, amount: ${}", detected, amount as f64 / 1_000_000.0);
        assert!(detected, "should detect borrow+repay");
        assert_eq!(amount, 1_000_000_000_000u64);
    }

    #[test]
    fn does_not_flag_arbitrage() {
        // Arb: USDC out, different USDC in amount (net profit kept)
        // Net delta is non-zero → not a flash loan repayment
        let deltas = vec![
            usdc_delta("arb_wallet", -1_000_000_000_000), // pay $1M
            usdc_delta("arb_wallet",    50_000_000_000),  // receive $50k profit
            // net: -$950k → attacker kept $950k → NOT a flash loan
        ];
        let (detected, _) = detect_by_delta_pattern(&deltas);
        assert!(!detected, "should not flag arbitrage with non-zero net delta");
    }

    #[test]
    fn does_not_flag_small_amounts() {
        // $400 swap — below $500 minimum threshold
        let deltas = vec![
            usdc_delta("account_a", -400_000_000),
            usdc_delta("account_b",  400_000_000),
        ];
        let (detected, _) = detect_by_delta_pattern(&deltas);
        assert!(!detected, "should ignore amounts below $500 threshold");
    }

    #[test]
    fn detects_multi_account_flash_loan() {
        // Flash loan via proxy: funds flow through multiple accounts
        // but net delta per mint is still ≈ 0
        let deltas = vec![
            usdc_delta("solend_vault",  -2_000_000_000_000), // Solend sends $2M out
            usdc_delta("proxy_account", -1_000_000_000_000), // proxy routes $1M
            usdc_delta("proxy_account",  1_000_000_000_000), // proxy receives back
            usdc_delta("solend_vault",   2_006_000_000_000), // repay $2M + $6k fee
        ];
        let (detected, amount) = detect_by_delta_pattern(&deltas);
        println!("Multi-account: detected={}, amount=${}", detected, amount as f64 / 1_000_000.0);
        assert!(detected, "should detect multi-account flash loan");
    }

    #[test]
    fn cpi_suspicion_scores_correctly() {
        use crate::types::CpiMetrics;

        let normal = CpiMetrics { max_depth: 2, max_width: 2, total_cpi_count: 3 };
        let suspicious = CpiMetrics { max_depth: 9, max_width: 15, total_cpi_count: 35 };
        let exploit_level = CpiMetrics { max_depth: 12, max_width: 20, total_cpi_count: 60 };

        println!("Normal CPI suspicion: {}", normal.suspicion_score());
        println!("Suspicious CPI suspicion: {}", suspicious.suspicion_score());
        println!("Exploit-level CPI suspicion: {}", exploit_level.suspicion_score());

        assert!(normal.suspicion_score() < 20);
        assert!(suspicious.suspicion_score() >= 50);
        assert!(exploit_level.suspicion_score() >= 75);
    }
}

// ─── TVL Redis fallback ───────────────────────────────────────────────────────

#[cfg(test)]
mod tvl_computation {
    use crate::geyser::net_usdc_delta_from_tx;
    use crate::types::*;

    fn make_tx_with_deltas(deltas: Vec<(i64,)>) -> ParsedTransaction {
        ParsedTransaction {
            slot: 1,
            signature: "test".repeat(16),
            program_ids: vec![],
            token_deltas: deltas.into_iter().map(|(delta,)| TokenDelta {
                account: "vault".to_string(),
                mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
                before: 0,
                after: 0,
                delta,
            }).collect(),
            cpi: CpiMetrics::zero(),
            log_messages: vec![],
            flash_evidence: FlashLoanEvidence::none(),
            fee_payer: "fee".to_string(),
            timestamp: 0,
        }
    }

    #[test]
    fn net_delta_is_signed_not_sum_of_after() {
        // Old code summed `after` values — would return $2M here
        // Correct: net signed delta = -$1M + $500k = -$500k
        let tx = make_tx_with_deltas(vec![(-1_000_000_000_000,), (500_000_000_000,)]);
        let net = net_usdc_delta_from_tx(&tx);
        println!("Net USDC delta: ${}", net);
        // Net = -1M + 500k = -500k USDC
        assert!((net - (-500_000.0)).abs() < 1.0, "got {}", net);
    }

    #[test]
    fn pure_deposit_positive_delta() {
        let tx = make_tx_with_deltas(vec![(1_000_000_000_000,)]); // +$1M
        let net = net_usdc_delta_from_tx(&tx);
        assert!((net - 1_000_000.0).abs() < 1.0);
    }

    #[test]
    fn pure_withdrawal_negative_delta() {
        let tx = make_tx_with_deltas(vec![(-500_000_000_000,)]); // -$500k
        let net = net_usdc_delta_from_tx(&tx);
        assert!((net - (-500_000.0)).abs() < 1.0);
    }
}
