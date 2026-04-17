// watcher/src/responder/pause.rs
//
// Builds and submits the pause_withdrawals instruction to the SentinelGuard
// Anchor program. This is the CRITICAL PATH — every millisecond matters.
//
// Design decisions:
//   - Uses send_transaction (skipPreflight=true) for speed
//   - Does NOT wait for confirmation before returning
//   - Confirmation check is spawned as a background task
//   - RPC client is nonblocking (async, no thread blocking)

use anyhow::Result;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signature,
    signer::Signer,
    transaction::Transaction,
};
use std::str::FromStr;
use tracing::{info, warn};

use crate::config::Config;
use crate::db::DbPool;
use crate::types::AlertEvent;

/// Submit the pause_withdrawals instruction.
/// Returns immediately after sending — confirmation runs in background.
pub async fn submit_pause(
    alert: &AlertEvent,
    cfg: &Config,
    db: &DbPool,
) -> Result<()> {
    if alert.severity < cfg.min_severity_to_pause {
        info!(
            "Severity {} below pause threshold {} — skipping on-chain pause",
            alert.severity, cfg.min_severity_to_pause
        );
        return Ok(());
    }

    let keypair = solana_sdk::signature::read_keypair_file(&cfg.watcher_keypair_path)
        .map_err(|e| anyhow::anyhow!("Keypair load failed: {}", e))?;

    let rpc = RpcClient::new_with_commitment(
        cfg.solana_rpc_url.clone(),
        CommitmentConfig::processed(), // fastest confirmation level
    );

    let program_id = Pubkey::from_str(&cfg.sentinel_program_id)
        .map_err(|e| anyhow::anyhow!("Invalid program ID: {}", e))?;

    let protocol_pubkey = Pubkey::from_str(&alert.protocol)
        .map_err(|e| anyhow::anyhow!("Invalid protocol pubkey: {}", e))?;

    // Derive the SentinelState PDA
    // seeds = [b"sentinel", protocol_address]
    let (sentinel_state_pda, _bump) = Pubkey::find_program_address(
        &[b"sentinel", protocol_pubkey.as_ref()],
        &program_id,
    );

    // Derive the AlertRecord PDA
    // seeds = [b"alert", alert_id]
    let (alert_record_pda, _bump) = Pubkey::find_program_address(
        &[b"alert", &alert.alert_id],
        &program_id,
    );

    // Build the pause_withdrawals instruction
    // Anchor discriminator: sha256("global:pause_withdrawals")[..8]
    let discriminator = anchor_discriminator("pause_withdrawals");

    let mut data = discriminator.to_vec();
    data.extend_from_slice(&alert.alert_id);           // alert_id: [u8; 32]
    data.push(alert.severity);                         // severity: u8
    // estimated_at_risk: u64 (convert USD to lamports equiv, 6 decimals)
    let at_risk_lamports = (alert.estimated_at_risk_usd * 1_000_000.0) as u64;
    data.extend_from_slice(&at_risk_lamports.to_le_bytes());

    let accounts = vec![
        AccountMeta::new(sentinel_state_pda, false),   // sentinel_state (mut)
        AccountMeta::new(alert_record_pda, false),      // alert_record (mut, init)
        AccountMeta::new(keypair.pubkey(), true),        // watcher (signer, mut)
        AccountMeta::new_readonly(solana_sdk::system_program::ID, false), // system_program
    ];

    let instruction = Instruction {
        program_id,
        accounts,
        data,
    };

    // Get recent blockhash
    let recent_blockhash = rpc.get_latest_blockhash().await
        .map_err(|e| anyhow::anyhow!("Failed to get blockhash: {}", e))?;

    let tx = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&keypair.pubkey()),
        &[&keypair],
        recent_blockhash,
    );

    // Send without waiting for confirmation (fire and forget for speed)
    let signature = rpc.send_transaction(&tx).await
        .map_err(|e| anyhow::anyhow!("Failed to send pause tx: {}", e))?;

    info!(
        "⚡ Pause tx sent | sig={} | protocol={} | alert={}",
        signature,
        &alert.protocol[..8],
        alert.alert_id_hex,
    );

    // Confirm in background — don't block the alert pipeline
    let alert_id_hex = alert.alert_id_hex.clone();
    let db2 = db.clone();
    let rpc2 = RpcClient::new(cfg.solana_rpc_url.clone());

    tokio::spawn(async move {
        match confirm_transaction(&rpc2, signature).await {
            Ok(()) => {
                info!("✅ Pause tx confirmed: {}", signature);
                let _ = crate::db::update_alert_on_chain_tx(
                    &db2,
                    &alert_id_hex,
                    &signature.to_string(),
                ).await;
            }
            Err(e) => {
                warn!("Pause tx not confirmed: {} — {}", signature, e);
            }
        }
    });

    Ok(())
}

/// Poll for transaction confirmation with timeout.
async fn confirm_transaction(rpc: &RpcClient, signature: Signature) -> Result<()> {
    let timeout = tokio::time::Duration::from_secs(30);
    let start = tokio::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow::anyhow!("Confirmation timeout after 30s"));
        }

        match rpc.get_signature_status(&signature).await {
            Ok(Some(Ok(()))) => return Ok(()),
            Ok(Some(Err(e))) => return Err(anyhow::anyhow!("Tx failed: {:?}", e)),
            Ok(None) => {
                // Not yet seen — wait and retry
                tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
            }
            Err(e) => {
                warn!("Status check error: {} — retrying", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(400)).await;
            }
        }
    }
}

/// Compute the 8-byte Anchor instruction discriminator.
/// sha256("global:{instruction_name}")[..8]
fn anchor_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{}", name).as_bytes());
    let hash = hasher.finalize();
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}
