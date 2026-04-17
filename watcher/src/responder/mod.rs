// watcher/src/responder/mod.rs
pub mod pause;
pub mod webhooks;

use anyhow::Result;
use solana_sdk::signer::Signer;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::db::DbPool;
use crate::types::AlertEvent;

/// Listens on the alert channel and fires all responses in parallel:
///   1. On-chain pause tx (Rust, critical path)
///   2. Webhook fan-out (delegated to Bun dispatcher)
pub async fn run(
    cfg: Config,
    mut alert_rx: broadcast::Receiver<AlertEvent>,
    db: DbPool,
) -> Result<()> {
    // Load watcher keypair for signing pause transactions
    let keypair = solana_sdk::signature::read_keypair_file(&cfg.watcher_keypair_path)
        .map_err(|e| anyhow::anyhow!("Failed to load keypair from {}: {}", cfg.watcher_keypair_path, e))?;

    let rpc = solana_client::nonblocking::rpc_client::RpcClient::new(cfg.solana_rpc_url.clone());
    
    info!("Responder ready — watcher pubkey: {}", keypair.pubkey());

    loop {
        match alert_rx.recv().await {
            Ok(alert) => {
                info!(
                    "Responder received alert {} — severity {}",
                    alert.alert_id_hex, alert.severity
                );

                let cfg2 = cfg.clone();
                let db2 = db.clone();
                let alert2 = alert.clone();

                // Fire both responses in parallel — don't await sequentially
                tokio::spawn(async move {
                    let (pause_result, webhook_result) = tokio::join!(
                        pause::submit_pause(&alert2, &cfg2, &db2),
                        webhooks::dispatch(&alert2, &cfg2),
                    );

                    if let Err(e) = pause_result {
                        error!("On-chain pause FAILED for {}: {}", alert2.alert_id_hex, e);
                    }
                    if let Err(e) = webhook_result {
                        warn!("Webhook dispatch failed for {}: {}", alert2.alert_id_hex, e);
                    }
                });
            }

            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("Responder lagged — dropped {} alerts. THIS IS CRITICAL.", n);
            }

            Err(broadcast::error::RecvError::Closed) => {
                warn!("Alert channel closed — responder shutting down");
                break;
            }
        }
    }

    Ok(())
}
