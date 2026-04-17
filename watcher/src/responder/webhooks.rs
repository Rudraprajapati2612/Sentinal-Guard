// watcher/src/responder/webhooks.rs
//
// Two jobs:
//   1. Publish AlertEvent to Kafka topic (durable log — replay, audit, multi-consumer)
//   2. HTTP POST to Bun webhook-dispatcher service (fan-out to Discord/Circle/Wormhole)
//
// Why Kafka HERE (not in geyser.rs or detection engine):
//   AlertEvents are low-volume (~0-5/day in normal operation).
//   Kafka gives us:
//     a) Durable replay — if the Bun dispatcher is down, alerts are not lost
//     b) Audit log — every alert ever fired, forever, replayable
//     c) Multi-consumer — future: separate risk analysis service, customer alerting
//   We do NOT put raw transactions in Kafka because:
//     - Volume is too high (100k+ tx/day) for hackathon infra
//     - Latency added (5-20ms) would hurt detection speed
//     - The broadcast channel handles fan-out within this process already

use anyhow::Result;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::AlertEvent;

/// Dispatch an alert:
///   1. Publish to Kafka (fire and verify)
///   2. POST to Bun webhook dispatcher
pub async fn dispatch(alert: &AlertEvent, cfg: &Config) -> Result<()> {
    let payload = serde_json::to_string(alert)?;

    let (kafka_result, http_result) = tokio::join!(
        publish_to_kafka(&payload, cfg),
        post_to_dispatcher(&payload, cfg),
    );

    if let Err(e) = kafka_result {
        warn!("Kafka publish failed for {}: {}", alert.alert_id_hex, e);
        // Non-fatal — alert is already in DB, will be replayed manually if needed
    }

    if let Err(e) = http_result {
        warn!("Webhook dispatch failed for {}: {}", alert.alert_id_hex, e);
    }

    Ok(())
}

async fn publish_to_kafka(payload: &str, cfg: &Config) -> Result<()> {
    let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &cfg.kafka_brokers)
        .set("message.timeout.ms", "5000")
        .set("acks", "1") // leader ack only — speed over durability for alerts
        .create()?;

    producer.send(
        FutureRecord::to(&cfg.kafka_alert_topic)
            .payload(payload.as_bytes())
            .key("sentinel_alert"),
        Duration::from_secs(5),
    )
    .await
    .map_err(|(e, _)| anyhow::anyhow!("Kafka send failed: {:?}", e))?;

    info!("Alert published to Kafka topic: {}", cfg.kafka_alert_topic);
    Ok(())
}

async fn post_to_dispatcher(payload: &str, cfg: &Config) -> Result<()> {
    let client = Client::new();
    let url = format!("{}/dispatch", cfg.webhook_dispatcher_url);

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(payload.to_string())
        .timeout(Duration::from_secs(5))
        .send()
        .await?;

    if response.status().is_success() {
        info!("Webhook dispatcher notified: {}", url);
    } else {
        warn!(
            "Webhook dispatcher returned {}: {}",
            response.status(),
            url
        );
    }

    Ok(())
}
