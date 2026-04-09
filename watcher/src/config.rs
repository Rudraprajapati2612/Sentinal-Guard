use anyhow ::{Context,Result};

#[derive(Debug, Clone)]

pub struct Config{
     // ── Solana ────────────────────────────────────────────────────────────────
    /// Helius Geyser gRPC endpoint, e.g. "https://atlas-devnet.helius-rpc.com"
    pub geyser_endpoint: String,
    /// Helius API key (used as x-token header for Geyser auth)
    pub helius_api_key: String,
    /// Standard JSON-RPC endpoint for submitting transactions
    pub solana_rpc_url: String,
    /// Path to watcher keypair JSON file
    pub watcher_keypair_path: String,
    /// Deployed SentinelGuard program ID
    pub sentinel_program_id: String,
    /// Program IDs to watch — comma-separated in env var
    pub watched_programs: Vec<String>,
    // ── Redis ─────────────────────────────────────────────────────────────────
    /// Redis connection URL, e.g. "redis://127.0.0.1:6379"
    pub redis_url: String,
    /// TTL in seconds for alert dedup keys (default: 300 = 5 min)
    pub alert_dedup_ttl_secs: u64,
 
    // ── Kafka ─────────────────────────────────────────────────────────────────
    /// Kafka broker list, e.g. "localhost:9092"
    pub kafka_brokers: String,
    /// Topic for raw parsed transactions (high-volume)
    pub kafka_tx_topic: String,
    /// Topic for fired alert events (low-volume, durable)
    pub kafka_alert_topic: String,
 
    // ── PostgreSQL ────────────────────────────────────────────────────────────
    pub database_url: String,
    /// Max DB connections in pool
    pub db_pool_size: u32,
 
    // ── API server ────────────────────────────────────────────────────────────
    pub api_port: u16,
 
    // ── Webhook dispatcher (Bun service) ─────────────────────────────────────
    pub webhook_dispatcher_url: String,
    
       // ── Detection thresholds ─────────────────────────────────────────────────
    /// TVL drop fraction to trigger Rule 2 (e.g. 0.20 = 20%)
    pub tvl_drop_threshold: f64,
    /// Bridge outflow spike multiplier for Rule 3 (e.g. 10.0 = 10×)
    pub bridge_spike_multiplier: f64,
    /// Minimum severity score to fire an on-chain pause (e.g. 75)
    pub min_severity_to_pause: u8,
    /// Minimum severity score to emit a public alert (e.g. 60)
    pub min_severity_to_publish: u8,
    /// Rolling window size in slots (default: 10 = ~4 seconds)
    pub window_size: usize,
}

pub fn load() -> Result<Config> {
    Ok(Config {
        // ── Required ─────────────────────────────────────────────────────────
        helius_api_key: required("HELIUS_API_KEY")?,
        sentinel_program_id: required("SENTINEL_PROGRAM_ID")?,
        database_url: required("DATABASE_URL")?,
 
        // ── Optional with sensible defaults ──────────────────────────────────
        geyser_endpoint: std::env::var("GEYSER_ENDPOINT")
            .unwrap_or_else(|_| "https://atlas-devnet.helius-rpc.com".to_string()),
 
        solana_rpc_url: std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string()),
 
        watcher_keypair_path: std::env::var("WATCHER_KEYPAIR_PATH")
            .unwrap_or_else(|_| "keys/watcher-keypair.json".to_string()),
 
        watched_programs: std::env::var("WATCHED_PROGRAMS")
            .unwrap_or_else(|_| "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
 
        // ── Redis ─────────────────────────────────────────────────────────────
        redis_url: std::env::var("REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
 
        alert_dedup_ttl_secs: std::env::var("ALERT_DEDUP_TTL_SECS")
            .unwrap_or_else(|_| "300".to_string())
            .parse()
            .unwrap_or(300),
 
        // ── Kafka ─────────────────────────────────────────────────────────────
        kafka_brokers: std::env::var("KAFKA_BROKERS")
            .unwrap_or_else(|_| "localhost:9092".to_string()),
 
        kafka_tx_topic: std::env::var("KAFKA_TX_TOPIC")
            .unwrap_or_else(|_| "sentinel.transactions".to_string()),
 
        kafka_alert_topic: std::env::var("KAFKA_ALERT_TOPIC")
            .unwrap_or_else(|_| "sentinel.alerts".to_string()),
 
        // ── DB ────────────────────────────────────────────────────────────────
        db_pool_size: std::env::var("DB_POOL_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10),
 
        // ── API ───────────────────────────────────────────────────────────────
        api_port: std::env::var("API_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080),
 
        webhook_dispatcher_url: std::env::var("WEBHOOK_DISPATCHER_URL")
            .unwrap_or_else(|_| "http://localhost:3001".to_string()),
 
        // ── Thresholds ────────────────────────────────────────────────────────
        tvl_drop_threshold: std::env::var("TVL_DROP_THRESHOLD")
            .unwrap_or_else(|_| "0.20".to_string())
            .parse()
            .unwrap_or(0.20),
 
        bridge_spike_multiplier: std::env::var("BRIDGE_SPIKE_MULTIPLIER")
            .unwrap_or_else(|_| "10.0".to_string())
            .parse()
            .unwrap_or(10.0),
 
        min_severity_to_pause: std::env::var("MIN_SEVERITY_TO_PAUSE")
            .unwrap_or_else(|_| "75".to_string())
            .parse()
            .unwrap_or(75),
 
        min_severity_to_publish: std::env::var("MIN_SEVERITY_TO_PUBLISH")
            .unwrap_or_else(|_| "60".to_string())
            .parse()
            .unwrap_or(60),
 
        window_size: std::env::var("WINDOW_SIZE")
            .unwrap_or_else(|_| "10".to_string())
            .parse()
            .unwrap_or(10),
    })
}
 
fn required(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| {
        format!("Required environment variable '{}' is not set.\nAdd it to your .env file.", key)
    })
}
