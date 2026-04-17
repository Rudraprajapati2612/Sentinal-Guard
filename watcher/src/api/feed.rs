// watcher/src/api/feed.rs
//
// Public threat feed API — runs inside the same Rust binary as the watcher.
// Shares the alert broadcast channel (zero IPC, zero serialization cost).
//
// Endpoints:
//   WS  /feed               — real-time alert stream (WebSocket)
//   GET /alerts             — last 100 alerts (REST)
//   GET /alerts/:protocol   — alerts for one protocol (REST)
//   GET /protocols          — all monitored protocols + current TVL from Redis
//   GET /health             — watcher health check

use axum::{
    extract::{Path, State, WebSocketUpgrade, ws::{Message, WebSocket}},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use redis::aio::ConnectionManager;
use std::sync::Arc;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::db::DbPool;
use crate::types::{AlertEvent, TvlCache};

// ─── App State ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    alert_tx: broadcast::Sender<AlertEvent>,
    db: DbPool,
    redis: ConnectionManager,
    cfg: Config,
}

pub async fn run(
    alert_tx: broadcast::Sender<AlertEvent>,
    db: DbPool,
    redis: ConnectionManager,
    cfg: Config,
) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        alert_tx,
        db,
        redis,
        cfg: cfg.clone(),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/feed",              get(ws_handler))
        .route("/alerts",            get(get_alerts))
        .route("/alerts/:protocol",  get(get_alerts_for_protocol))
        .route("/protocols",         get(get_protocols))
        .route("/health",            get(health))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", cfg.api_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Threat feed API listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}

// ─── WebSocket Handler ────────────────────────────────────────────────────────

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: Arc<AppState>) {
    let mut rx = state.alert_tx.subscribe();

    info!("WS client connected to threat feed");

    loop {
        match rx.recv().await {
            Ok(alert) => {
                // Only forward alerts above the publish threshold
                if alert.severity < state.cfg.min_severity_to_publish {
                    continue;
                }

                let json = match serde_json::to_string(&alert) {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Alert serialize error: {}", e);
                        continue;
                    }
                };

                if socket.send(Message::Text(json)).await.is_err() {
                    debug!("WS client disconnected");
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("WS feed lagged {} alerts", n);
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
}

// ─── REST Handlers ────────────────────────────────────────────────────────────

async fn get_alerts(
    State(state): State<Arc<AppState>>,
) -> Response {
    match crate::db::get_recent_alerts(&state.db, 100).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn get_alerts_for_protocol(
    Path(protocol): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    match crate::db::get_alerts_for_protocol(&state.db, &protocol, 50).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

async fn get_protocols(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut result = Vec::new();
    let mut redis = state.redis.clone();

    for protocol in &state.cfg.watched_programs {
        let key = format!("tvl:{}", protocol);
        let tvl_entry: Option<TvlCache> = redis::cmd("GET")
            .arg(&key)
            .query_async::<Option<String>>(&mut redis)
            .await
            .ok()
            .flatten()
            .and_then(|s| serde_json::from_str(&s).ok());

        result.push(serde_json::json!({
            "protocol": protocol,
            "tvl_usd": tvl_entry.as_ref().map(|t| t.tvl_usd).unwrap_or(0.0),
            "last_updated_slot": tvl_entry.as_ref().map(|t| t.slot),
        }));
    }

    Json(result)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
