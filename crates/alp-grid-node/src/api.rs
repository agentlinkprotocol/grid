//! Local HTTP JSON API on 127.0.0.1:7777, described by OpenAPI (served at `/openapi.json`).
//! Bearer token from `<data_dir>/api.token`. Public without token: `/healthz`, `/openapi.json`,
//! `/v1/atlas/stats`.

use std::sync::Arc;

use alp_grid_core::ids::AgentId;
use alp_grid_core::keys::{Bytes32, Bytes64, PublicKey};
use alp_grid_core::types::*;
use alp_grid_core::wire::{InboxAck, InboxMessage, VaultShard};
use alp_grid_core::Error as CoreError;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use utoipa::{OpenApi, ToSchema};

use crate::engine::*;
use crate::observer::{self, AtlasStats};

#[derive(Clone)]
pub struct ApiState {
    pub engine: Arc<Engine>,
    pub token: Arc<String>,
    pub observer: bool,
    pub listen_addrs: Arc<parking_lot::RwLock<Vec<String>>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    pub error: String,
}

pub struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(ApiError { error: self.1 })).into_response()
    }
}

impl From<CoreError> for AppError {
    fn from(e: CoreError) -> Self {
        let code = match &e {
            CoreError::NotFound => StatusCode::NOT_FOUND,
            CoreError::StaleVersion { .. } => StatusCode::CONFLICT,
            CoreError::Quota => StatusCode::TOO_MANY_REQUESTS,
            CoreError::Invalid { .. } | CoreError::Signature(_) | CoreError::Expired | CoreError::Encoding(_) | CoreError::ProofOfWork(_) => {
                StatusCode::BAD_REQUEST
            }
            CoreError::Other(_) => StatusCode::BAD_GATEWAY,
        };
        AppError(code, e.to_string())
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct NodeStatus {
    pub version: String,
    pub node_pubkey: PublicKey,
    pub operator_pubkey: PublicKey,
    pub operator_cert: OperatorCert,
    pub position: String,
    pub pow_nonce: u64,
    pub uptime_secs: u64,
    pub model: String,
    pub map_version: u32,
    pub map_zones: u64,
    pub map_hash: String,
    pub peers: usize,
    pub listen_addrs: Vec<String>,
    pub zones_held: usize,
    pub store: StoreStatsView,
    pub capacity_fill: f32,
    pub ledger_size: u64,
    pub ledger_root: String,
    pub own_agents: Vec<AgentId>,
    pub observer: bool,
    pub metrics: MetricsSnapshot,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct StoreStatsView {
    pub cards: u64,
    pub revocations: u64,
    pub zone_entries: u64,
    pub zones: u64,
    pub inbox_messages: u64,
    pub vault_shards: u64,
    pub ledger_entries: u64,
    pub bytes_on_disk: u64,
}

impl From<alp_grid_store::StoreStats> for StoreStatsView {
    fn from(s: alp_grid_store::StoreStats) -> Self {
        StoreStatsView {
            cards: s.cards,
            revocations: s.revocations,
            zone_entries: s.zone_entries,
            zones: s.zones,
            inbox_messages: s.inbox_messages,
            vault_shards: s.vault_shards,
            ledger_entries: s.ledger_entries,
            bytes_on_disk: s.bytes_on_disk,
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct EmbedRequest {
    pub texts: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct EmbedResponse {
    pub model: String,
    pub vectors: Vec<Vector>,
}

#[derive(Serialize, ToSchema)]
pub struct CardLookup {
    pub card: Option<Card>,
    pub revocation: Option<Revocation>,
}

#[derive(Deserialize, ToSchema)]
pub struct DepositRequest {
    pub to: AgentId,
    pub from_pubkey: PublicKey,
    /// Sealed box produced by the SDK (hex).
    pub sealed: Blob,
}

#[derive(Deserialize, ToSchema)]
pub struct FetchRequest {
    pub agent_pubkey: PublicKey,
    pub nonce: u64,
    pub auth: Bytes64,
}

#[derive(Serialize, ToSchema)]
pub struct FetchResponse {
    pub messages: Vec<InboxMessage>,
}

#[derive(Serialize, ToSchema)]
pub struct AckResponse {
    pub removed_copies: usize,
}

#[derive(Deserialize, ToSchema)]
pub struct VaultPutRequest {
    pub shards: Vec<VaultShard>,
}

#[derive(Deserialize, ToSchema)]
pub struct VaultSplitRequest {
    /// The encrypted snapshot (hex). The node never sees the plaintext.
    pub encrypted: Blob,
}

#[derive(Serialize, ToSchema)]
pub struct UnsignedShard {
    pub index: u8,
    pub total: u8,
    pub data_shards: u8,
    pub shard_hash: Bytes32,
    pub data: Blob,
}

#[derive(Serialize, ToSchema)]
pub struct VaultSplitResponse {
    pub shards: Vec<UnsignedShard>,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub struct LedgerQuery {
    pub from: Option<u64>,
    pub limit: Option<u32>,
}

#[derive(Serialize, ToSchema)]
pub struct LedgerPage {
    pub entries: Vec<LedgerEntry>,
    pub root: String,
    pub size: u64,
}

#[derive(Serialize, ToSchema)]
pub struct ZonesOfResponse {
    pub map_version: u32,
    pub zones: Vec<ZoneOfTrait>,
}

#[derive(Serialize, ToSchema)]
pub struct ZoneOfTrait {
    pub zone_id: u32,
    pub trait_indices: Vec<u8>,
}

#[derive(OpenApi)]
#[openapi(
    info(title = "The Grid local API", version = "1.0.0", description = "Local API of an Agent Link Protocol Atlas node. Agents sign; the node countersigns and talks to the Atlas.", license(name = "AGPL-3.0-only")),
    paths(healthz, status, publish_card, get_card, publish_ephemeral, publish_revocation, search, embed, zones_of, inbox_deposit, inbox_fetch, inbox_ack, vault_split, vault_put, vault_get, ledger, atlas_stats),
    components(schemas(ApiError, NodeStatus, Card, Filters, OperatorCert, Ephemeral, Revocation, RevocationTarget, RevokedBy, PublishReport, ZoneReport, SearchQuery, SearchResult, AgentResult, alp_grid_core::wire::SearchHit, EntryKind, EmbedRequest, EmbedResponse, CardLookup, DepositRequest, DepositReport, FetchRequest, FetchResponse, InboxMessage, InboxAck, AckResponse, VaultPutRequest, VaultSplitRequest, VaultSplitResponse, UnsignedShard, VaultShard, VaultPutReport, VaultGetReport, LedgerPage, LedgerEntry, LedgerEvent, Witness, AtlasStats, MetricsSnapshot, ZonesOfResponse, ZoneOfTrait, StoreStatsView)),
    tags((name = "node"), (name = "cards"), (name = "search"), (name = "inbox"), (name = "vault"), (name = "atlas"))
)]
pub struct ApiDoc;

pub fn openapi_json() -> String {
    ApiDoc::openapi().to_pretty_json().unwrap_or_default()
}

pub fn router(state: ApiState, cors_origins: &[String]) -> Router {
    let public = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/openapi.json",
            get(|| async { ([(header::CONTENT_TYPE, "application/json")], openapi_json()) }),
        )
        .route("/v1/atlas/stats", get(atlas_stats));
    let private = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/cards", post(publish_card))
        .route("/v1/cards/{agent_id}", get(get_card))
        .route("/v1/ephemerals", post(publish_ephemeral))
        .route("/v1/revocations", post(publish_revocation))
        .route("/v1/search", post(search))
        .route("/v1/embed", post(embed))
        .route("/v1/zones", post(zones_of))
        .route("/v1/inbox", post(inbox_deposit))
        .route("/v1/inbox/{agent_id}/fetch", post(inbox_fetch))
        .route("/v1/inbox/{agent_id}/ack", post(inbox_ack))
        .route("/v1/vault/shards", post(vault_split))
        .route("/v1/vault/{agent_id}", put(vault_put))
        .route("/v1/vault/{agent_id}/{snapshot}", get(vault_get))
        .route("/v1/ledger", get(ledger))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    let cors = if cors_origins.iter().any(|o| o == "*") {
        CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)
    } else {
        let origins: Vec<_> = cors_origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new().allow_origin(origins).allow_methods(Any).allow_headers(Any)
    };
    Router::new()
        .merge(public)
        .merge(private)
        .layer(axum::extract::DefaultBodyLimit::max(300 * 1024 * 1024))
        .layer(cors)
        .with_state(state)
}

async fn auth(State(st): State<ApiState>, headers: HeaderMap, req: axum::extract::Request, next: Next) -> Response {
    let ok = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t == st.token.as_str())
        .unwrap_or(false);
    if !ok {
        return AppError(StatusCode::UNAUTHORIZED, "missing or invalid bearer token (see <data_dir>/api.token)".into()).into_response();
    }
    next.run(req).await
}

#[utoipa::path(get, path = "/healthz", tag = "node", responses((status = 200, description = "alive")))]
async fn healthz() -> &'static str {
    "ok"
}

#[utoipa::path(get, path = "/v1/status", tag = "node", security(("bearer" = [])), responses((status = 200, body = NodeStatus)))]
async fn status(State(st): State<ApiState>) -> Result<Json<NodeStatus>, AppError> {
    let e = &st.engine;
    let store = e.store.stats().map_err(|x| AppError(StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;
    Ok(Json(NodeStatus {
        version: env!("CARGO_PKG_VERSION").into(),
        node_pubkey: e.identity.node.public(),
        operator_pubkey: e.identity.operator.public(),
        operator_cert: e.identity.cert.clone(),
        position: alp_grid_core::ids::Position::of_node(&e.identity.node.public()).0.to_hex(),
        pow_nonce: e.identity.pow_nonce,
        uptime_secs: e.now().saturating_sub(e.started_at),
        model: e.model().into(),
        map_version: e.map.version,
        map_zones: e.map.zones() as u64,
        map_hash: e.map.hash().to_hex(),
        peers: e.known_nodes().len(),
        listen_addrs: st.listen_addrs.read().clone(),
        zones_held: e.store.zones_held().len(),
        store: store.into(),
        capacity_fill: e.capacity.read().fill(),
        ledger_size: e.ledger.len(),
        ledger_root: e.ledger.root().to_hex(),
        own_agents: e.own_agents(),
        observer: st.observer,
        metrics: e.metrics.snapshot(),
    }))
}

#[utoipa::path(post, path = "/v1/cards", tag = "cards", security(("bearer" = [])), request_body = Card, responses((status = 200, body = PublishReport), (status = 400, body = ApiError), (status = 429, body = ApiError)))]
async fn publish_card(State(st): State<ApiState>, Json(card): Json<Card>) -> Result<Json<PublishReport>, AppError> {
    Ok(Json(st.engine.publish_card(card).await?))
}

#[utoipa::path(get, path = "/v1/cards/{agent_id}", tag = "cards", security(("bearer" = [])), params(("agent_id" = String, Path)), responses((status = 200, body = CardLookup), (status = 404, body = ApiError)))]
async fn get_card(State(st): State<ApiState>, Path(agent_id): Path<String>) -> Result<Json<CardLookup>, AppError> {
    let id = AgentId::parse(&agent_id)?;
    let (card, revocation) = st.engine.get_card(&id).await?;
    if card.is_none() && revocation.is_none() {
        return Err(AppError(StatusCode::NOT_FOUND, "unknown agent".into()));
    }
    Ok(Json(CardLookup { card, revocation }))
}

#[utoipa::path(post, path = "/v1/ephemerals", tag = "cards", security(("bearer" = [])), request_body = Ephemeral, responses((status = 200, body = PublishReport), (status = 400, body = ApiError)))]
async fn publish_ephemeral(State(st): State<ApiState>, Json(e): Json<Ephemeral>) -> Result<Json<PublishReport>, AppError> {
    Ok(Json(st.engine.publish_ephemeral(e).await?))
}

#[utoipa::path(post, path = "/v1/revocations", tag = "cards", security(("bearer" = [])), request_body = Revocation, responses((status = 200, body = PublishReport), (status = 400, body = ApiError)))]
async fn publish_revocation(State(st): State<ApiState>, Json(r): Json<Revocation>) -> Result<Json<PublishReport>, AppError> {
    Ok(Json(st.engine.publish_revocation(r).await?))
}

#[utoipa::path(post, path = "/v1/search", tag = "search", security(("bearer" = [])), request_body = SearchQuery, responses((status = 200, body = SearchResult), (status = 400, body = ApiError)))]
async fn search(State(st): State<ApiState>, Json(q): Json<SearchQuery>) -> Result<Json<SearchResult>, AppError> {
    Ok(Json(st.engine.search(q).await?))
}

#[utoipa::path(post, path = "/v1/embed", tag = "search", security(("bearer" = [])), request_body = EmbedRequest, responses((status = 200, body = EmbedResponse)))]
async fn embed(State(st): State<ApiState>, Json(r): Json<EmbedRequest>) -> Result<Json<EmbedResponse>, AppError> {
    if r.texts.is_empty() || r.texts.len() > 64 {
        return Err(AppError(StatusCode::BAD_REQUEST, "1..=64 texts".into()));
    }
    let refs: Vec<&str> = r.texts.iter().map(|s| s.as_str()).collect();
    let vectors = st
        .engine
        .embedder
        .embed_batch(&refs)
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(EmbedResponse {
        model: st.engine.model().into(),
        vectors,
    }))
}

#[utoipa::path(post, path = "/v1/zones", tag = "search", security(("bearer" = [])), request_body = EmbedRequest, responses((status = 200, body = ZonesOfResponse)))]
async fn zones_of(State(st): State<ApiState>, Json(r): Json<EmbedRequest>) -> Result<Json<ZonesOfResponse>, AppError> {
    let groups = st.engine.zones_of(&r.texts)?;
    let mut zones: Vec<ZoneOfTrait> = groups
        .into_iter()
        .map(|(zone_id, trait_indices)| ZoneOfTrait { zone_id, trait_indices })
        .collect();
    zones.sort_by_key(|z| z.zone_id);
    Ok(Json(ZonesOfResponse {
        map_version: st.engine.map.version,
        zones,
    }))
}

#[utoipa::path(post, path = "/v1/inbox", tag = "inbox", security(("bearer" = [])), request_body = DepositRequest, responses((status = 200, body = DepositReport)))]
async fn inbox_deposit(State(st): State<ApiState>, Json(r): Json<DepositRequest>) -> Result<Json<DepositReport>, AppError> {
    Ok(Json(st.engine.inbox_deposit(r.to, r.from_pubkey, r.sealed.0).await?))
}

#[utoipa::path(post, path = "/v1/inbox/{agent_id}/fetch", tag = "inbox", security(("bearer" = [])), params(("agent_id" = String, Path)), request_body = FetchRequest, responses((status = 200, body = FetchResponse)))]
async fn inbox_fetch(State(st): State<ApiState>, Path(agent_id): Path<String>, Json(r): Json<FetchRequest>) -> Result<Json<FetchResponse>, AppError> {
    let id = AgentId::parse(&agent_id)?;
    Ok(Json(FetchResponse {
        messages: st.engine.inbox_fetch(id, r.agent_pubkey, r.nonce, r.auth).await?,
    }))
}

#[utoipa::path(post, path = "/v1/inbox/{agent_id}/ack", tag = "inbox", security(("bearer" = [])), params(("agent_id" = String, Path)), request_body = InboxAck, responses((status = 200, body = AckResponse)))]
async fn inbox_ack(State(st): State<ApiState>, Path(agent_id): Path<String>, Json(ack): Json<InboxAck>) -> Result<Json<AckResponse>, AppError> {
    if ack.agent_id.as_str() != agent_id {
        return Err(AppError(StatusCode::BAD_REQUEST, "agent_id mismatch".into()));
    }
    Ok(Json(AckResponse {
        removed_copies: st.engine.inbox_ack(ack).await?,
    }))
}

#[utoipa::path(post, path = "/v1/vault/shards", tag = "vault", security(("bearer" = [])), request_body = VaultSplitRequest, responses((status = 200, body = VaultSplitResponse)))]
async fn vault_split(State(_st): State<ApiState>, Json(r): Json<VaultSplitRequest>) -> Result<Json<VaultSplitResponse>, AppError> {
    if r.encrypted.0.len() as u64 > alp_grid_core::params::VAULT_MAX_BYTES + 64 {
        return Err(AppError(StatusCode::PAYLOAD_TOO_LARGE, "snapshot larger than 256 MiB".into()));
    }
    let shards = alp_grid_vault::split(&r.encrypted.0).map_err(|e| AppError(StatusCode::BAD_REQUEST, e.to_string()))?;
    let total = shards.len() as u8;
    Ok(Json(VaultSplitResponse {
        shards: shards
            .into_iter()
            .enumerate()
            .map(|(i, d)| UnsignedShard {
                index: i as u8,
                total,
                data_shards: alp_grid_core::params::VAULT_DATA_SHARDS as u8,
                shard_hash: Bytes32(alp_grid_core::canon::hash(&d)),
                data: Blob(d),
            })
            .collect(),
    }))
}

#[utoipa::path(put, path = "/v1/vault/{agent_id}", tag = "vault", security(("bearer" = [])), params(("agent_id" = String, Path)), request_body = VaultPutRequest, responses((status = 200, body = VaultPutReport)))]
async fn vault_put(State(st): State<ApiState>, Path(agent_id): Path<String>, Json(r): Json<VaultPutRequest>) -> Result<Json<VaultPutReport>, AppError> {
    if r.shards.iter().any(|s| s.agent_id.as_str() != agent_id) {
        return Err(AppError(StatusCode::BAD_REQUEST, "agent_id mismatch".into()));
    }
    Ok(Json(st.engine.vault_put(r.shards).await?))
}

#[utoipa::path(get, path = "/v1/vault/{agent_id}/{snapshot}", tag = "vault", security(("bearer" = [])), params(("agent_id" = String, Path), ("snapshot" = u64, Path)), responses((status = 200, body = VaultGetReport)))]
async fn vault_get(State(st): State<ApiState>, Path((agent_id, snapshot)): Path<(String, u64)>) -> Result<Json<VaultGetReport>, AppError> {
    let id = AgentId::parse(&agent_id)?;
    Ok(Json(st.engine.vault_get(id, snapshot).await?))
}

#[utoipa::path(get, path = "/v1/ledger", tag = "atlas", security(("bearer" = [])), params(LedgerQuery), responses((status = 200, body = LedgerPage)))]
async fn ledger(State(st): State<ApiState>, Query(q): Query<LedgerQuery>) -> Result<Json<LedgerPage>, AppError> {
    let entries = st.engine.ledger.range(q.from.unwrap_or(0), q.limit.unwrap_or(100).min(1000) as usize)?;
    Ok(Json(LedgerPage {
        entries,
        root: st.engine.ledger.root().to_hex(),
        size: st.engine.ledger.len(),
    }))
}

#[utoipa::path(get, path = "/v1/atlas/stats", tag = "atlas", responses((status = 200, body = AtlasStats), (status = 404, description = "observer mode disabled")))]
async fn atlas_stats(State(st): State<ApiState>) -> Result<Json<AtlasStats>, AppError> {
    if !st.observer {
        return Err(AppError(
            StatusCode::NOT_FOUND,
            "this node is not an observer (set node.observer = true)".into(),
        ));
    }
    Ok(Json(observer::collect(&st.engine)))
}
