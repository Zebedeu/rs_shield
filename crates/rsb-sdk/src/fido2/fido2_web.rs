use crate::credentials::Fido2Manager;
use crate::server::middleware::{is_allowed_local_host, local_host_guard_middleware};
use axum::response::Html;
use axum::{
    Json, Router,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self as axum_mw, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use webauthn_rs::prelude::*;

pub type AppState = Arc<Mutex<Fido2Manager>>;

/// Porta do servidor local FIDO2 (tem de coincidir com a origin do manager).
pub const FIDO2_WEB_PORT: u16 = 3000;
/// Nome do cookie com o token de acesso desta execução.
const TOKEN_COOKIE: &str = "rsb_fido2_token";
/// Cabeçalho alternativo para o token (clientes não-browser).
const TOKEN_HEADER: &str = "x-rsb-token";

/// Modo de execução do servidor local.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerMode {
    /// Termina após uma autenticação bem-sucedida (login).
    Authenticate,
    /// Termina após um registo bem-sucedido; uma autenticação prévia
    /// (obrigatória para adicionar chaves a um utilizador existente) não
    /// termina o servidor.
    Register,
}

#[derive(Clone)]
pub struct ServerState {
    pub manager: Arc<Mutex<Fido2Manager>>,
    pub done_tx: Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
    /// Token aleatório por execução, exigido em todas as rotas.
    pub access_token: Arc<String>,
    pub port: u16,
    pub mode: ServerMode,
    /// Utilizadores que concluíram uma asserção FIDO2 nesta execução.
    pub authenticated_users: Arc<Mutex<HashSet<String>>>,
    /// Ficheiro de credenciais a persistir após alterações.
    pub storage_path: std::path::PathBuf,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub user_id: String,
}

#[derive(Serialize)]
pub struct CredentialInfo {
    pub user_id: String,
    pub username: String,
    pub display_name: String,
    pub counter: u32,
    pub created_at: String,
    pub last_used: Option<String>,
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

// Custom error response
pub struct ApiResponse<T: Serialize>(pub T, pub StatusCode);

impl<T: Serialize + Send + 'static> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (self.1, Json(self.0)).into_response()
    }
}

fn api_error(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

/// Comparação em tempo constante.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Gera o token aleatório (256 bits, hex) desta execução.
pub fn generate_access_token() -> String {
    use rand::Rng;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| {
            let kv = kv.trim();
            kv.strip_prefix(TOKEN_COOKIE)
                .and_then(|rest| rest.strip_prefix('='))
                .map(|t| t.to_string())
        })
        .next()
}

/// True se o pedido apresenta o token desta execução (cookie ou cabeçalho).
fn request_has_valid_token(headers: &HeaderMap, expected: &str) -> bool {
    let header_tok = headers
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    [header_tok, cookie_token(headers)]
        .into_iter()
        .flatten()
        .any(|t| ct_eq(t.as_bytes(), expected.as_bytes()))
}

/// Middleware: exige o token por execução em todas as rotas da API.
async fn require_run_token(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    if !request_has_valid_token(request.headers(), &state.access_token) {
        warn!("Rejected FIDO2 web request without a valid access token");
        return api_error(StatusCode::FORBIDDEN, "Missing or invalid access token").into_response();
    }
    next.run(request).await
}

pub fn create_router(state: ServerState, html: Html<&'static str>) -> Router {
    let api = Router::new()
        // register
        .route("/register/start", post(register_start))
        .route("/register/finish", post(register_finish))
        // auth
        .route("/auth/start", post(auth_start))
        .route("/auth/finish", post(auth_finish))
        // credentials management
        .route("/credentials", get(list_credentials))
        .route("/credentials/:user_id", delete(delete_credential))
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            require_run_token,
        ));

    let port = state.port;
    Router::new()
        .route(
            "/",
            get(
                move |State(st): State<ServerState>,
                      Query(q): Query<HashMap<String, String>>,
                      headers: HeaderMap| async move { index(st, q, headers, html) },
            ),
        )
        .merge(api)
        .with_state(state)
        // Host tem de ser localhost:<port>/127.0.0.1:<port> (anti DNS rebinding).
        .layer(axum_mw::from_fn_with_state(
            port,
            local_host_guard_middleware,
        ))
}

/// GET / — aceita o token por query (URL aberta pela CLI), grava-o num cookie
/// HttpOnly/SameSite=Strict e redireciona para `/` (remove o token da URL).
fn index(
    state: ServerState,
    query: HashMap<String, String>,
    headers: HeaderMap,
    html: Html<&'static str>,
) -> Response {
    if !is_allowed_local_host(&headers, state.port) {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    if let Some(tok) = query.get("token") {
        if ct_eq(tok.as_bytes(), state.access_token.as_bytes()) {
            let cookie = format!(
                "{}={}; HttpOnly; SameSite=Strict; Path=/",
                TOKEN_COOKIE, state.access_token
            );
            return ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response();
        }
        return (StatusCode::FORBIDDEN, "Invalid access token").into_response();
    }
    if request_has_valid_token(&headers, &state.access_token) {
        return html.into_response();
    }
    (
        StatusCode::FORBIDDEN,
        "Access denied. Open the URL printed in your terminal.",
    )
        .into_response()
}

// ================= REGISTER =================

async fn register_start(
    State(state): State<ServerState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<CreationChallengeResponse>, (StatusCode, Json<ApiError>)> {
    info!("Register start: user_id={}", req.user_id);

    // Validate request
    if req.user_id.is_empty() || req.user_id.len() > 255 {
        warn!("Invalid user_id in register request");
        return Err(api_error(StatusCode::BAD_REQUEST, "Invalid user_id length"));
    }

    // Um utilizador que já tem chaves só pode adicionar outra depois de provar
    // posse de uma chave existente (asserção bem-sucedida nesta execução).
    let already_authenticated = state
        .authenticated_users
        .lock()
        .await
        .contains(&req.user_id);

    let mut m = state.manager.lock().await;

    if m.has_credential(&req.user_id) && !already_authenticated {
        warn!("Registration for existing user refused without prior assertion");
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "This user already has a security key. Authenticate with an existing key first.",
        ));
    }

    m.start_registration(&req.user_id, &req.username, &req.display_name)
        .map(Json)
        .map_err(|e| {
            error!("Registration start error: {}", e);
            api_error(StatusCode::BAD_REQUEST, e.to_string())
        })
}

async fn register_finish(
    State(state): State<ServerState>,
    Json(res): Json<RegisterPublicKeyCredential>,
) -> Result<Json<bool>, (StatusCode, Json<ApiError>)> {
    let mut m = state.manager.lock().await;

    match m.finish_registration(res) {
        Ok(_) => {
            // 🔐 save credentials to file (o registo só conta se for persistido)
            m.save_to_file(&state.storage_path).map_err(|e| {
                error!("Failed to persist credentials after registration: {}", e);
                api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            })?;
            drop(m);

            if state.mode == ServerMode::Register {
                signal_done(&state).await;
            }
            Ok(Json(true))
        }
        Err(e) => Err(api_error(StatusCode::BAD_REQUEST, e.to_string())),
    }
}

// ================= AUTH =================

async fn auth_start(
    State(state): State<ServerState>,
    Json(req): Json<AuthRequest>,
) -> Result<Json<RequestChallengeResponse>, (StatusCode, Json<ApiError>)> {
    info!("Auth start: user_id={}", req.user_id);

    if req.user_id.is_empty() {
        warn!("Empty user_id in auth request");
        return Err(api_error(StatusCode::BAD_REQUEST, "user_id is required"));
    }

    let mut m = state.manager.lock().await;

    m.start_authentication(&req.user_id).map(Json).map_err(|e| {
        error!("Auth start error: {}", e);
        api_error(StatusCode::BAD_REQUEST, e.to_string())
    })
}

async fn auth_finish(
    State(state): State<ServerState>,
    Json(res): Json<PublicKeyCredential>,
) -> Result<Json<String>, (StatusCode, Json<ApiError>)> {
    info!("Auth finish");
    let user_id = {
        let mut m = state.manager.lock().await;

        let user_id = m.finish_authentication(res).map_err(|e| {
            error!("Auth finish error: {}", e);
            api_error(StatusCode::BAD_REQUEST, e.to_string())
        })?;

        // Persistir o contador atualizado; sem isto não há deteção de clones.
        m.save_to_file(&state.storage_path).map_err(|e| {
            error!("Failed to persist authenticator state: {}", e);
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist authenticator state",
            )
        })?;
        user_id
    };

    state
        .authenticated_users
        .lock()
        .await
        .insert(user_id.clone());

    // Se a autenticação foi bem-sucedida, sinaliza para encerrar o servidor
    if state.mode == ServerMode::Authenticate {
        info!("🎉 Authentication successful! Signaling server to shutdown...");
        signal_done(&state).await;
    }

    Ok(Json(user_id))
}

async fn signal_done(state: &ServerState) {
    let mut tx_opt = state.done_tx.lock().await;
    if let Some(tx) = tx_opt.take() {
        let _ = tx.send(());
    }
}

// ================= CREDENTIALS MANAGEMENT =================

async fn list_credentials(
    State(state): State<ServerState>,
) -> Result<Json<Vec<CredentialInfo>>, (StatusCode, Json<ApiError>)> {
    info!("Listing credentials");
    let m = state.manager.lock().await;

    let credentials = m
        .list_credentials()
        .into_iter()
        .map(|c| CredentialInfo {
            user_id: c.user_id,
            username: c.user_name,
            display_name: c.display_name,
            counter: c.counter,
            created_at: c.created_at,
            last_used: c.last_used,
        })
        .collect();

    Ok(Json(credentials))
}

async fn delete_credential(
    State(state): State<ServerState>,
    Path(user_id): Path<String>,
) -> Result<Json<bool>, (StatusCode, Json<ApiError>)> {
    info!("Deleting credential: user_id={}", user_id);

    if user_id.is_empty() {
        warn!("Empty user_id in delete request");
        return Err(api_error(StatusCode::BAD_REQUEST, "user_id is required"));
    }

    // Operação destrutiva: exige asserção prévia do próprio utilizador.
    let authenticated = state.authenticated_users.lock().await.contains(&user_id);
    if !authenticated {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "Authenticate with this user's security key before deleting it.",
        ));
    }

    let mut m = state.manager.lock().await;

    m.revoke_user(&user_id).map_err(|e| {
        error!("Delete credential error: {}", e);
        let status = if e.to_string().contains("not found") {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::BAD_REQUEST
        };
        api_error(status, e.to_string())
    })?;

    m.save_to_file(&state.storage_path).map_err(|e| {
        error!("Failed to persist credential deletion: {}", e);
        api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(Json(true))
}

// ================= SERVER =================

/// Executa o servidor em modo `Authenticate` (termina após login).
pub async fn run_server(
    manager: Arc<Mutex<Fido2Manager>>,
    html: Html<&'static str>,
) -> Result<(), Box<dyn std::error::Error>> {
    run_server_with_mode(manager, html, ServerMode::Authenticate).await
}

pub async fn run_server_with_mode(
    manager: Arc<Mutex<Fido2Manager>>,
    html: Html<&'static str>,
    mode: ServerMode,
) -> Result<(), Box<dyn std::error::Error>> {
    // Carregar o estado persistido antes de aceitar pedidos: sem isto um
    // registo gravaria um ficheiro contendo apenas o utilizador novo.
    let storage_path = Fido2Manager::default_storage_path()?;
    {
        let mut m = manager.lock().await;
        if !m.is_loaded_from(&storage_path) {
            m.load_from_file(&storage_path)?;
        }
    }

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let port = FIDO2_WEB_PORT;
    let access_token = generate_access_token();

    let server_state = ServerState {
        manager,
        done_tx: Arc::new(tokio::sync::Mutex::new(Some(tx))),
        access_token: Arc::new(access_token.clone()),
        port,
        mode,
        authenticated_users: Arc::new(Mutex::new(HashSet::new())),
        storage_path,
    };

    let router = create_router(server_state, html);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    let url = format!("http://localhost:{}/?token={}", port, access_token);

    info!("🌐 Server running at http://localhost:{}", port);
    println!("🌐 Server: {}", url);

    // Abre browser
    let _ = open::that(&url);

    // Cria uma tarefa para rodar o servidor
    let server_task = axum::serve(listener, router);

    // Aguarda ou o sinal de conclusão ou que o servidor retorne (error)
    tokio::select! {
        _ = rx => {
            info!("✅ Done! Shutting down server gracefully...");
            // Quando o signal é recebido, o servidor será encerrado automaticamente
            Ok(())
        }
        result = server_task => {
            result.map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_token_from_cookie_and_header() {
        let tok = generate_access_token();
        assert_eq!(tok.len(), 64);

        let mut h = HeaderMap::new();
        assert!(!request_has_valid_token(&h, &tok));

        h.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("other=1; {}={}", TOKEN_COOKIE, tok)).unwrap(),
        );
        assert!(request_has_valid_token(&h, &tok));

        let mut h2 = HeaderMap::new();
        h2.insert(TOKEN_HEADER, HeaderValue::from_str(&tok).unwrap());
        assert!(request_has_valid_token(&h2, &tok));

        let mut h3 = HeaderMap::new();
        h3.insert(TOKEN_HEADER, HeaderValue::from_static("wrong"));
        assert!(!request_has_valid_token(&h3, &tok));
    }
}
