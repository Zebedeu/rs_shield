use crate::auth::{
    AuditLogger, AuthRequest, AuthResponse, JwtManager, RateLimiter, Session, SessionStore,
};
use crate::credentials;
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Html,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

#[derive(Clone)]
pub struct AuthHandlerState<S: SessionStore + Clone> {
    pub jwt_manager: Arc<JwtManager>,
    pub fido2_manager: Arc<Mutex<credentials::Fido2Manager>>,
    pub session_store: Arc<S>,
    pub device_flows: Arc<Mutex<HashMap<String, DeviceFlowStatus>>>,
    pub rate_limiter: Arc<RateLimiter>,
    pub audit_logger: Arc<AuditLogger>,
    /// Ficheiro de credenciais FIDO2: tem de ser persistido após cada
    /// autenticação (contador) e consumo de recovery code.
    pub fido2_storage_path: std::path::PathBuf,
    /// URL base pública do servidor (ex.: `http://localhost:3000`).
    pub public_base_url: String,
}

#[derive(Clone)]
pub struct DeviceFlowStatus {
    pub user_code: String,
    pub user_id: String,
    pub access_token: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub attempts: u32,
}

impl DeviceFlowStatus {
    pub fn new(user_code: String, user_id: String, ttl_secs: i64) -> Self {
        let now = chrono::Utc::now();
        Self {
            user_code,
            user_id,
            access_token: None,
            created_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_secs),
            attempts: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }
}

/// Alfabeto do user_code: 31 símbolos sem 0/O/1/I/L confusos.
pub(crate) const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Comprimento do user_code (~39.6 bits de entropia).
pub(crate) const USER_CODE_LEN: usize = 8;

/// Gera o user_code com amostragem por rejeição: sem viés de módulo e sem
/// indexação fora dos limites (antes `b % 32` num alfabeto de 31 → panic).
pub(crate) fn generate_user_code() -> String {
    use rand::Rng;
    let n = USER_CODE_ALPHABET.len();
    // Maior múltiplo de n que cabe num byte; bytes acima são rejeitados.
    let limit = (256 / n) * n;
    let mut rng = rand::rng();
    let mut out = String::with_capacity(USER_CODE_LEN);
    let mut buf = [0u8; 16];
    while out.len() < USER_CODE_LEN {
        rng.fill_bytes(&mut buf);
        for &b in buf.iter() {
            if out.len() == USER_CODE_LEN {
                break;
            }
            if (b as usize) < limit {
                out.push(USER_CODE_ALPHABET[(b as usize) % n] as char);
            }
        }
    }
    out
}

fn prune_expired_device_flows(flows: &mut HashMap<String, DeviceFlowStatus>) {
    let now = chrono::Utc::now();
    flows.retain(|_, f| f.expires_at > now);
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}
const EXPIRE_DATE: i64 = 1800;
/// Tempo de vida de um device flow (segundos).
const DEVICE_FLOW_TTL: i64 = 900;
/// Número máximo de device flows pendentes.
const MAX_DEVICE_FLOWS: usize = 100;
/// Limite partilhado para pedidos de utilizadores inexistentes (não cria
/// entradas por user_id arbitrário no rate limiter).
const UNKNOWN_USER_LIMIT: u32 = 20;

fn error_response(status: StatusCode, message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: status.canonical_reason().unwrap_or("Error").to_string(),
            message: message.to_string(),
        }),
    )
}

fn extract_ip_from_headers(_headers: &HeaderMap) -> String {
    // Servidor faz bind em 127.0.0.1 sem proxy confiável à frente:
    // `x-forwarded-for` seria spoofável e envenenaria a trilha de auditoria.
    // Registamos loopback; se um dia houver proxy, validar a origem aqui.
    "127.0.0.1".to_string()
}

fn rate_key(user_id: &str, ip: &str) -> String {
    format!("{}|{}", user_id.trim().to_lowercase(), ip)
}

fn unknown_key(scope: &str, ip: &str) -> String {
    format!("{}-unknown|{}", scope, ip)
}

/// Rate-limit que só cria contadores por utilizador para utilizadores
/// existentes; pedidos para utilizadores desconhecidos usam um balde comum.
async fn rate_limit_user<S: SessionStore + Clone>(
    state: &AuthHandlerState<S>,
    scope: &str,
    user_id: &str,
    ip: &str,
) -> bool {
    let exists = state.fido2_manager.lock().await.user_exists(user_id);
    if exists {
        state
            .rate_limiter
            .is_allowed(&format!("{}|{}", scope, rate_key(user_id, ip)))
            .await
    } else {
        state
            .rate_limiter
            .is_allowed_n(&unknown_key(scope, ip), UNKNOWN_USER_LIMIT)
            .await
    }
}

/// Cria token + sessão persistida. Se a sessão não puder ser guardada, o
/// token NÃO é devolvido.
async fn issue_session<S: SessionStore + Clone>(
    state: &AuthHandlerState<S>,
    headers: &HeaderMap,
    user_id: &str,
    fido2_counter: u32,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let scopes = vec!["backup".to_string(), "restore".to_string()];
    let token = state
        .jwt_manager
        .create_token(user_id, scopes.clone(), EXPIRE_DATE)
        .map_err(|e| {
            error!("JWT creation failed: {:?}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create access token",
            )
        })?;
    let jti = state.jwt_manager.extract_jti(&token).ok_or_else(|| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create access token",
        )
    })?;
    let now = Utc::now();
    let session = Session {
        user_id: user_id.to_string(),
        jti,
        created_at: now,
        expires_at: now + chrono::Duration::seconds(EXPIRE_DATE),
        revoked: false,
        ip_address: Some(extract_ip_from_headers(headers)),
        user_agent: Some(extract_user_agent_from_headers(headers)),
        fido2_counter,
        scopes,
    };
    if let Err(e) = state.session_store.save(session).await {
        error!("Failed to save session to store: {}", e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to establish session",
        ));
    }
    Ok(token)
}

fn extract_user_agent_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// POST /api/auth/start - Iniciar autenticação FIDO2
pub async fn auth_start<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<AuthRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    info!("Auth start: user_id={}", req.user_id);

    if req.user_id.is_empty() {
        warn!("Empty user_id in auth request");
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "user_id is required",
        ));
    }

    // Rate Limiting check (chave: user+ip; utilizadores desconhecidos partilham
    // um balde comum para não criar entradas por user_id arbitrário)
    let client_ip = extract_ip_from_headers(&headers);
    if !rate_limit_user(&state, "start", &req.user_id, &client_ip).await {
        state
            .audit_logger
            .log_auth_failure(
                &req.user_id,
                &client_ip,
                &extract_user_agent_from_headers(&headers),
                "Rate limit exceeded",
            )
            .await;
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many authentication attempts. Please try again later.",
        ));
    }

    let mut fido2_mgr = state.fido2_manager.lock().await;

    match fido2_mgr.start_authentication(&req.user_id) {
        Ok(challenge_response) => {
            let ip = extract_ip_from_headers(&headers);
            info!(
                "Auth challenge created for user: {}, ip: {}",
                req.user_id, ip
            );

            Ok(Json(
                serde_json::to_value(&challenge_response).unwrap_or_default(),
            ))
        }
        Err(credentials::fido2_manager::Fido2Error::CredentialNotFound) => {
            // Resposta genérica para não permitir enumeração de user_id (401 vs 404).
            warn!("Auth attempt for unknown user (generic response)");
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid credentials",
            ))
        }
        Err(e) => {
            warn!("Failed to create auth challenge: {:?}", e);
            Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create authentication challenge",
            ))
        }
    }
}

/// POST /api/auth/finish - Completar autenticação FIDO2
pub async fn auth_finish<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<AuthRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Auth finish: user_id={}", req.user_id);

    if req.user_id.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "user_id is required",
        ));
    }

    // Rate-limit também no finish (antes cobria só o start).
    let client_ip = extract_ip_from_headers(&headers);
    if !rate_limit_user(&state, "finish", &req.user_id, &client_ip).await {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many authentication attempts. Please try again later.",
        ));
    }

    let credential_json = req
        .fido2_response
        .clone()
        .ok_or_else(|| error_response(StatusCode::BAD_REQUEST, "fido2_response is required"))?;

    let credential: webauthn_rs::prelude::PublicKeyCredential =
        serde_json::from_str(&credential_json)
            .map_err(|_| error_response(StatusCode::BAD_REQUEST, "Invalid credential format"))?;

    let auth_result = {
        let mut fido2_mgr = state.fido2_manager.lock().await;
        match fido2_mgr.finish_authentication(credential) {
            Ok(authenticated_user_id) => {
                // Persistir o contador atualizado ANTES de emitir o token: sem
                // isto um replay/clone não seria detetado após reinício.
                if let Err(e) = fido2_mgr.save_to_file(&state.fido2_storage_path) {
                    error!("Failed to persist FIDO2 credential state: {}", e);
                    return Err(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Failed to persist authenticator state",
                    ));
                }
                let latest_counter = fido2_mgr
                    .list_user_credentials(&authenticated_user_id)
                    .into_iter()
                    .map(|c| c.counter)
                    .max()
                    .unwrap_or(0);
                Ok((authenticated_user_id, latest_counter))
            }
            Err(e) => Err(e),
        }
    };

    let (authenticated_user_id, latest_counter) = match auth_result {
        Ok(v) => v,
        Err(e) => {
            warn!("Security Keyverification failed: {:?}", e);
            state
                .audit_logger
                .log_auth_failure(
                    &req.user_id,
                    &client_ip,
                    &extract_user_agent_from_headers(&headers),
                    &format!("Security Keyerror: {:?}", e),
                )
                .await;
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "Invalid Security Keycredential",
            ));
        }
    };

    // O utilizador autenticado tem de ser o que foi pedido.
    if authenticated_user_id != req.user_id {
        warn!("Authenticated user does not match requested user_id");
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Invalid Security Keycredential",
        ));
    }

    // Device flow: tem de existir, não estar expirado nem já concluído, e estar
    // vinculado ao MESMO utilizador que se autenticou.
    if let Some(device_code) = req.device_code.as_deref() {
        let mut flows = state.device_flows.lock().await;
        prune_expired_device_flows(&mut flows);
        let valid = flows
            .get(device_code)
            .map(|f| f.user_id == authenticated_user_id && f.access_token.is_none())
            .unwrap_or(false);
        if !valid {
            warn!("Device flow not found, already completed or bound to another user");
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "Invalid device_code or user_id not found.",
            ));
        }
    }

    let token = issue_session(&state, &headers, &authenticated_user_id, latest_counter).await?;

    if let Some(device_code) = req.device_code.as_deref() {
        let mut flows = state.device_flows.lock().await;
        match flows.get_mut(device_code) {
            Some(flow) if flow.user_id == authenticated_user_id => {
                flow.access_token = Some(token.clone());
                debug!("Device flow updated with access token");
            }
            _ => {
                // Expirou entre a verificação e agora: revogar o token emitido.
                if let Some(jti) = state.jwt_manager.extract_jti(&token) {
                    let _ = state.session_store.revoke(&jti).await;
                }
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid device_code or user_id not found.",
                ));
            }
        }
    }

    info!(
        "Auth successful: user_id={}, counter={}, ip={}",
        authenticated_user_id, latest_counter, client_ip
    );

    state
        .audit_logger
        .log_auth_success(
            &authenticated_user_id,
            &client_ip,
            &extract_user_agent_from_headers(&headers),
        )
        .await;

    Ok(Json(AuthResponse {
        access_token: token,
        expires_in: EXPIRE_DATE,
        token_type: "Bearer".to_string(),
        user_id: authenticated_user_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// POST /api/auth/refresh - Refresh access token (com rotação e revogação)
pub async fn auth_refresh<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Token refresh requested");

    let client_ip = extract_ip_from_headers(&headers);

    // Verificação HMAC primeiro (barata e sem estado); o rate-limit é por
    // utilizador verificado em vez de um balde global partilhado por todos.
    let claims = state
        .jwt_manager
        .verify_token(&req.refresh_token)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid refresh token"))?;

    if !state
        .rate_limiter
        .is_allowed(&format!("refresh|{}", rate_key(&claims.sub, &client_ip)))
        .await
    {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many refresh attempts. Please try again later.",
        ));
    }

    // O refresh só é válido se a sessão original ainda existir e não estiver revogada.
    // Sem isto, um token roubado renovava para sempre (jti novo sem revogar o antigo).
    match state.session_store.get(&claims.jti).await {
        Ok(Some(_)) => {}
        _ => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "Session not found or revoked",
            ));
        }
    }

    let user_id = claims.sub.clone();

    // Revoga a sessão antiga antes de emitir a nova (rotação, sem extensão indefinida).
    if let Err(e) = state.session_store.revoke(&claims.jti).await {
        error!("Failed to revoke old session during refresh: {}", e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to rotate session",
        ));
    }

    let new_token = issue_session(&state, &headers, &user_id, 0).await?;

    info!("Token refreshed (rotated) for user: {}", user_id);

    Ok(Json(AuthResponse {
        access_token: new_token,
        expires_in: EXPIRE_DATE,
        token_type: "Bearer".to_string(),
        user_id: user_id.clone(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct RecoveryRequest {
    pub user_id: String,
    pub recovery_code: String,
}

/// POST /api/auth/recovery - Validate and use a recovery code
pub async fn auth_recovery<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<RecoveryRequest>,
) -> Result<Json<AuthResponse>, (StatusCode, Json<ErrorResponse>)> {
    info!("Recovery attempt for user_id={}", req.user_id);

    if req.user_id.is_empty() || req.recovery_code.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "user_id and recovery_code are required",
        ));
    }

    // Rate-limit no recovery (antes sem limite → brute-force de códigos).
    let client_ip = extract_ip_from_headers(&headers);

    // Lock curto: apenas para obter salt/iterações (o PBKDF2 corre fora do lock).
    let material = {
        let fido2_mgr = state.fido2_manager.lock().await;
        fido2_mgr.recovery_material(&req.user_id)
    };

    let allowed = match material {
        Some(_) => {
            state
                .rate_limiter
                .is_allowed(&format!("recovery|{}", rate_key(&req.user_id, &client_ip)))
                .await
        }
        None => {
            state
                .rate_limiter
                .is_allowed_n(&unknown_key("recovery", &client_ip), UNKNOWN_USER_LIMIT)
                .await
        }
    };
    if !allowed {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many recovery attempts. Please try again later.",
        ));
    }

    // Utilizador inexistente/sem códigos: mesmo custo e mesma resposta genérica.
    let (salt, iterations, known) = match material {
        Some(m) => (m.salt, m.iterations, true),
        None => (
            vec![0u8; 16],
            credentials::fido2_manager::RECOVERY_CODE_ITERATIONS,
            false,
        ),
    };
    let code = req.recovery_code.clone();
    let input_hash = tokio::task::spawn_blocking(move || {
        credentials::Fido2Manager::compute_recovery_hash(&code, &salt, iterations)
    })
    .await
    .map_err(|e| {
        error!("Recovery hash task failed: {}", e);
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to verify recovery code",
        )
    })?;

    let verified = if known {
        let mut fido2_mgr = state.fido2_manager.lock().await;
        if fido2_mgr.consume_recovery_hash(&req.user_id, &input_hash) {
            // Persistir o consumo: sem isto o código voltava a ser válido.
            if let Err(e) = fido2_mgr.save_to_file(&state.fido2_storage_path) {
                error!("Failed to persist recovery code consumption: {}", e);
                return Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to persist recovery code state",
                ));
            }
            true
        } else {
            false
        }
    } else {
        false
    };

    if !verified {
        state
            .audit_logger
            .log_auth_failure(
                &req.user_id,
                &client_ip,
                &extract_user_agent_from_headers(&headers),
                "Invalid recovery code",
            )
            .await;
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "Invalid or used recovery code",
        ));
    }

    info!(
        "Recovery code successfully verified for user: {}",
        req.user_id
    );

    // Recovery grants full access
    let token = issue_session(&state, &headers, &req.user_id, 0).await?;

    state
        .audit_logger
        .log_auth_success(
            &req.user_id,
            &client_ip,
            &extract_user_agent_from_headers(&headers),
        )
        .await;

    Ok(Json(AuthResponse {
        access_token: token,
        expires_in: EXPIRE_DATE,
        token_type: "Bearer".to_string(),
        user_id: req.user_id,
    }))
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub access_token: String,
}

/// POST /api/auth/logout - Logout and revoke session
pub async fn auth_logout<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    _headers: HeaderMap,
    Json(req): Json<LogoutRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let claims = state
        .jwt_manager
        .verify_token(&req.access_token)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid token"))?;

    if let Err(e) = state.session_store.revoke(&claims.jti).await {
        error!("Failed to revoke session: {}", e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to revoke session",
        ));
    }

    info!("User logged out: {}", claims.sub);

    Ok(Json(json!({
        "message": "Successfully logged out"
    })))
}

/// POST /api/auth/localhost-callback - Callback para CLI via localhost
///
/// SEGURANÇA: este endpoint existia mintando JWT sem prova
/// (`{"user_id":"admin"}` bastava). Agora está DESATIVADO por defeito:
/// retorna 410 Gone. Reative apenas com prova FIDO2 completa via
/// `/api/auth/finish` + device flow.
pub async fn auth_localhost_callback<S: SessionStore + Clone>(
    State(_state): State<AuthHandlerState<S>>,
    _headers: HeaderMap,
    _payload: Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    warn!("Blocked unauthenticated localhost-callback mint attempt");
    Err(error_response(
        StatusCode::GONE,
        "Direct token minting is disabled. Authenticate via FIDO2 device flow.",
    ))
}

/// GET /api/auth/verify - Verificar se token é válido
pub async fn auth_verify<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "Missing or invalid authorization header",
            )
        })?;

    let claims = state
        .jwt_manager
        .verify_token(token)
        .map_err(|_| error_response(StatusCode::UNAUTHORIZED, "Invalid token"))?;

    let jti = claims.jti.clone();

    match state.session_store.get(&jti).await {
        Ok(Some(session)) if session.user_id == claims.sub => {
            info!("Token verified for user: {}", session.user_id);
            Ok(Json(json!({
                "valid": true,
                "user_id": session.user_id,
                "scopes": session.scopes,
                "expires_at": session.expires_at
            })))
        }
        Ok(_) => {
            warn!("Session not found or expired");
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                "Session not found or expired",
            ))
        }
        Err(e) => {
            error!("Session store error: {}", e);
            Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify session",
            ))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceFlowStartResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: i64,
    pub interval: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceFlowTokenRequest {
    pub device_code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceFlowTokenResponse {
    pub access_token: Option<String>,
    pub status: String,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceFlowStartRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceFlowLookupRequest {
    pub user_code: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceFlowLookupResponse {
    pub device_code: String,
    pub user_id: String,
}

/// Cria um device flow vinculado a `user_id` (com limites de taxa e tamanho).
async fn create_device_flow<S: SessionStore + Clone>(
    state: &AuthHandlerState<S>,
    headers: &HeaderMap,
    user_id: &str,
) -> Result<DeviceFlowStartResponse, (StatusCode, Json<ErrorResponse>)> {
    if user_id.trim().is_empty() || user_id.len() > 255 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "user_id is required",
        ));
    }

    let client_ip = extract_ip_from_headers(headers);
    if !state
        .rate_limiter
        .is_allowed_n(&format!("devstart|{}", client_ip), 10)
        .await
    {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many device flow requests. Please try again later.",
        ));
    }

    let device_code = uuid::Uuid::new_v4().to_string();
    let user_code = generate_user_code();

    let mut flows = state.device_flows.lock().await;
    prune_expired_device_flows(&mut flows);
    if flows.len() >= MAX_DEVICE_FLOWS {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many pending device flows. Please try again later.",
        ));
    }
    flows.insert(
        device_code.clone(),
        DeviceFlowStatus::new(user_code.clone(), user_id.to_string(), DEVICE_FLOW_TTL),
    );
    // Não registar device_code/user_code em logs (são segredos de curta duração).
    debug!("Device flow started for user_id={}", user_id);

    Ok(DeviceFlowStartResponse {
        device_code,
        user_code,
        // The user_code is no longer part of the URL, it will be entered manually.
        verification_url: format!("{}/auth/device/verify", state.public_base_url),
        expires_in: DEVICE_FLOW_TTL,
        interval: 5, // Polling interval for CLI
    })
}

/// POST /auth/device/start - Iniciar fluxo de autenticação de dispositivo
pub async fn device_flow_start<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<DeviceFlowStartRequest>,
) -> Result<Json<DeviceFlowStartResponse>, (StatusCode, Json<ErrorResponse>)> {
    create_device_flow(&state, &headers, &req.user_id)
        .await
        .map(Json)
}

/// GET /auth/device/verify - Página de verificação do fluxo de dispositivo
pub async fn device_flow_verify_page<S: SessionStore + Clone>(
    State(_state): State<AuthHandlerState<S>>,
) -> Result<Html<String>, (StatusCode, Json<ErrorResponse>)> {
    Ok(Html(r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><title>RSB Verification</title>
<style>
    body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; padding: 50px; background: #f5f5f5; }
    .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; width: 100%; text-align: center; }
    input[type="text"] { padding: 12px 15px; font-size: 24px; text-align: center; width: calc(100% - 30px); margin-bottom: 15px; border: 2px solid #ccc; border-radius: 5px; letter-spacing: 4px; font-weight: bold; }
    .input-group { margin-bottom: 20px; }
    button { padding: 15px 30px; font-size: 18px; cursor: pointer; background: #3498db; color: white; border: none; border-radius: 5px; width: 100%; transition: background 0.3s; }
    button:hover { background: #2980b9; }
    #authenticateButton { background: #2ecc71; display: none; margin-top: 20px; }
    button:disabled { background: #95a5a6; cursor: not-allowed; }
    .message { margin-top: 20px; padding: 15px; border-radius: 5px; display: none; }
    .error { background: #f8d7da; color: #721c24; }
    .success { background: #d4edda; color: #155724; }
    .info { background: #d1ecf1; color: #0c5460; }
    #userInfo { display: none; text-align: left; margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 5px; border: 1px solid #e9ecef; }
</style></head>
<body><div class="container">
    <h1>🔐 Device Verification</h1>
    <p>Enter the verification code displayed on your terminal:</p>
    <div class="input-group" id="lookupSection">
        <input type="text" id="userCodeInput" maxlength="8" placeholder="********" style="text-transform:uppercase;">
        <button id="lookupButton">Confirm Code</button>
    </div>
    <div id="userInfo">
        <p><strong>User:</strong> <span id="displayUserId"></span></p>
    </div>
    <button id="authenticateButton">🔐 Click to Authenticate</button>
    <div id="statusMessage" class="message"></div>
</div>
<script type="text/javascript">
    let deviceCode = null;
    let userId = null;
    const statusMessage = document.getElementById('statusMessage');
    function showMessage(text, type) {
        if (text === 'Failed to fetch') {
            text = "Unable to connect to the server. Please check your internet.";
        }

        statusMessage.innerText = text;
        statusMessage.className = 'message ' + type;
        statusMessage.style.display = 'block';
    }
    function base64url_to_uint8array(base64url) {
        const padding = '='.repeat((4 - base64url.length % 4) % 4);
        const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
        return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
    }
    function uint8array_to_base64url(buffer) {
        const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    document.getElementById('lookupButton').onclick = async () => {
        const userCode = document.getElementById('userCodeInput').value.trim().toUpperCase();
        if (userCode.length !== 8) { showMessage('Please enter the 8-character code.', 'error'); return; }
        try {
            const res = await fetch('/api/auth/device/lookup-code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_code: userCode })
            });
            if (!res.ok) throw new Error('Invalid or expired code.');
            const data = await res.json();
            deviceCode = data.device_code;
            userId = data.user_id;
            document.getElementById('displayUserId').innerText = userId;
            document.getElementById('userInfo').style.display = 'block';
            document.getElementById('lookupSection').style.display = 'none';
            document.getElementById('authenticateButton').style.display = 'block';
            showMessage('Code validated! Proceed...', 'success');
        } catch (e) { showMessage(e.message, 'error'); }
    };
    document.getElementById('authenticateButton').onclick = async () => {
        showMessage('Waiting for key...', 'info');
        try {
            const startRes = await fetch('/api/auth/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId })
            });
            if (!startRes.ok) throw new Error('Authentication failed.');
            const options = await startRes.json();
            const publicKey = options.publicKey || options;
            publicKey.challenge = base64url_to_uint8array(publicKey.challenge);
            if (publicKey.allowCredentials) {
                publicKey.allowCredentials.forEach(c => c.id = base64url_to_uint8array(c.id));
            }
            const credential = await navigator.credentials.get({ publicKey });
            const credentialJson = JSON.stringify({
                id: credential.id, rawId: uint8array_to_base64url(credential.rawId), type: credential.type,
                response: {
                    authenticatorData: uint8array_to_base64url(credential.response.authenticatorData),
                    clientDataJSON: uint8array_to_base64url(credential.response.clientDataJSON),
                    signature: uint8array_to_base64url(credential.response.signature),
                    userHandle: credential.response.userHandle ? uint8array_to_base64url(credential.response.userHandle) : null,
                },
                extensions: credential.getClientExtensionResults(),
            });
            const finishRes = await fetch('/api/auth/finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_id: userId, fido2_response: credentialJson, device_code: deviceCode })
            });
            if (!finishRes.ok) throw new Error('Authentication failed.');
            showMessage('✅ Success! You can close this page.', 'success');
        } catch (e) { showMessage(e.message, 'error'); }
    };
</script></body></html>"#.to_string()))
}

/// POST /auth/device/token - Polling para obter token após Security Keyauth
pub async fn device_flow_token<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    Json(req): Json<DeviceFlowTokenRequest>,
) -> Json<DeviceFlowTokenResponse> {
    let mut flows = state.device_flows.lock().await;
    prune_expired_device_flows(&mut flows);

    let ready = flows
        .get(&req.device_code)
        .map(|f| f.access_token.is_some())
        .unwrap_or(false);
    if ready {
        // Uso único: o flow é removido assim que o token é entregue.
        if let Some(token) = flows.remove(&req.device_code).and_then(|f| f.access_token) {
            return Json(DeviceFlowTokenResponse {
                access_token: Some(token),
                status: "success".to_string(),
                expires_in: Some(EXPIRE_DATE),
            });
        }
    }

    Json(DeviceFlowTokenResponse {
        access_token: None,
        status: "pending".to_string(),
        expires_in: None,
    })
}

/// POST /api/auth/device/lookup-code - Lookup device flow by user code
pub async fn device_flow_lookup_code<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
    Json(req): Json<DeviceFlowLookupRequest>,
) -> Result<Json<DeviceFlowLookupResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Rate-limit por IP: antes sem throttle → brute-force do código curto.
    let client_ip = extract_ip_from_headers(&headers);
    if !state
        .rate_limiter
        .is_allowed(&format!("lookup|{}", client_ip))
        .await
    {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Please try again later.",
        ));
    }

    let user_code = req.user_code.to_uppercase(); // Ensure uppercase for comparison

    let mut flows = state.device_flows.lock().await;
    prune_expired_device_flows(&mut flows);

    // Resposta genérica (sem distinguir inexistente vs expirado) + atraso
    // para dificultar enumeração online.
    let found = flows
        .iter_mut()
        .find(|(_, flow_status)| flow_status.user_code == user_code)
        .map(|(device_code, flow_status)| {
            flow_status.attempts = flow_status.attempts.saturating_add(1);
            (device_code.clone(), flow_status.clone())
        });
    let (device_code, flow_status) = match found {
        Some(v) => v,
        None => {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "Invalid or expired user code. Please check your terminal.",
            ));
        }
    };
    // Limite de tentativas por código; um flow já concluído não é reutilizável.
    if flow_status.attempts > 10 || flow_status.access_token.is_some() {
        flows.remove(&device_code);
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts for this code.",
        ));
    }

    info!(
        "User code lookup successful for user_id={}",
        flow_status.user_id
    );

    Ok(Json(DeviceFlowLookupResponse {
        device_code,
        user_id: flow_status.user_id,
    }))
}

pub async fn home<S: SessionStore + Clone>(
    State(_state): State<AuthHandlerState<S>>,
) -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RSB Shield</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; padding: 50px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; }
        h1 { color: #2c3e50; }
        a { display: inline-block; margin-top: 20px; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 RSB Shield</h1>
        <p>Security system for secure backup with Security Key authentication</p>
        <a href="/auth/device/start">Start Authentication</a>
    </div>
</body>
</html>"#,
    )
}

pub async fn device_flow_page<S: SessionStore + Clone>(
    State(_state): State<AuthHandlerState<S>>,
) -> Html<String> {
    Html(r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Device Flow</title>
    <style>
        body { font-family: sans-serif; display: flex; flex-direction: column; align-items: center; padding: 50px; background: #f5f5f5; }
        .container { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 500px; }
        .code { font-size: 48px; font-weight: bold; color: #2c3e50; margin: 20px; letter-spacing: 8px; text-align: center; font-family: monospace; }
        .loading { color: #3498db; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>✅ Verification Code</h1>
        <p>Your verification code:</p>
        <div class="code" id="code" style="display: none;">------</div>
        <div class="loading"><p>Generating code...</p></div>
    </div>
    <script>
        fetch('/auth/device/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: 'cli-user' })
        })
        .then(r => r.json())
        .then(d => {
            const codeDiv = document.getElementById('code');
            codeDiv.innerText = d.user_code;
            codeDiv.style.display = 'block';
            document.querySelector('.loading').style.display = 'none';
            console.log('Verification URL:', d.verification_url);
        })
        .catch(e => {
            console.error('Error:', e);
            document.querySelector('.loading').innerText = 'Error generating code';
        });
    </script>
</body>
</html>"#.to_string())
}

pub async fn device_flow_start_api<S: SessionStore + Clone>(
    State(state): State<AuthHandlerState<S>>,
    headers: HeaderMap,
) -> Result<Json<DeviceFlowStartResponse>, (StatusCode, Json<ErrorResponse>)> {
    create_device_flow(&state, &headers, "cli-user")
        .await
        .map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_code_never_panics_and_uses_alphabet() {
        // Regressão: `b % 32` num alfabeto de 31 símbolos fazia panic
        // (índice fora dos limites) em ~22% das gerações.
        for _ in 0..5000 {
            let code = generate_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(code.bytes().all(|c| USER_CODE_ALPHABET.contains(&c)));
        }
    }

    #[test]
    fn test_user_code_alphabet_fully_used() {
        // Todos os símbolos (incluindo o último, '9') devem ser alcançáveis.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..2000 {
            for c in generate_user_code().bytes() {
                seen.insert(c);
            }
        }
        assert_eq!(seen.len(), USER_CODE_ALPHABET.len());
    }
}
