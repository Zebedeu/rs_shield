//! FIDO2/WebAuthn login end to end with a software authenticator.
//!
//! `webauthn-authenticator-rs`'s `SoftPasskey` plays the browser + security
//! key, so registration, assertion and the JWT session that a login issues
//! can be checked without a physical key:
//!
//! * `Fido2Manager` level: registration → authentication, and rejection of a
//!   foreign credential, a tampered signature/authenticator data, a replayed
//!   challenge and a wrong origin (no keyring needed);
//! * HTTP level: registration through the FIDO2 web server, device-flow
//!   login through the auth server, JWT issued, validated (server and CLI
//!   side) and revoked on logout. Persisting credentials needs the OS
//!   keyring: that test uses an isolated keyring service
//!   (`RSB_FIDO2_KEYRING_SERVICE`, deleted afterwards) and is skipped when
//!   no keyring backend exists.

use rsb_sdk::auth::{
    AuditLogger, AuthResponse, JwtManager, PersistentSessionStore, RateLimiter, SessionRegistry,
};
use rsb_sdk::credentials::{Fido2Error, Fido2Manager};
use rsb_sdk::fido2::fido2_web::{ServerMode, ServerState, create_router};
use rsb_sdk::server::handlers::{DeviceFlowStartResponse, DeviceFlowTokenResponse};
use rsb_sdk::server::routes::verify_token_locally;
use rsb_sdk::server::{AuthHandlerState, create_auth_router};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url,
};

const ORIGIN: &str = "http://localhost:3000";

fn origin() -> Url {
    Url::parse(ORIGIN).unwrap()
}

fn manager() -> Fido2Manager {
    Fido2Manager::new(ORIGIN, "localhost", "RSB Test").unwrap()
}

/// A software passkey. `true` sets the user-verified flag, which passkey
/// registration and authentication require.
fn token() -> WebauthnAuthenticator<SoftPasskey> {
    WebauthnAuthenticator::new(SoftPasskey::new(true))
}

fn register(m: &mut Fido2Manager, key: &mut WebauthnAuthenticator<SoftPasskey>, user: &str) {
    let ccr = m
        .start_registration(user, &format!("{user}@example.com"), user)
        .unwrap();
    let reg = key.do_registration(origin(), ccr).unwrap();
    m.finish_registration(reg).unwrap();
    assert!(m.has_credential(user));
}

fn assertion(
    m: &mut Fido2Manager,
    key: &mut WebauthnAuthenticator<SoftPasskey>,
    user: &str,
) -> PublicKeyCredential {
    let rcr = m.start_authentication(user).unwrap();
    key.do_authentication(origin(), rcr).unwrap()
}

fn is_auth_failure(e: &Fido2Error) -> bool {
    matches!(e, Fido2Error::AuthenticationFailed(_))
}

#[test]
fn registration_then_authentication_succeeds() {
    let mut m = manager();
    let mut key = token();
    register(&mut m, &mut key, "alice");
    assert_eq!(m.list_user_credentials("alice").len(), 1);
    assert_eq!(m.list_user_credentials("alice")[0].counter, 0);

    let a = assertion(&mut m, &mut key, "alice");
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");
    let cred = &m.list_user_credentials("alice")[0];
    assert!(cred.last_used.is_some());
    let first_counter = cred.counter;
    assert!(first_counter > 0, "signature counter is recorded");

    // A second login with the same key works and advances the counter.
    let a = assertion(&mut m, &mut key, "alice");
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");
    assert!(m.list_user_credentials("alice")[0].counter > first_counter);
}

#[test]
fn second_key_can_be_registered_and_used() {
    let mut m = manager();
    let mut k1 = token();
    let mut k2 = token();
    register(&mut m, &mut k1, "alice");
    register(&mut m, &mut k2, "alice");
    assert_eq!(m.list_user_credentials("alice").len(), 2);
    for key in [&mut k1, &mut k2] {
        let a = assertion(&mut m, key, "alice");
        assert_eq!(m.finish_authentication(a).unwrap(), "alice");
    }
}

#[test]
fn foreign_credential_is_rejected() {
    let mut m = manager();
    let mut alice_key = token();
    let mut bob_key = token();
    register(&mut m, &mut alice_key, "alice");
    register(&mut m, &mut bob_key, "bob");

    // Bob's key answers a challenge issued for Alice (the browser is told
    // to use Bob's credential instead of Alice's).
    let mut rcr: RequestChallengeResponse = m.start_authentication("alice").unwrap();
    let bob_allowed = m
        .start_authentication("bob")
        .unwrap()
        .public_key
        .allow_credentials;
    rcr.public_key.allow_credentials = bob_allowed;
    let forged = bob_key.do_authentication(origin(), rcr).unwrap();
    let err = m.finish_authentication(forged).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");

    // A key that was never registered at all.
    let mut stranger = token();
    let mut other = manager();
    register(&mut other, &mut stranger, "alice");
    let mut rcr = m.start_authentication("alice").unwrap();
    rcr.public_key.allow_credentials = other
        .start_authentication("alice")
        .unwrap()
        .public_key
        .allow_credentials;
    let forged = stranger.do_authentication(origin(), rcr).unwrap();
    let err = m.finish_authentication(forged).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");

    // Alice can still log in.
    let a = assertion(&mut m, &mut alice_key, "alice");
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");
}

#[test]
fn tampered_assertion_is_rejected() {
    let mut m = manager();
    let mut key = token();
    register(&mut m, &mut key, "alice");

    // Signature: flip one bit in the middle and at the end.
    for pick in [|n: usize| n / 2, |n: usize| n - 1] {
        let mut a = assertion(&mut m, &mut key, "alice");
        let i = pick(a.response.signature.len());
        a.response.signature[i] ^= 0x01;
        let err = m.finish_authentication(a).unwrap_err();
        assert!(is_auth_failure(&err), "{err:?}");
    }

    // Authenticator data (signed): flip a bit of the counter.
    let mut a = assertion(&mut m, &mut key, "alice");
    let last = a.response.authenticator_data.len() - 1;
    a.response.authenticator_data[last] ^= 0x01;
    let err = m.finish_authentication(a).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");

    // Client data (signed through its hash): change the type, keep the
    // challenge so the pending state is still found.
    let mut a = assertion(&mut m, &mut key, "alice");
    let cd = String::from_utf8(a.response.client_data_json.to_vec()).unwrap();
    let tampered = cd.replace("webauthn.get", "webauthn.got");
    assert_ne!(cd, tampered);
    a.response.client_data_json = tampered.into_bytes().into();
    let err = m.finish_authentication(a).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");

    // Nothing above counted as a login.
    assert!(m.list_user_credentials("alice")[0].last_used.is_none());
    let a = assertion(&mut m, &mut key, "alice");
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");
}

#[test]
fn replayed_challenge_is_rejected() {
    let mut m = manager();
    let mut key = token();
    register(&mut m, &mut key, "alice");

    let a = assertion(&mut m, &mut key, "alice");
    let replay = a.clone();
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");
    // The challenge was consumed by the first use.
    assert!(matches!(
        m.finish_authentication(replay.clone()),
        Err(Fido2Error::NoAuthenticationInProgress)
    ));
    // Still rejected while a fresh challenge is pending.
    let fresh = m.start_authentication("alice").unwrap();
    assert!(m.finish_authentication(replay).is_err());
    let a = key.do_authentication(origin(), fresh).unwrap();
    assert_eq!(m.finish_authentication(a).unwrap(), "alice");

    // A registration response cannot be replayed either.
    let ccr: CreationChallengeResponse = m
        .start_registration("bob", "bob@example.com", "Bob")
        .unwrap();
    let reg: RegisterPublicKeyCredential = token().do_registration(origin(), ccr).unwrap();
    m.finish_registration(reg.clone()).unwrap();
    assert!(matches!(
        m.finish_registration(reg),
        Err(Fido2Error::NoRegistrationInProgress)
    ));
    assert_eq!(m.list_user_credentials("bob").len(), 1);
}

#[test]
fn wrong_origin_is_rejected() {
    // Same RP id (`localhost`) so the client accepts it, different origin.
    let evil = Url::parse("http://localhost:4000").unwrap();

    let mut m = manager();
    let mut key = token();
    let ccr = m
        .start_registration("mallory", "mallory@example.com", "Mallory")
        .unwrap();
    let reg = key.do_registration(evil.clone(), ccr).unwrap();
    assert!(matches!(
        m.finish_registration(reg),
        Err(Fido2Error::RegistrationFailed(_))
    ));
    assert!(!m.has_credential("mallory"));

    register(&mut m, &mut key, "alice");
    let rcr = m.start_authentication("alice").unwrap();
    let a = key.do_authentication(evil.clone(), rcr).unwrap();
    let err = m.finish_authentication(a).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");

    // The other way round: a relying party on the other origin rejects
    // assertions made for this one.
    let mut other = Fido2Manager::new(evil.as_str(), "localhost", "Other").unwrap();
    let mut key2 = token();
    let ccr = other
        .start_registration("alice", "alice@example.com", "Alice")
        .unwrap();
    let reg = key2.do_registration(evil.clone(), ccr).unwrap();
    other.finish_registration(reg).unwrap();
    let rcr = other.start_authentication("alice").unwrap();
    let a = key2.do_authentication(origin(), rcr).unwrap();
    let err = other.finish_authentication(a).unwrap_err();
    assert!(is_auth_failure(&err), "{err:?}");
    let rcr = other.start_authentication("alice").unwrap();
    let a = key2.do_authentication(evil, rcr).unwrap();
    assert_eq!(other.finish_authentication(a).unwrap(), "alice");
}

// ---------------------------------------------------------------------------
// HTTP: register on the FIDO2 web server, log in on the auth server.
// ---------------------------------------------------------------------------

/// Isolated keyring service for the credential-file DEK, deleted on drop.
struct KeyringService(String);

impl KeyringService {
    /// `None` when the platform has no usable keyring backend.
    fn isolated() -> Option<Self> {
        let service = format!("rsb-fido2-dek-test-{}", uuid::Uuid::new_v4());
        let probe = keyring::Entry::new(&service, "default")
            .and_then(|entry| entry.set_password("probe").map(|_| entry));
        match probe {
            Ok(entry) => {
                let _ = entry.delete_password();
            }
            Err(e) => {
                eprintln!("skipping: no keyring backend ({e})");
                return None;
            }
        }
        // SAFETY: the only test of this binary that reads this variable.
        unsafe { std::env::set_var("RSB_FIDO2_KEYRING_SERVICE", &service) };
        Some(Self(service))
    }
}

impl Drop for KeyringService {
    fn drop(&mut self) {
        if let Ok(entry) = keyring::Entry::new(&self.0, "default") {
            let _ = entry.delete_password();
        }
    }
}

async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_register_login_issues_and_revokes_jwt() {
    let Some(_keyring) = KeyringService::isolated() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cred_file = dir.path().join("fido2_credentials.json");
    let manager = Arc::new(Mutex::new(manager()));
    let http = reqwest::Client::new();
    let mut key = token();

    // --- Registration on the FIDO2 web server (per-run access token). ---
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let web_port = listener.local_addr().unwrap().port();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let access_token = "t".repeat(64);
    let web_state = ServerState {
        manager: manager.clone(),
        done_tx: Arc::new(Mutex::new(Some(done_tx))),
        access_token: Arc::new(access_token.clone()),
        port: web_port,
        mode: ServerMode::Register,
        authenticated_users: Arc::new(Mutex::new(HashSet::new())),
        storage_path: cred_file.clone(),
    };
    let router = create_router(web_state, axum::response::Html("<html></html>"));
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let web = format!("http://127.0.0.1:{web_port}");
    let body = serde_json::json!({
        "user_id": "alice", "username": "alice@example.com", "display_name": "Alice"
    });

    // Without the per-run token the API refuses.
    let resp = http
        .post(format!("{web}/register/start"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let ccr: CreationChallengeResponse = http
        .post(format!("{web}/register/start"))
        .header("x-rsb-token", &access_token)
        .json(&body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let reg = key.do_registration(origin(), ccr).unwrap();
    let ok: bool = http
        .post(format!("{web}/register/finish"))
        .header("x-rsb-token", &access_token)
        .json(&reg)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(ok);
    // Register mode stops the server after a successful registration.
    done_rx.await.unwrap();
    assert!(cred_file.exists(), "credentials persisted");

    // The persisted file reloads (with the isolated keyring DEK).
    let mut reloaded = Fido2Manager::new(ORIGIN, "localhost", "RSB Test").unwrap();
    reloaded.load_from_file(&cred_file).unwrap();
    assert!(reloaded.has_credential("alice"));

    // --- Login on the auth server (device flow, as `rsb login` does). ---
    let jwt = Arc::new(JwtManager::new(&"s".repeat(48)).unwrap());
    let registry = SessionRegistry::new(dir.path().join("sessions.json"));
    let state = AuthHandlerState {
        jwt_manager: jwt.clone(),
        fido2_manager: manager.clone(),
        session_store: Arc::new(PersistentSessionStore::new(registry.clone())),
        device_flows: Arc::new(Mutex::new(HashMap::new())),
        rate_limiter: Arc::new(RateLimiter::new(50, 60)),
        audit_logger: Arc::new(AuditLogger::new(Some(
            dir.path().join("audit.log").to_string_lossy().into_owned(),
        ))),
        fido2_storage_path: cred_file.clone(),
        public_base_url: ORIGIN.to_string(),
    };
    let api = serve(create_auth_router(state)).await;

    let flow: DeviceFlowStartResponse = http
        .post(format!("{api}/auth/device/start"))
        .json(&serde_json::json!({ "user_id": "alice" }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let poll = || async {
        http.post(format!("{api}/auth/device/token"))
            .json(&serde_json::json!({ "device_code": flow.device_code }))
            .send()
            .await
            .unwrap()
            .json::<DeviceFlowTokenResponse>()
            .await
            .unwrap()
    };
    assert_eq!(poll().await.status, "pending");

    let start = || async {
        http.post(format!("{api}/api/auth/start"))
            .json(&serde_json::json!({ "user_id": "alice" }))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<RequestChallengeResponse>()
            .await
            .unwrap()
    };
    let finish = |cred: &PublicKeyCredential, device_code: Option<&str>| {
        let body = serde_json::json!({
            "user_id": "alice",
            "fido2_response": serde_json::to_string(cred).unwrap(),
            "device_code": device_code,
        });
        let req = http.post(format!("{api}/api/auth/finish")).json(&body);
        async move { req.send().await.unwrap() }
    };

    // Tampered signature: 401, no token for the device flow.
    let mut bad = key.do_authentication(origin(), start().await).unwrap();
    let n = bad.response.signature.len();
    bad.response.signature[n / 2] ^= 0x40;
    assert_eq!(finish(&bad, Some(&flow.device_code)).await.status(), 401);
    assert_eq!(poll().await.status, "pending");

    // Wrong origin: 401.
    let evil = Url::parse("http://localhost:4000").unwrap();
    let bad = key.do_authentication(evil, start().await).unwrap();
    assert_eq!(finish(&bad, Some(&flow.device_code)).await.status(), 401);

    // Valid assertion completes the device flow.
    let good = key.do_authentication(origin(), start().await).unwrap();
    let resp = finish(&good, Some(&flow.device_code)).await;
    assert_eq!(resp.status(), 200);
    let auth: AuthResponse = resp.json().await.unwrap();
    assert_eq!(auth.user_id, "alice");
    assert_eq!(auth.token_type, "Bearer");

    // Replaying the same assertion fails (challenge consumed).
    assert_eq!(finish(&good, None).await.status(), 401);

    // The CLI polls the token once; the flow is single use.
    let polled = poll().await;
    assert_eq!(polled.status, "success");
    let token = polled.access_token.unwrap();
    assert_eq!(token, auth.access_token);
    assert_eq!(poll().await.status, "pending");

    // JWT: valid signature/claims, an active session server side and in the
    // persisted registry the CLI reads.
    let claims = jwt.verify_token(&token).unwrap();
    assert_eq!(claims.sub, "alice");
    assert!(claims.has_scope("backup") && claims.has_scope("restore"));
    assert_eq!(
        verify_token_locally(&token, &jwt, &registry).unwrap().sub,
        "alice"
    );
    let other_secret = JwtManager::new(&"o".repeat(48)).unwrap();
    assert!(verify_token_locally(&token, &other_secret, &registry).is_err());

    let verify = |t: String| {
        let req = http
            .get(format!("{api}/api/auth/verify"))
            .header("Authorization", format!("Bearer {t}"));
        async move { req.send().await.unwrap().status() }
    };
    assert_eq!(verify(token.clone()).await, 200);
    let mut forged = token.clone().into_bytes();
    let i = forged.len() - 3;
    forged[i] = if forged[i] == b'A' { b'B' } else { b'A' };
    assert_eq!(verify(String::from_utf8(forged).unwrap()).await, 401);

    // The counter was persisted before the token was issued.
    let mut reloaded = Fido2Manager::new(ORIGIN, "localhost", "RSB Test").unwrap();
    reloaded.load_from_file(&cred_file).unwrap();
    assert!(reloaded.list_user_credentials("alice")[0].counter > 0);

    // Logout revokes the session everywhere.
    let resp = http
        .post(format!("{api}/api/auth/logout"))
        .json(&serde_json::json!({ "access_token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(verify(token.clone()).await, 401);
    assert!(verify_token_locally(&token, &jwt, &registry).is_err());
}
