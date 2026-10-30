//! 使用本地模拟 fnOS WebSocket 服务器验证完整登录、刷新和签名流程。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::Message;

use fnos_git_auth::auth::{AuthService, LoginOptions};
use fnos_git_auth::config::{ConfigStore, ServerConfig};
use fnos_git_auth::crypto::{aes_cbc_decrypt, aes_cbc_encrypt};
use fnos_git_auth::git::GitRunner;
use fnos_git_auth::hooks;
use fnos_git_auth::paths::AppPaths;

const SIGN_KEY: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
const USERNAME: &str = "alice";
const PASSWORD: &str = "correct horse battery staple";
const TWOFA_USER: &str = "twofa-user";
const TWOFA_CODE: &str = "583213";

type HmacSha256 = Hmac<Sha256>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_then_refresh_with_fn_and_long_tokens() {
    let private_key =
        Arc::new(RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate RSA key"));
    let public_key = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode public key");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let entries = Arc::new(AtomicU64::new(0));
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));

    let server = tokio::spawn(run_server(
        listener,
        private_key,
        public_key,
        entries,
        seen.clone(),
        3,
        None,
    ));

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().join("config"));
    let git = GitRunner::with_global_config(dir.path().join("gitconfig"));
    let store = ConfigStore::new(paths.clone());
    store
        .set_preference("use_ssl", json!(false))
        .expect("set ssl");
    store
        .set_preference("timeout", json!(10.0))
        .expect("set timeout");

    let service = AuthService::with_git(paths.clone(), git.clone());
    service
        .login(&address.to_string(), USERNAME, PASSWORD)
        .await
        .expect("login");

    let server_config = store.server().expect("server config");
    assert_eq!(server_config.fnos_token.as_deref(), Some("fnos-token-1"));
    assert_eq!(
        server_config.long_token.as_deref(),
        Some("long-token-value")
    );
    assert_eq!(server_config.entry_token.as_deref(), Some("entry-token-1"));
    assert_eq!(
        server_config.sign_key.as_deref(),
        Some(BASE64.encode(SIGN_KEY).as_str())
    );
    assert_eq!(
        git.get_extra_header(&address.to_string()).as_deref(),
        Some("Cookie: entry-token=entry-token-1")
    );
    assert!(hooks::has(&paths, &git));

    service
        .refresh(false)
        .await
        .expect("refresh with fnos token");
    assert_eq!(
        store.server().unwrap().entry_token.as_deref(),
        Some("entry-token-2")
    );
    assert_eq!(
        git.get_extra_header(&address.to_string()).as_deref(),
        Some("Cookie: entry-token=entry-token-2")
    );

    let mut server_config = store.server().unwrap();
    server_config.fnos_token_expires_at = Some("2000-01-01T00:00:00+00:00".to_string());
    store
        .save_server_config(server_config, false)
        .expect("expire fnos token");

    service
        .refresh(false)
        .await
        .expect("refresh with long token");
    let server_config = store.server().unwrap();
    assert_eq!(
        server_config.fnos_token.as_deref(),
        Some("fnos-token-from-long")
    );
    assert_eq!(server_config.entry_token.as_deref(), Some("entry-token-3"));
    assert_eq!(
        git.get_extra_header(&address.to_string()).as_deref(),
        Some("Cookie: entry-token=entry-token-3")
    );

    timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not finish")
        .expect("server task");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec![
            "util.crypto.getRSAPub",
            "user.login",
            "appcgi.sac.entry.v1.exchangeEntryToken",
            "util.crypto.getRSAPub",
            "user.authToken",
            "appcgi.sac.entry.v1.exchangeEntryToken",
            "util.crypto.getRSAPub",
            "user.tokenLogin",
            "appcgi.sac.entry.v1.exchangeEntryToken",
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_factor_login_with_totp_and_trusted_device() {
    let private_key =
        Arc::new(RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("generate RSA key"));
    let public_key = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode public key");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    let entries = Arc::new(AtomicU64::new(0));
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let server = tokio::spawn(run_server(
        listener,
        private_key,
        public_key,
        entries,
        seen.clone(),
        2,
        Some(TWOFA_USER),
    ));

    let dir = tempfile::tempdir().expect("tempdir");
    let paths = AppPaths::new(dir.path().join("config"));
    let git = GitRunner::with_global_config(dir.path().join("gitconfig"));
    let store = ConfigStore::new(paths.clone());
    store.set_preference("use_ssl", json!(false)).unwrap();
    store.set_preference("timeout", json!(10.0)).unwrap();
    let mut existing = ServerConfig::new(address.to_string());
    existing.did = Some("fixed-device-id".to_string());
    store.save_server_config(existing, false).unwrap();

    let service = AuthService::with_git(paths.clone(), git.clone());
    let error = service
        .login_with_options(
            &address.to_string(),
            TWOFA_USER,
            PASSWORD,
            LoginOptions {
                two_factor_code: Some("000000".to_string()),
                trust_device: true,
                interactive_two_factor: false,
            },
        )
        .await
        .expect_err("wrong code must fail");
    assert!(error.to_string().contains("验证码错误"));

    service
        .login_with_options(
            &address.to_string(),
            TWOFA_USER,
            PASSWORD,
            LoginOptions {
                two_factor_code: Some(TWOFA_CODE.to_string()),
                trust_device: true,
                interactive_two_factor: false,
            },
        )
        .await
        .expect("two-factor login");

    let config = store.server().expect("server config");
    assert_eq!(config.fnos_token.as_deref(), Some("fnos-token-2fa"));
    assert_eq!(config.entry_token.as_deref(), Some("entry-token-1"));
    assert!(config.long_token.is_none());
    assert_eq!(config.did.as_deref(), Some("fixed-device-id"));
    assert_eq!(
        config.sign_key.as_deref(),
        Some(BASE64.encode(SIGN_KEY).as_str())
    );
    assert_eq!(
        git.get_extra_header(&address.to_string()).as_deref(),
        Some("Cookie: entry-token=entry-token-1")
    );

    timeout(Duration::from_secs(5), server)
        .await
        .expect("server did not finish")
        .expect("server task");

    assert_eq!(
        seen.lock().unwrap().clone(),
        vec![
            "util.crypto.getRSAPub",
            "user.login",
            "user.2fa.loginVerify",
            "util.crypto.getRSAPub",
            "user.login",
            "user.2fa.loginVerify",
            "appcgi.sac.entry.v1.exchangeEntryToken",
        ]
    );
}

async fn run_server(
    listener: TcpListener,
    private_key: Arc<RsaPrivateKey>,
    public_key: String,
    entries: Arc<AtomicU64>,
    seen: Arc<Mutex<Vec<String>>>,
    connections: usize,
    twofa_user: Option<&'static str>,
) {
    for _ in 0..connections {
        let (stream, _) = listener.accept().await.expect("accept");
        let websocket = accept_async(stream).await.expect("websocket handshake");
        handle_connection(
            websocket,
            Arc::clone(&private_key),
            public_key.clone(),
            Arc::clone(&entries),
            Arc::clone(&seen),
            twofa_user,
        )
        .await;
    }
}

async fn handle_connection(
    websocket: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    private_key: Arc<RsaPrivateKey>,
    public_key: String,
    entries: Arc<AtomicU64>,
    seen: Arc<Mutex<Vec<String>>>,
    twofa_user: Option<&'static str>,
) {
    let (mut sink, mut stream) = websocket.split();

    while let Some(message) = stream.next().await {
        let message = match message {
            Ok(Message::Text(text)) => text,
            Ok(Message::Close(_)) | Err(_) => break,
            Ok(_) => continue,
        };

        let (mut req, mut reqid, mut body) = decode_request(&message);
        let mut encrypted_keys = None;

        if req == "encrypted" {
            let outer: Value = serde_json::from_str(&message).expect("outer json");
            let key = private_key
                .decrypt(
                    Pkcs1v15Encrypt,
                    &BASE64
                        .decode(outer["rsa"].as_str().unwrap())
                        .expect("rsa b64"),
                )
                .expect("rsa decrypt");
            let iv = BASE64
                .decode(outer["iv"].as_str().unwrap())
                .expect("iv b64");
            let ciphertext = BASE64
                .decode(outer["aes"].as_str().unwrap())
                .expect("aes b64");
            let plaintext = aes_cbc_decrypt(&ciphertext, &key, &iv).expect("aes decrypt");
            let inner: Value = serde_json::from_slice(&plaintext).expect("encrypted inner json");

            req = inner["req"].as_str().expect("inner req").to_string();
            reqid = inner["reqid"].as_str().expect("inner reqid").to_string();
            body = inner;
            encrypted_keys = Some((key, iv));
        }

        seen.lock().unwrap().push(req.clone());

        let response = match req.as_str() {
            "util.crypto.getRSAPub" => json!({
                "reqid": reqid,
                "pub": public_key,
                "si": "test-si",
                "result": "succ",
            }),
            "user.login" => {
                assert_eq!(body["password"], PASSWORD);
                assert_eq!(body["stay"], true);
                assert!(!body["did"].as_str().unwrap_or_default().is_empty());

                if body["user"].as_str() == twofa_user {
                    assert_eq!(body["did"], "fixed-device-id");
                    json!({
                        "reqid": reqid,
                        "isTwofaEnforced": true,
                        "isBindTwofaSecret": true,
                        "isBindSecureEmail": true,
                        "secureEmail": "al***@example.com",
                        "isTrustedDevice": false,
                        "accessToken": "2fa-access-token",
                        "result": "succ",
                    })
                } else {
                    assert_eq!(body["user"], USERNAME);
                    let (key, iv) = encrypted_keys.expect("encrypted login");
                    let secret = BASE64.encode(
                        aes_cbc_encrypt(SIGN_KEY, &key, &iv).expect("encrypt server secret"),
                    );
                    json!({
                        "reqid": reqid,
                        "uid": 1000,
                        "admin": true,
                        "secret": secret,
                        "token": "fnos-token-1",
                        "longToken": "long-token-value",
                        "backId": "0000000000000001",
                        "result": "succ",
                    })
                }
            }
            "user.2fa.loginVerify" => {
                assert_eq!(body["accessToken"], "2fa-access-token");
                assert_eq!(body["isTrustedDevice"], true);
                assert_eq!(body["stay"], 1);
                assert_eq!(body["deviceType"], "Browser");
                assert_eq!(body["deviceName"], "fnos-git-auth");
                assert_eq!(body["did"], "fixed-device-id");
                assert_eq!(body["si"], "test-si");

                if body["code"] != TWOFA_CODE {
                    json!({
                        "reqid": reqid,
                        "errno": 135168,
                        "result": "fail",
                    })
                } else {
                    let (key, iv) = encrypted_keys.expect("encrypted 2fa");
                    let secret = BASE64.encode(
                        aes_cbc_encrypt(SIGN_KEY, &key, &iv).expect("encrypt server secret"),
                    );
                    json!({
                        "reqid": reqid,
                        "uid": 1001,
                        "admin": true,
                        "secret": secret,
                        "token": "fnos-token-2fa",
                        "backId": "0000000000000002",
                        "result": "succ",
                    })
                }
            }
            "user.authToken" => {
                assert_eq!(body["token"], "fnos-token-1");
                assert_eq!(body["si"], "test-si");
                json!({
                    "reqid": reqid,
                    "uid": 1000,
                    "admin": true,
                    "backId": "0000000000000001",
                    "result": "succ",
                })
            }
            "user.tokenLogin" => {
                assert_eq!(body["token"], "long-token-value");
                // 本地模拟服务器不知道新连接的 AES key，故意返回无法解密的 secret，
                // 客户端应回退到已保存的 sign_key。
                let decoy_key = b"abcdefghijklmnopqrstuvwxyz012345";
                let decoy_iv = [0u8; 16];
                let secret = BASE64
                    .encode(aes_cbc_encrypt(b"decoy-secret", decoy_key, &decoy_iv).expect("decoy"));
                json!({
                    "reqid": reqid,
                    "token": "fnos-token-from-long",
                    "secret": secret,
                    "uid": 1000,
                    "admin": true,
                    "backId": "0000000000000002",
                    "result": "succ",
                })
            }
            "appcgi.sac.entry.v1.exchangeEntryToken" => {
                let number = entries.fetch_add(1, Ordering::SeqCst) + 1;
                json!({
                    "reqid": reqid,
                    "data": {"token": format!("entry-token-{number}")},
                    "result": "succ",
                })
            }
            "user.logout" => json!({"reqid": reqid, "result": "succ"}),
            other => panic!("unexpected request: {other}"),
        };

        if sink
            .send(Message::text(response.to_string()))
            .await
            .is_err()
        {
            break;
        }
    }
}

/// 返回 (req, reqid, body)，并验证签名。
fn decode_request(message: &str) -> (String, String, Value) {
    let (json_text, signature) = if message.starts_with('{') {
        (message, None)
    } else {
        assert!(message.len() > 44, "signed message too short");
        let (signature, json) = message.split_at(44);
        (json, Some(signature))
    };

    let body: Value = serde_json::from_str(json_text).expect("request json");
    let req = body["req"].as_str().expect("req").to_string();

    let signature_required = !matches!(
        req.as_str(),
        "encrypted" | "util.getSI" | "util.crypto.getRSAPub" | "ping"
    );

    if signature_required {
        let signature = signature.expect("request must be signed");
        let mut mac = HmacSha256::new_from_slice(SIGN_KEY).expect("hmac");
        mac.update(json_text.as_bytes());
        mac.verify_slice(&BASE64.decode(signature).expect("signature b64"))
            .expect("valid signature");
    }

    (
        req,
        body["reqid"].as_str().unwrap_or_default().to_string(),
        body,
    )
}
