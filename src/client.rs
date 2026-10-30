//! fnOS WebSocket 客户端。
//!
//! 协议要点：
//! 1. 连接 `/websocket?type=main`，fn connect 模式需要携带 Cookie；
//! 2. 先取 RSA 公钥与 `si`；
//! 3. 登录请求用 RSA + AES 混合加密；
//! 4. 其他请求以 `Base64(HMAC-SHA256(json)) + json` 的形式签名；
//! 5. 通过 `reqid` 匹配响应。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio::net::TcpStream;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::COOKIE;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

use crate::crypto::{
    aes_decrypt, encrypt_login_request, generate_iv, generate_random_string, sign_request,
};
use crate::util::generate_device_id;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type PendingSender = oneshot::Sender<Result<Value, String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoFactorKind {
    /// 已绑定 TOTP，需要提交 6 位验证码。
    Verify,
    /// 账号被强制要求 2FA，但尚未绑定 TOTP。
    SetupRequired,
}

#[derive(Debug, Clone)]
pub struct TwoFactorChallenge {
    pub kind: TwoFactorKind,
    pub access_token: String,
    pub secure_email: Option<String>,
    pub is_secure_email_bound: bool,
    pub is_trusted_device: bool,
    pub twofa_secret: Option<String>,
    pub otpauth: Option<String>,
}

static REQUEST_INDEX: AtomicU64 = AtomicU64::new(0);

fn next_request_id(back_id: &str) -> String {
    let index = REQUEST_INDEX.fetch_add(1, Ordering::Relaxed) + 1;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let back_id = if back_id.is_empty() {
        "0000000000000000"
    } else {
        back_id
    };
    format!("{timestamp:08x}{back_id}{index:04x}")
}

pub struct FnOsClient {
    timeout: Duration,
    sink: Option<futures_util::stream::SplitSink<WsStream, Message>>,
    reader_task: Option<JoinHandle<()>>,
    pending: Arc<Mutex<HashMap<String, PendingSender>>>,

    aes_key: String,
    iv: [u8; 16],

    /// RSA 公钥（PEM）。
    pub rsa_pub: Option<String>,
    /// 用于登录 / authToken 的 `si`。
    pub si: Option<String>,

    pub back_id: String,
    pub token: Option<String>,
    pub secret: Option<String>,
    pub sign_key: Option<String>,
    pub uid: Option<i64>,
    pub admin: Option<bool>,

    /// 客户端设备 ID，登录时作为 `did` 发送；“信任此设备”后复用。
    pub device_id: String,
    device_type: String,
    device_name: String,
    stay: bool,
    two_factor: Option<TwoFactorChallenge>,
}

impl FnOsClient {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            sink: None,
            reader_task: None,
            pending: Arc::new(Mutex::new(HashMap::new())),
            aes_key: String::new(),
            iv: [0u8; 16],
            rsa_pub: None,
            si: None,
            back_id: "0000000000000000".to_string(),
            token: None,
            secret: None,
            sign_key: None,
            uid: None,
            admin: None,
            device_id: String::new(),
            device_type: "Browser".to_string(),
            device_name: "fnos-git-auth".to_string(),
            stay: true,
            two_factor: None,
        }
    }

    pub fn set_device_id(&mut self, device_id: impl Into<String>) {
        self.device_id = device_id.into();
    }

    pub fn two_factor_challenge(&self) -> Option<&TwoFactorChallenge> {
        self.two_factor
            .as_ref()
            .filter(|challenge| challenge.kind == TwoFactorKind::Verify)
    }

    pub fn two_factor_setup_challenge(&self) -> Option<&TwoFactorChallenge> {
        self.two_factor
            .as_ref()
            .filter(|challenge| challenge.kind == TwoFactorKind::SetupRequired)
    }

    pub fn is_connected(&self) -> bool {
        self.sink.is_some()
    }

    /// 建立 WebSocket 连接。
    pub async fn connect(&mut self, server: &str, use_ssl: bool, cookie: &str) -> Result<()> {
        if self.sink.is_some() {
            self.close().await;
        }

        let protocol = if use_ssl { "wss" } else { "ws" };
        let url = format!("{protocol}://{server}/websocket?type=main");

        let mut request = url
            .as_str()
            .into_client_request()
            .with_context(|| format!("WebSocket 地址无效: {url}"))?;
        if use_ssl && !cookie.is_empty() {
            let value = HeaderValue::from_str(cookie).context("fn connect Cookie 含非法字符")?;
            request.headers_mut().insert(COOKIE, value);
        }

        let (stream, _response) = tokio::time::timeout(self.timeout, connect_async(request))
            .await
            .map_err(|_| anyhow!("连接 {server} 超时"))?
            .with_context(|| format!("连接 {server} 失败"))?;

        self.aes_key = generate_random_string(32);
        self.iv = generate_iv();
        self.rsa_pub = None;
        self.si = None;
        self.token = None;
        self.secret = None;
        self.sign_key = None;
        self.uid = None;
        self.admin = None;
        self.two_factor = None;
        self.back_id = "0000000000000000".to_string();

        let (sink, mut reader) = stream.split();
        self.sink = Some(sink);

        let pending = Arc::clone(&self.pending);
        self.reader_task = Some(tokio::spawn(async move {
            while let Some(message) = reader.next().await {
                match message {
                    Ok(Message::Text(text)) => dispatch_message(&pending, text.as_str()).await,
                    Ok(Message::Binary(bytes)) => {
                        if let Ok(text) = std::str::from_utf8(&bytes) {
                            dispatch_message(&pending, text).await;
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(error) => {
                        fail_all_pending(&pending, format!("WebSocket 连接异常: {error}")).await;
                        return;
                    }
                }
            }
            fail_all_pending(&pending, "WebSocket 连接已关闭".to_string()).await;
        }));

        Ok(())
    }

    pub async fn close(&mut self) {
        if let Some(task) = self.reader_task.take() {
            task.abort();
        }
        if let Some(mut sink) = self.sink.take() {
            let _ = sink.send(Message::Close(None)).await;
            let _ = sink.close().await;
        }
        fail_all_pending(&self.pending, "连接已关闭".to_string()).await;
    }

    /// 发送请求并等待同 `reqid` 的响应。
    pub async fn request(&mut self, req: &str, fields: Vec<(&str, Value)>) -> Result<Value> {
        if self.sink.is_none() {
            bail!("未连接到服务器");
        }

        let reqid = next_request_id(&self.back_id);
        let mut data = Map::new();
        data.insert("req".to_string(), Value::String(req.to_string()));
        data.insert("reqid".to_string(), Value::String(reqid.clone()));
        for (key, value) in fields {
            data.insert(key.to_string(), value);
        }
        let data = Value::Object(data);

        let encrypted_request = matches!(req, "user.login" | "user.add" | "user.2fa.loginVerify");
        if req == "user.2fa.loginVerify" {
            // 2FA 验证使用一套全新的 AES key/IV，最终登录响应中的 secret
            // 会用这套新密钥加密。
            self.aes_key = generate_random_string(32);
            self.iv = generate_iv();
        }

        let message = if encrypted_request {
            let public_key = self.rsa_pub.as_deref().context("尚未获取服务器 RSA 公钥")?;
            let json = serde_json::to_string(&data)?;
            let encrypted = encrypt_login_request(&json, public_key, &self.aes_key, &self.iv)?;
            serde_json::to_string(&encrypted)?
        } else {
            sign_request(&data, self.sign_key.as_deref())?
        };

        let (sender, receiver) = oneshot::channel();
        self.pending.lock().await.insert(reqid.clone(), sender);

        let send_result = match self.sink.as_mut() {
            Some(sink) => sink.send(Message::text(message)).await,
            None => Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed),
        };
        if let Err(error) = send_result {
            self.pending.lock().await.remove(&reqid);
            return Err(anyhow!("发送请求失败: {error}"));
        }

        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(Ok(response))) => Ok(response),
            Ok(Ok(Err(error))) => Err(anyhow!(error)),
            Ok(Err(_)) => Err(anyhow!("等待响应时连接已关闭")),
            Err(_) => {
                self.pending.lock().await.remove(&reqid);
                Err(anyhow!("请求超时: {req}"))
            }
        }
    }

    // ==================== 协议接口 ====================

    pub async fn get_rsa_pub(&mut self) -> Result<Value> {
        let response = self.request("util.crypto.getRSAPub", vec![]).await?;
        ensure_success(&response, "获取公钥失败")?;
        let public_key = response
            .get("pub")
            .and_then(Value::as_str)
            .context("服务器未返回 RSA 公钥")?;
        self.rsa_pub = Some(public_key.to_string());
        self.si = response
            .get("si")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        Ok(response)
    }

    /// 账号密码登录，`stay=true` 时会获得 long-token。
    ///
    /// 如果返回 2FA 挑战，客户端会保存挑战上下文，调用方需要继续调用
    /// [`FnOsClient::submit_two_factor_code`]。
    pub async fn login(
        &mut self,
        username: &str,
        password: &str,
        stay: bool,
        device_type: &str,
        device_name: &str,
    ) -> Result<Value> {
        if self.rsa_pub.is_none() {
            self.get_rsa_pub().await?;
        }

        self.stay = stay;
        self.device_type = device_type.to_string();
        self.device_name = device_name.to_string();
        if self.device_id.trim().is_empty() {
            self.device_id = generate_device_id();
        }

        let response = self
            .request(
                "user.login",
                vec![
                    ("user", json!(username)),
                    ("password", json!(password)),
                    ("stay", json!(stay)),
                    ("deviceType", json!(device_type)),
                    ("deviceName", json!(device_name)),
                    ("did", json!(self.device_id)),
                    ("si", json!(self.si)),
                ],
            )
            .await?;
        ensure_success(&response, "登录失败")?;

        if let Some(challenge) = classify_two_factor(&response) {
            self.two_factor = Some(challenge);
            return Ok(response);
        }

        self.apply_login_response(&response)?;
        if self.token.is_none() {
            let has_access_token = response
                .get("accessToken")
                .and_then(Value::as_str)
                .is_some_and(|token| !token.is_empty());
            if has_access_token {
                let bind_secure_email = bool_field(&response, "isBindSecureEmail").unwrap_or(false);
                let bind_totp = bool_field(&response, "isBindTwofaSecret").unwrap_or(false);
                if bind_secure_email && !bind_totp {
                    bail!("该账号使用安全邮箱两步验证，目前仅支持已绑定 TOTP 的账号");
                }
                bail!("收到无法识别的两步验证挑战，请升级工具后重试");
            }
            bail!("服务器未返回 token（可能登录被拒绝）");
        }
        Ok(response)
    }

    /// 提交 6 位 TOTP / 两步验证码，完成登录。
    pub async fn submit_two_factor_code(
        &mut self,
        code: &str,
        trust_device: bool,
    ) -> Result<Value> {
        if !is_six_digit_code(code) {
            bail!("两步验证码必须是 6 位数字");
        }

        let challenge = self
            .two_factor_challenge()
            .cloned()
            .context("没有待完成的两步验证登录，请重新执行 login")?;

        let response = self
            .request(
                "user.2fa.loginVerify",
                vec![
                    ("code", json!(code)),
                    ("isTrustedDevice", json!(trust_device)),
                    ("accessToken", json!(challenge.access_token)),
                    ("stay", json!(if self.stay { 1 } else { 0 })),
                    ("deviceName", json!(self.device_name)),
                    ("deviceType", json!(self.device_type)),
                    ("did", json!(self.device_id)),
                    ("si", json!(self.si)),
                ],
            )
            .await?;

        if let Some(code) = response.get("errno").and_then(Value::as_i64) {
            match code {
                135168 => bail!("两步验证失败: 验证码错误或已过期"),
                102570109 => bail!("两步验证失败: 登录验证已过期，请重新执行 login"),
                _ => {}
            }
        }
        ensure_success(&response, "两步验证失败")?;

        self.apply_login_response(&response)?;
        if self.token.is_none() {
            bail!("两步验证失败: 服务器未返回 token");
        }
        self.two_factor = None;
        Ok(response)
    }

    fn apply_login_response(&mut self, response: &Value) -> Result<()> {
        if let Some(back_id) = response.get("backId").and_then(Value::as_str) {
            self.back_id = back_id.to_string();
        }
        self.token = string_field(response, "token");
        self.secret = string_field(response, "secret");
        self.uid = response.get("uid").and_then(Value::as_i64);
        self.admin = response.get("admin").and_then(Value::as_bool);

        if let Some(secret) = self.secret.as_deref() {
            self.sign_key = Some(aes_decrypt(secret, &self.aes_key, &self.iv)?);
        }
        if self.token.is_some() {
            self.two_factor = None;
        }
        Ok(())
    }

    /// 使用已有 fnos-token 验证会话，用于刷新 entry-token。
    pub async fn auth_token(&mut self, main: bool) -> Result<Value> {
        if self.si.is_none() {
            self.get_rsa_pub().await?;
        }
        let token = self.token.clone().context("缺少 fnos-token")?;
        let response = self
            .request(
                "user.authToken",
                vec![
                    ("token", json!(token)),
                    ("main", json!(main)),
                    ("si", json!(self.si)),
                ],
            )
            .await?;
        ensure_success(&response, "token 验证失败")?;

        if let Some(back_id) = response.get("backId").and_then(Value::as_str) {
            self.back_id = back_id.to_string();
        }
        self.uid = response.get("uid").and_then(Value::as_i64);
        self.admin = response.get("admin").and_then(Value::as_bool);
        Ok(response)
    }

    /// 获取 Git HTTP 认证使用的 entry-token。
    pub async fn exchange_entry_token(&mut self) -> Result<String> {
        let response = self
            .request("appcgi.sac.entry.v1.exchangeEntryToken", vec![])
            .await?;
        ensure_success(&response, "获取 entry-token 失败")?;
        response
            .get("data")
            .and_then(|data| data.get("token"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .context("服务器未返回 entry-token")
    }

    /// 使用 long-token 换取新的 fnos-token。
    pub async fn token_login(
        &mut self,
        long_token: &str,
        device_type: &str,
        device_name: &str,
    ) -> Result<Value> {
        let response = self
            .request(
                "user.tokenLogin",
                vec![
                    ("token", json!(long_token)),
                    ("deviceType", json!(device_type)),
                    ("deviceName", json!(device_name)),
                    ("did", json!(self.device_id)),
                    ("si", json!(self.si)),
                ],
            )
            .await?;
        ensure_success(&response, "long-token 登录失败")?;

        self.token = string_field(&response, "token").or_else(|| self.token.clone());
        if let Some(secret) = string_field(&response, "secret") {
            self.secret = Some(secret.clone());
            // tokenLogin 的新连接没有把本次 AES key 交给服务器，旧版服务可能返回
            // 无法用当前 key 解密的 secret。此时保留旧 sign_key 继续尝试。
            if let Ok(sign_key) = aes_decrypt(&secret, &self.aes_key, &self.iv) {
                self.sign_key = Some(sign_key);
            }
        }
        if let Some(back_id) = response.get("backId").and_then(Value::as_str) {
            self.back_id = back_id.to_string();
        }
        self.uid = response.get("uid").and_then(Value::as_i64);
        self.admin = response.get("admin").and_then(Value::as_bool);
        Ok(response)
    }
}

async fn dispatch_message(pending: &Mutex<HashMap<String, PendingSender>>, text: &str) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let Some(reqid) = value.get("reqid").and_then(Value::as_str) else {
        return;
    };
    let sender = pending.lock().await.remove(reqid);
    if let Some(sender) = sender {
        let _ = sender.send(Ok(value));
    }
}

async fn fail_all_pending(pending: &Mutex<HashMap<String, PendingSender>>, message: String) {
    let mut map = pending.lock().await;
    for (_, sender) in map.drain() {
        let _ = sender.send(Err(message.clone()));
    }
}

fn string_field(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn bool_field(value: &Value, key: &str) -> Option<bool> {
    value.get(key).and_then(Value::as_bool)
}

/// 识别 `user.login` 返回的 2FA 挑战。
pub fn classify_two_factor(response: &Value) -> Option<TwoFactorChallenge> {
    if string_field(response, "token").is_some_and(|token| !token.is_empty()) {
        return None;
    }

    let access_token = string_field(response, "accessToken")?;
    if access_token.is_empty() {
        return None;
    }

    let is_bind_twofa = bool_field(response, "isBindTwofaSecret").unwrap_or(false);
    let is_enforced = bool_field(response, "isTwofaEnforced").unwrap_or(false);
    let is_trusted = bool_field(response, "isTrustedDevice").unwrap_or(false);

    let kind = if is_bind_twofa && !is_trusted {
        TwoFactorKind::Verify
    } else if is_enforced && !is_bind_twofa {
        TwoFactorKind::SetupRequired
    } else {
        return None;
    };

    Some(TwoFactorChallenge {
        kind,
        access_token,
        secure_email: string_field(response, "secureEmail"),
        is_secure_email_bound: bool_field(response, "isBindSecureEmail").unwrap_or(false),
        is_trusted_device: is_trusted,
        twofa_secret: string_field(response, "twofaSecret"),
        otpauth: string_field(response, "otpauth"),
    })
}

pub fn is_six_digit_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// 检查 fnOS 响应。`errno` 为 null/0 时视为成功，非零则为错误。
pub fn ensure_success(value: &Value, context: &str) -> Result<()> {
    let Some(object) = value.as_object() else {
        return Ok(());
    };
    let Some(errno) = object.get("errno") else {
        return Ok(());
    };
    if errno.is_null() || errno.as_i64() == Some(0) || errno.as_str() == Some("0") {
        if object.get("result").and_then(Value::as_str) == Some("fail") {
            let message = object
                .get("msg")
                .or_else(|| object.get("errmsg"))
                .or_else(|| object.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("服务器返回失败");
            bail!("{context}: {message}");
        }
        return Ok(());
    }

    let code = errno.to_string();
    let message = object
        .get("msg")
        .or_else(|| object.get("errmsg"))
        .or_else(|| object.get("error"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("错误码: {code}"));
    bail!("{context}: {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reqid_has_expected_layout() {
        let reqid = next_request_id("0000000000000000");
        assert_eq!(reqid.len(), 28);
        assert!(reqid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn detects_errno_responses() {
        assert!(ensure_success(&json!({"token": "abc"}), "登录失败").is_ok());
        assert!(ensure_success(&json!({"errno": null}), "登录失败").is_ok());
        assert!(ensure_success(&json!({"errno": 0}), "登录失败").is_ok());
        let error =
            ensure_success(&json!({"errno": 1, "msg": "密码错误"}), "登录失败").unwrap_err();
        assert!(error.to_string().contains("密码错误"));

        let error = ensure_success(
            &json!({"errno": null, "result": "fail", "errmsg": "验证码错误"}),
            "两步验证失败",
        )
        .unwrap_err();
        assert!(error.to_string().contains("验证码错误"));
    }

    #[test]
    fn classifies_bound_two_factor_challenge() {
        let challenge = classify_two_factor(&json!({
            "isTwofaEnforced": true,
            "isBindTwofaSecret": true,
            "isBindSecureEmail": true,
            "secureEmail": "al***@example.com",
            "isTrustedDevice": false,
            "accessToken": "access-token",
            "result": "succ",
        }))
        .expect("challenge");
        assert_eq!(challenge.kind, TwoFactorKind::Verify);
        assert_eq!(challenge.access_token, "access-token");
        assert_eq!(challenge.secure_email.as_deref(), Some("al***@example.com"));
    }

    #[test]
    fn classifies_enforced_unbound_two_factor_as_setup() {
        let challenge = classify_two_factor(&json!({
            "isTwofaEnforced": true,
            "isBindTwofaSecret": false,
            "isTrustedDevice": false,
            "accessToken": "access-token",
            "twofaSecret": "SECRET",
            "otpauth": "otpauth://totp/fnOS",
            "result": "succ",
        }))
        .expect("challenge");
        assert_eq!(challenge.kind, TwoFactorKind::SetupRequired);
        assert_eq!(challenge.twofa_secret.as_deref(), Some("SECRET"));
        assert_eq!(challenge.otpauth.as_deref(), Some("otpauth://totp/fnOS"));
    }

    #[test]
    fn normal_login_is_not_a_two_factor_challenge() {
        assert!(classify_two_factor(&json!({
            "token": "token",
            "secret": "secret",
            "result": "succ",
        }))
        .is_none());
        assert!(classify_two_factor(&json!({
            "isBindTwofaSecret": true,
            "isTrustedDevice": true,
            "accessToken": "ignored",
        }))
        .is_none());
    }

    #[test]
    fn validates_six_digit_codes() {
        assert!(is_six_digit_code("583213"));
        assert!(!is_six_digit_code("58321"));
        assert!(!is_six_digit_code("5832134"));
        assert!(!is_six_digit_code("58321a"));
        assert!(!is_six_digit_code(""));
    }
}
