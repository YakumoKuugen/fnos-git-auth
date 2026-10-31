//! 登录、登出、状态与 token 刷新。

use std::io::{self, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::client::{is_six_digit_code, FnOsClient, TwoFactorChallenge};
use crate::config::{expiry_after_days, expiry_after_hours, ConfigStore, ServerConfig};
use crate::credentials::CredentialsStore;
use crate::git::GitRunner;
use crate::hooks;
use crate::paths::AppPaths;
use crate::util::generate_device_id;

#[derive(Debug, Clone, Default)]
pub struct LoginOptions {
    /// 非交互传入的 6 位 2FA 验证码。
    pub two_factor_code: Option<String>,
    /// 本次登录是否信任当前设备，减少后续 2FA。
    pub trust_device: bool,
    /// 遇到 2FA 挑战时是否允许从终端读取验证码。
    pub interactive_two_factor: bool,
}

#[derive(Debug, Clone)]
pub struct AuthService {
    paths: AppPaths,
    git: GitRunner,
}

impl AuthService {
    pub fn new(paths: AppPaths) -> Self {
        Self {
            paths,
            git: GitRunner::new(),
        }
    }

    pub fn with_git(paths: AppPaths, git: GitRunner) -> Self {
        Self { paths, git }
    }

    fn store(&self) -> ConfigStore {
        ConfigStore::new(self.paths.clone())
    }

    fn credentials(&self) -> CredentialsStore {
        CredentialsStore::new(self.paths.clone())
    }

    async fn connect_client(&self, client: &mut FnOsClient, server: &str) -> Result<()> {
        let store = self.store();
        let use_ssl = store.pref_bool("use_ssl", true);
        let cookie = store.pref_string("fn_connect_cookie", "mode=relay; language=zh");
        client.connect(server, use_ssl, &cookie).await
    }

    fn new_client(&self) -> FnOsClient {
        let timeout = self.store().pref_f64("timeout", 30.0);
        let timeout = if timeout.is_finite() && timeout > 0.0 {
            timeout.min(3600.0)
        } else {
            30.0
        };
        FnOsClient::new(Duration::from_secs_f64(timeout))
    }

    /// 执行完整登录（不支持交互式 2FA，供刷新流程使用）。
    pub async fn login(&self, server: &str, username: &str, password: &str) -> Result<()> {
        self.login_with_options(server, username, password, LoginOptions::default())
            .await
    }

    /// 执行完整登录，成功后保存 token、配置 Git extraHeader 并安装刷新 hooks。
    pub async fn login_with_options(
        &self,
        server: &str,
        username: &str,
        password: &str,
        options: LoginOptions,
    ) -> Result<()> {
        let store = self.store();
        let device_type = store.pref_string("device_type", "Browser");
        let device_name = store.pref_string("device_name", "fnos-git-auth");
        let auto_refresh = store.pref_bool("auto_refresh_token", true);
        let device_id = store
            .server()
            .filter(|config| {
                config
                    .url
                    .as_deref()
                    .is_some_and(|url| url.eq_ignore_ascii_case(server))
            })
            .and_then(|config| config.did)
            .filter(|did| !did.trim().is_empty())
            .unwrap_or_else(generate_device_id);

        let mut client = self.new_client();
        println!("正在连接到 {server}...");

        let outcome = async {
            self.connect_client(&mut client, server).await?;

            client.set_device_id(device_id.clone());

            println!("正在获取公钥...");
            client.get_rsa_pub().await?;

            println!("正在验证凭据...");
            let mut response = client
                .login(username, password, true, &device_type, &device_name)
                .await
                .context("登录失败")?;

            if let Some(challenge) = client.two_factor_setup_challenge().cloned() {
                if options.interactive_two_factor || options.two_factor_code.is_some() {
                    print_two_factor_setup(&challenge)?;
                }
                bail!("该账号需要先绑定两步验证（TOTP）后才能登录");
            }

            if let Some(challenge) = client.two_factor_challenge().cloned() {
                if options.interactive_two_factor || options.two_factor_code.is_some() {
                    print_two_factor_challenge(&challenge);
                }
                let mut retries = 0;
                loop {
                    let code = match options.two_factor_code.clone() {
                        Some(code) => code,
                        None if options.interactive_two_factor => prompt_two_factor_code()?,
                        None => bail!("该账号已启用两步验证，请使用 --code 传入 6 位验证码"),
                    };
                    if !is_six_digit_code(&code) {
                        bail!("两步验证码必须是 6 位数字");
                    }
                    println!("正在验证两步验证码...");
                    match client
                        .submit_two_factor_code(&code, options.trust_device)
                        .await
                    {
                        Ok(final_response) => {
                            response = final_response;
                            break;
                        }
                        Err(error)
                            if options.interactive_two_factor
                                && options.two_factor_code.is_none()
                                && retries < 2
                                && error.to_string().contains("验证码错误") =>
                        {
                            retries += 1;
                            eprintln!("{error}");
                            println!("请重新输入验证码。");
                        }
                        Err(error) => return Err(error),
                    }
                }
                if options.trust_device {
                    println!("已将该设备标记为可信设备");
                }
            }

            let fnos_token = client
                .token
                .clone()
                .context("登录失败: 服务器未返回 token")?;
            let long_token = response
                .get("longToken")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);

            println!("正在获取 entry-token...");
            let entry_token = match client.exchange_entry_token().await {
                Ok(token) => {
                    println!("成功获取 entry-token");
                    token
                }
                Err(error) => {
                    println!("获取 entry-token 失败: {error}");
                    String::new()
                }
            };
            let entry_warning = entry_token.is_empty();
            let entry_token = if entry_warning {
                println!("警告: 使用 fnos-token 作为备选，git push 可能会遇到 403 错误");
                fnos_token.clone()
            } else {
                entry_token
            };

            let entry_expires_at =
                expiry_after_hours(store.pref_i64("entry_token_expire_hours", 8));
            let fnos_expires_at = expiry_after_hours(store.pref_i64("fnos_token_expire_hours", 8));
            let long_expires_at = long_token
                .as_ref()
                .map(|_| expiry_after_days(store.pref_i64("long_token_expire_days", 25)));

            let mut server_config = ServerConfig::new(server);
            server_config.username = Some(username.to_string());
            server_config.did = Some(device_id.clone());
            server_config.fnos_token = Some(fnos_token);
            server_config.fnos_token_expires_at = Some(fnos_expires_at);
            server_config.long_token = long_token;
            server_config.long_token_expires_at = long_expires_at;
            server_config.entry_token = Some(entry_token.clone());
            server_config.entry_token_expires_at = Some(entry_expires_at.clone());
            server_config.sign_key = client.sign_key.clone();
            server_config.uid = client.uid;
            server_config.admin = client.admin;
            server_config.back_id = Some(client.back_id.clone());
            server_config.expires_at = Some(entry_expires_at);
            store.save_server_config(server_config, true)?;

            println!("正在配置 git...");
            let use_ssl = store.pref_bool("use_ssl", true);
            if let Err(error) = self.git.set_extra_header_for(server, &entry_token, use_ssl) {
                println!("警告: git extraHeader 配置失败，可能需要手动配置: {error}");
            }

            if auto_refresh {
                if let Err(error) = hooks::setup(&self.paths, &self.git) {
                    println!(
                        "警告: 自动刷新 hooks 设置失败，token 过期后需手动执行 refresh: {error}"
                    );
                }
            } else {
                println!("提示: 自动刷新已禁用（config -k auto_refresh_token -v false）");
                let _ = hooks::remove(&self.paths, &self.git);
            }

            println!(
                "登录成功! 用户: {username}, UID: {}",
                client
                    .uid
                    .map(|uid| uid.to_string())
                    .unwrap_or_else(|| "未知".to_string())
            );
            if entry_warning {
                println!("提示: entry-token 获取失败，如遇 git 403 错误请重新登录");
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;

        client.close().await;
        outcome
    }

    /// 登出：清除 token、Git extraHeader 和 hooks，保留服务器地址与已保存凭据。
    pub fn logout(&self) -> Result<()> {
        let store = self.store();
        let Some(server) = store.server() else {
            bail!("当前未登录");
        };
        if !server.has_session() {
            bail!("当前未登录");
        }

        let url = server
            .url
            .clone()
            .unwrap_or_else(|| "未知服务器".to_string());
        if let Err(error) = self.git.remove_extra_header(&url) {
            println!("警告: 移除 git extraHeader 失败: {error}");
        }
        if let Err(error) = hooks::remove(&self.paths, &self.git) {
            println!("警告: 移除自动刷新 hooks 失败: {error}");
        }
        store.delete_server_tokens()?;
        println!("已登出 {url}");
        Ok(())
    }

    pub fn status(&self) {
        let store = self.store();
        let Some(server) = store.server() else {
            println!("当前未登录");
            return;
        };
        if !server.has_session() {
            println!("当前未登录");
            if let Some(url) = server.url.as_deref() {
                println!("上次服务器: {url}");
            }
            return;
        }

        let url = server.url.as_deref().unwrap_or("未知");
        let expired = store.is_entry_token_expired();
        let needs_refresh = store.token_needs_refresh();

        println!("服务器: {url}");
        println!("用户名: {}", server.username.as_deref().unwrap_or("未知"));
        println!("状态: {}", if expired { "已过期" } else { "已登录" });
        if needs_refresh && !expired {
            println!("提示: Token 即将过期，建议刷新");
        }
        if let Some(expires_at) = server.entry_expiry() {
            println!("过期时间: {expires_at}");
        }
        if let Some(last_login) = server.last_login.as_deref() {
            println!("最后登录: {last_login}");
        }
        println!(
            "Git 配置: {}",
            if self.git.has_extra_header(url) {
                "已配置"
            } else {
                "未配置"
            }
        );
        println!(
            "自动刷新: {}",
            if hooks::has(&self.paths, &self.git) {
                "已启用"
            } else {
                "未启用"
            }
        );
        println!(
            "定时刷新: {}",
            if crate::schedule::is_installed() {
                "已启用".to_string()
            } else {
                "未启用（fnos-git-auth schedule install）".to_string()
            }
        );
    }

    /// 刷新 token。`if_needed=true` 时，token 仍充足则直接返回（供 hook 使用）。
    pub async fn refresh(&self, if_needed: bool) -> Result<()> {
        let store = self.store();
        let Some(config) = store.server() else {
            bail!("当前未登录");
        };
        let Some(server) = config.url.clone() else {
            bail!("当前未登录");
        };
        if config.fnos_token.is_none() && config.long_token.is_none() {
            bail!("当前未登录");
        }

        if if_needed && !store.is_entry_token_expired() && !store.token_needs_refresh() {
            println!("Token 仍然有效，无需刷新");
            return Ok(());
        }

        // 策略 1：fnos-token 未过期，直接验证并换取 entry-token。
        if let (Some(fnos_token), Some(sign_key)) = (&config.fnos_token, &config.sign_key) {
            if !store.is_fnos_token_expired() {
                match self
                    .refresh_with_fnos_token(&server, fnos_token, sign_key)
                    .await
                {
                    Ok(()) => return Ok(()),
                    Err(error) => println!("fnos_token 验证失败: {error:#}"),
                }
            }
        }

        // 策略 2：long-token 未过期，先换新的 fnos-token。
        if let Some(long_token) = &config.long_token {
            if !store.is_long_token_expired() {
                match self.refresh_with_long_token(&server, long_token).await {
                    Ok(()) => return Ok(()),
                    Err(error) => println!("long_token 刷新失败: {error:#}"),
                }
            }
        }

        // 策略 3：使用保存的凭据重新登录。
        if let Some(credentials) = self.credentials().get() {
            if !credentials.username.is_empty() && !credentials.password.is_empty() {
                println!("Token 已失效，使用保存的凭据重新登录...");
                return self
                    .login(&server, &credentials.username, &credentials.password)
                    .await;
            }
        }

        bail!("Token 已失效且未保存凭据，请重新登录")
    }

    async fn refresh_with_fnos_token(
        &self,
        server: &str,
        fnos_token: &str,
        sign_key: &str,
    ) -> Result<()> {
        let mut client = self.new_client();
        println!("正在刷新 token...");
        self.connect_client(&mut client, server).await?;
        client.token = Some(fnos_token.to_string());
        client.sign_key = Some(sign_key.to_string());

        let outcome = async {
            client.auth_token(true).await?;
            self.entry_token_from(&mut client).await
        }
        .await;

        let entry_token = match outcome {
            Ok(token) => token,
            Err(error) => {
                client.close().await;
                return Err(error);
            }
        };

        let store = self.store();
        let mut config = store.server().context("读取服务器配置失败")?;
        if config.did.is_none() {
            config.did = Some(generate_device_id());
        }
        let entry_expires_at = expiry_after_hours(store.pref_i64("entry_token_expire_hours", 8));
        config.entry_token = Some(entry_token.clone());
        config.entry_token_expires_at = Some(entry_expires_at.clone());
        config.expires_at = Some(entry_expires_at);
        config.fnos_token = Some(fnos_token.to_string());
        config.sign_key = Some(sign_key.to_string());
        if client.uid.is_some() {
            config.uid = client.uid;
        }
        if client.admin.is_some() {
            config.admin = client.admin;
        }
        if !client.back_id.is_empty() {
            config.back_id = Some(client.back_id.clone());
        }
        store.save_server_config(config, false)?;

        client.close().await;
        self.finish_refresh(server, &entry_token)
    }

    async fn refresh_with_long_token(&self, server: &str, long_token: &str) -> Result<()> {
        let store = self.store();
        let device_type = store.pref_string("device_type", "Browser");
        let device_name = store.pref_string("device_name", "fnos-git-auth");
        let old_config = store.server().context("读取服务器配置失败")?;
        let device_id = old_config
            .did
            .clone()
            .filter(|did| !did.trim().is_empty())
            .unwrap_or_else(generate_device_id);

        let mut client = self.new_client();
        client.set_device_id(device_id.clone());
        println!("正在使用 long_token 刷新...");
        self.connect_client(&mut client, server).await?;

        // tokenLogin 是登录后的接口，必须用已有 secret 对请求签名；
        // 否则服务器返回 65534（验签失败），随后只能回退到密码 + 2FA。
        client.sign_key = old_config.sign_key.clone();

        let outcome = async {
            client.get_rsa_pub().await?;
            let response = client
                .token_login(long_token, &device_type, &device_name)
                .await?;
            let new_fnos_token = client
                .token
                .clone()
                .or_else(|| {
                    response
                        .get("token")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .context("刷新失败: 未获取到新的 fnos_token")?;
            if client.sign_key.is_none() {
                client.sign_key = old_config.sign_key.clone();
            }
            let entry_token = self.entry_token_from(&mut client).await?;
            Ok::<_, anyhow::Error>((new_fnos_token, entry_token))
        }
        .await;

        let (new_fnos_token, entry_token) = match outcome {
            Ok(result) => result,
            Err(error) => {
                client.close().await;
                return Err(error);
            }
        };

        let mut config = old_config;
        config.did = Some(device_id);
        let fnos_expires_at = expiry_after_hours(store.pref_i64("fnos_token_expire_hours", 8));
        let entry_expires_at = expiry_after_hours(store.pref_i64("entry_token_expire_hours", 8));
        config.fnos_token = Some(new_fnos_token);
        config.fnos_token_expires_at = Some(fnos_expires_at);
        config.entry_token = Some(entry_token.clone());
        config.entry_token_expires_at = Some(entry_expires_at.clone());
        config.expires_at = Some(entry_expires_at);
        config.long_token = Some(long_token.to_string());
        if client.sign_key.is_some() {
            config.sign_key = client.sign_key.clone();
        }
        if client.uid.is_some() {
            config.uid = client.uid;
        }
        if client.admin.is_some() {
            config.admin = client.admin;
        }
        if !client.back_id.is_empty() {
            config.back_id = Some(client.back_id.clone());
        }
        store.save_server_config(config, false)?;

        client.close().await;
        self.finish_refresh(server, &entry_token)
    }

    async fn entry_token_from(&self, client: &mut FnOsClient) -> Result<String> {
        println!("正在获取 entry-token...");
        let token = client.exchange_entry_token().await?;
        println!("成功获取 entry-token");
        Ok(token)
    }

    fn finish_refresh(&self, server: &str, entry_token: &str) -> Result<()> {
        let use_ssl = self.store().pref_bool("use_ssl", true);
        self.git
            .set_extra_header_for(server, entry_token, use_ssl)
            .with_context(|| "更新 git extraHeader 失败")?;
        println!("Token 已刷新");
        Ok(())
    }
}

fn print_two_factor_challenge(challenge: &TwoFactorChallenge) {
    println!("该账号已启用两步验证（2FA）。");
    if challenge.is_secure_email_bound {
        if let Some(email) = challenge.secure_email.as_deref() {
            println!("安全邮箱: {email}");
        }
    }
    println!("请使用认证器中的 6 位 TOTP 验证码完成验证。");
}

fn print_two_factor_setup(challenge: &TwoFactorChallenge) -> Result<()> {
    println!("检测到该账号被强制要求两步验证，但尚未绑定 TOTP 验证器。");
    if let Some(secret) = challenge.twofa_secret.as_deref() {
        println!("TOTP 密钥: {secret}");
    }
    if let Some(otpauth) = challenge.otpauth.as_deref() {
        println!("otpauth: {otpauth}");
    }
    println!("请先在 fnOS Web 界面完成 TOTP 绑定，然后重新执行 login。");
    Ok(())
}

fn prompt_two_factor_code() -> Result<String> {
    print!("两步验证码: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    if io::stdin()
        .read_line(&mut input)
        .context("读取两步验证码失败")?
        == 0
    {
        bail!("无法读取两步验证码，请使用 --code 传入");
    }
    let code = input.trim().to_string();
    if !is_six_digit_code(&code) {
        bail!("两步验证码必须是 6 位数字");
    }
    Ok(code)
}

/// 供 CLI 测试和诊断使用：返回可读的登录状态摘要。
pub fn status_summary(paths: &AppPaths) -> Result<Value> {
    let store = ConfigStore::new(paths.clone());
    let Some(server) = store.server() else {
        return Ok(serde_json::json!({"logged_in": false}));
    };
    Ok(serde_json::json!({
        "logged_in": server.has_session(),
        "server": server.url,
        "username": server.username,
        "entry_token_expired": store.is_entry_token_expired(),
        "fnos_token_expired": store.is_fnos_token_expired(),
        "long_token_expired": store.is_long_token_expired(),
        "needs_refresh": store.token_needs_refresh(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refresh_without_login_fails() {
        let dir = tempfile::tempdir().unwrap();
        let service = AuthService::new(AppPaths::new(dir.path()));
        let error = service.refresh(false).await.unwrap_err();
        assert!(error.to_string().contains("未登录"));
    }

    #[test]
    fn logout_without_login_fails() {
        let dir = tempfile::tempdir().unwrap();
        let service = AuthService::new(AppPaths::new(dir.path()));
        assert!(service.logout().is_err());
    }

    #[test]
    fn status_summary_handles_missing_config() {
        let dir = tempfile::tempdir().unwrap();
        let value = status_summary(&AppPaths::new(dir.path())).unwrap();
        assert_eq!(value["logged_in"], serde_json::json!(false));
    }
}
