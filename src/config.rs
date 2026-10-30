//! 配置与偏好管理。
//!
//! 配置格式与 Python 版本兼容，默认位置为 `~/.fnos-git-auth/config.json`。
//! 所有 token 只保存在本地配置文件中，文件权限为当前用户可读写。

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Local, NaiveDateTime, TimeZone};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::paths::AppPaths;
use crate::util::{create_private_dir, write_private_file};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerConfig>,
    #[serde(default)]
    pub preferences: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 设备 ID，用于 2FA“信任此设备”和登录设备列表。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fnos_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fnos_token_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub long_token_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_token_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login: Option<String>,
    /// 兼容 Python 版本的旧字段。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// 保留未来版本或 Python 版本写入的未知字段，避免保存时丢数据。
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ServerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: Some(url.into()),
            ..Self::default()
        }
    }

    pub fn has_session(&self) -> bool {
        self.fnos_token.is_some()
    }

    pub fn entry_expiry(&self) -> Option<&str> {
        self.entry_token_expires_at
            .as_deref()
            .or(self.expires_at.as_deref())
    }
}

/// 默认偏好。`entry_token_expire_hours` 等也显式列出，方便 `config` 命令查看。
pub fn default_preferences() -> BTreeMap<String, Value> {
    let mut prefs = BTreeMap::new();
    prefs.insert("timeout".into(), json!(30.0));
    prefs.insert("device_type".into(), json!("Browser"));
    prefs.insert("device_name".into(), json!("fnos-git-auth"));
    prefs.insert("language".into(), json!("zh"));
    prefs.insert("token_expire_hours".into(), json!(24));
    prefs.insert("token_refresh_threshold_hours".into(), json!(1.0));
    prefs.insert("entry_token_expire_hours".into(), json!(8));
    prefs.insert("fnos_token_expire_hours".into(), json!(8));
    prefs.insert("long_token_expire_days".into(), json!(25));
    prefs.insert("fn_connect_cookie".into(), json!("mode=relay; language=zh"));
    prefs.insert("use_ssl".into(), json!(true));
    prefs.insert("auto_save_credentials".into(), json!(true));
    prefs.insert("auto_refresh_token".into(), json!(true));
    prefs
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    paths: AppPaths,
}

impl ConfigStore {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// 读取配置。不存在时返回空配置；损坏时给出警告并返回空配置。
    pub fn read(&self) -> Config {
        let path = self.paths.config_file();
        let content = match fs::read_to_string(&path) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Config::default(),
            Err(error) => {
                eprintln!("读取配置文件失败: {error}");
                return Config::default();
            }
        };
        match serde_json::from_str(&content) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("解析配置文件失败: {error}");
                Config::default()
            }
        }
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        create_private_dir(self.paths.dir())?;
        let mut data = serde_json::to_vec_pretty(config).context("序列化配置失败")?;
        data.push(b'\n');
        write_private_file(&self.paths.config_file(), &data)
    }

    pub fn server(&self) -> Option<ServerConfig> {
        self.read().server
    }

    pub fn server_url(&self) -> Option<String> {
        self.server().and_then(|server| server.url)
    }

    pub fn save_server_config(&self, server: ServerConfig, update_last_login: bool) -> Result<()> {
        let mut config = self.read();
        let mut server = server;
        if update_last_login {
            server.last_login = Some(now_iso());
        }
        config.server = Some(server);
        self.save(&config)
    }

    /// 登出时保留服务器地址和设备 ID，删除所有 token 和用户信息。
    pub fn delete_server_tokens(&self) -> Result<()> {
        let mut config = self.read();
        match config.server.as_ref().and_then(|server| server.url.clone()) {
            Some(url) => {
                let did = config.server.as_ref().and_then(|server| server.did.clone());
                let mut server = ServerConfig::new(url);
                server.did = did;
                config.server = Some(server);
            }
            None => config.server = None,
        }
        self.save(&config)
    }

    pub fn preferences(&self) -> BTreeMap<String, Value> {
        let mut merged = default_preferences();
        for (key, value) in self.read().preferences {
            merged.insert(key, value);
        }
        merged
    }

    pub fn preference(&self, key: &str) -> Option<Value> {
        self.preferences().get(key).cloned()
    }

    pub fn set_preference(&self, key: &str, value: Value) -> Result<()> {
        let mut config = self.read();
        config.preferences.insert(key.to_string(), value);
        self.save(&config)
    }

    pub fn reset_preferences(&self) -> Result<()> {
        let mut config = self.read();
        config.preferences.clear();
        self.save(&config)
    }

    pub fn pref_string(&self, key: &str, default: &str) -> String {
        self.preference(key)
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| default.to_string())
    }

    pub fn pref_bool(&self, key: &str, default: bool) -> bool {
        self.preference(key)
            .and_then(|value| value.as_bool())
            .unwrap_or(default)
    }

    pub fn pref_f64(&self, key: &str, default: f64) -> f64 {
        self.preference(key)
            .and_then(|value| value.as_f64())
            .unwrap_or(default)
    }

    pub fn pref_i64(&self, key: &str, default: i64) -> i64 {
        self.preference(key)
            .and_then(|value| value.as_i64())
            .unwrap_or(default)
    }

    pub fn is_entry_token_expired(&self) -> bool {
        match self.server() {
            Some(server) => is_expired(server.entry_expiry()),
            None => true,
        }
    }

    pub fn is_fnos_token_expired(&self) -> bool {
        match self.server() {
            Some(server) => is_expired(
                server
                    .fnos_token_expires_at
                    .as_deref()
                    .or(server.expires_at.as_deref()),
            ),
            None => true,
        }
    }

    pub fn is_long_token_expired(&self) -> bool {
        match self.server() {
            Some(server) => is_expired(server.long_token_expires_at.as_deref()),
            None => true,
        }
    }

    pub fn token_needs_refresh(&self) -> bool {
        let Some(server) = self.server() else {
            return false;
        };
        let Some(expires_at) = server.entry_expiry() else {
            return false;
        };
        let Some(expires_at) = parse_datetime(expires_at) else {
            return false;
        };
        let threshold = self.pref_f64("token_refresh_threshold_hours", 1.0);
        Local::now() > expires_at - Duration::minutes((threshold * 60.0) as i64)
    }
}

/// 与 Python `datetime.isoformat()` 一致：本地时间，不带时区偏移。
fn format_local(datetime: DateTime<Local>) -> String {
    datetime
        .naive_local()
        .format("%Y-%m-%dT%H:%M:%S%.6f")
        .to_string()
}

pub fn now_iso() -> String {
    format_local(Local::now())
}

pub fn expiry_after_hours(hours: i64) -> String {
    format_local(Local::now() + Duration::hours(hours))
}

pub fn expiry_after_days(days: i64) -> String {
    format_local(Local::now() + Duration::days(days))
}

/// 判断 ISO 时间是否已过期。缺失或无法解析都视为过期。
pub fn is_expired(value: Option<&str>) -> bool {
    match value.and_then(parse_datetime) {
        Some(expires_at) => Local::now() > expires_at,
        None => true,
    }
}

pub fn parse_datetime(value: &str) -> Option<DateTime<Local>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Local));
    }

    // Python 的 datetime.isoformat() 默认是不带时区的本地时间。
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            if let Some(parsed) = Local.from_local_datetime(&naive).single() {
                return Some(parsed);
            }
        }
    }
    None
}

/// 将偏好值从 JSON 转成适合展示的字符串。
pub fn display_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// 深度合并偏好，供诊断等功能使用。
pub fn merged_preferences(config: &Config) -> Map<String, Value> {
    let mut merged = Map::new();
    for (key, value) in default_preferences() {
        merged.insert(key, value);
    }
    for (key, value) in &config.preferences {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

/// 确保配置目录可创建（测试和外部工具使用）。
pub fn ensure_config_dir(paths: &AppPaths) -> Result<()> {
    create_private_dir(paths.dir())
}

pub fn config_exists(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> (tempfile::TempDir, ConfigStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(AppPaths::new(dir.path()));
        (dir, store)
    }

    #[test]
    fn saves_and_reads_config() {
        let (_dir, store) = test_store();
        let mut config = Config::default();
        config.preferences.insert("timeout".into(), json!(45.0));
        store.save(&config).unwrap();

        let loaded = store.read();
        assert_eq!(loaded.preferences.get("timeout"), Some(&json!(45.0)));
    }

    #[test]
    fn saves_server_and_preserves_url_when_deleting() {
        let (_dir, store) = test_store();
        let mut server = ServerConfig::new("demo.fnos.net");
        server.username = Some("alice".into());
        server.did = Some("device-id".into());
        server.fnos_token = Some("token".into());
        store.save_server_config(server, true).unwrap();

        let loaded = store.server().unwrap();
        assert_eq!(loaded.url.as_deref(), Some("demo.fnos.net"));
        assert!(loaded.last_login.is_some());

        store.delete_server_tokens().unwrap();
        let loaded = store.server().unwrap();
        assert_eq!(loaded.url.as_deref(), Some("demo.fnos.net"));
        assert_eq!(loaded.did.as_deref(), Some("device-id"));
        assert!(loaded.username.is_none());
        assert!(loaded.fnos_token.is_none());
    }

    #[test]
    fn token_expiry_detection() {
        let (_dir, store) = test_store();
        let mut server = ServerConfig::new("demo.fnos.net");
        server.fnos_token = Some("token".into());
        server.entry_token_expires_at = Some(expiry_after_hours(2));
        store.save_server_config(server, false).unwrap();

        assert!(!store.is_entry_token_expired());
        assert!(!store.token_needs_refresh());

        let mut server = store.server().unwrap();
        server.entry_token_expires_at = Some(expiry_after_hours(-1));
        store.save_server_config(server, false).unwrap();
        assert!(store.is_entry_token_expired());
    }

    #[test]
    fn parses_python_naive_timestamps() {
        let parsed = parse_datetime("2030-01-02T03:04:05.123456").unwrap();
        assert_eq!(parsed.format("%Y-%m-%d").to_string(), "2030-01-02");
    }

    #[test]
    fn writes_python_compatible_naive_timestamps() {
        let value = expiry_after_hours(1);
        assert!(!value.contains('+'));
        assert!(!value.ends_with('Z'));
        assert!(parse_datetime(&value).is_some());
    }

    #[test]
    fn preferences_are_typed() {
        let (_dir, store) = test_store();
        assert_eq!(store.pref_i64("entry_token_expire_hours", 8), 8);
        assert!(store.pref_bool("use_ssl", false));
        assert_eq!(store.pref_f64("timeout", 0.0), 30.0);
    }
}
