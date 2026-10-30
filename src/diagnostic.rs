//! 诊断信息收集与脱敏打包。

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use chrono::Local;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::{json, Map, Value};

use crate::config::{merged_preferences, ConfigStore};
use crate::git::GitRunner;
use crate::paths::AppPaths;

const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "token",
    "secret",
    "key",
    "credential",
    "fnos_token",
    "long_token",
    "entry_token",
    "sign_key",
];

const MIN_SENSITIVE_LENGTH: usize = 8;

pub fn mask_sensitive_value(value: &str) -> String {
    let length = value.chars().count();
    if length < MIN_SENSITIVE_LENGTH {
        return value.to_string();
    }
    if length <= 8 {
        return "*".repeat(length);
    }
    let prefix: String = value.chars().take(4).collect();
    let suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}{}{suffix}", "*".repeat(length - 8))
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "did"
        || SENSITIVE_KEYS
            .iter()
            .any(|sensitive| key.contains(sensitive))
}

fn sanitize_value(value: &Value, key: &str) -> Value {
    match value {
        Value::Object(object) => {
            let mut result = Map::new();
            for (child_key, child_value) in object {
                result.insert(child_key.clone(), sanitize_value(child_value, child_key));
            }
            Value::Object(result)
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|item| sanitize_value(item, key)).collect())
        }
        Value::String(text) if is_sensitive_key(key) => Value::String(mask_sensitive_value(text)),
        other => other.clone(),
    }
}

fn mask_entry_token(value: &str) -> String {
    let mut result = value.to_string();
    if let Some(position) = result.find("entry-token=") {
        let start = position + "entry-token=".len();
        let end = result[start..]
            .find(char::is_whitespace)
            .map(|offset| start + offset)
            .unwrap_or(result.len());
        if end > start {
            let masked = mask_sensitive_value(&result[start..end]);
            result.replace_range(start..end, &masked);
        }
    }
    result
}

fn system_info() -> Value {
    json!({
        "os": std::env::consts::OS,
        "family": std::env::consts::FAMILY,
        "arch": std::env::consts::ARCH,
        "description": os_description(),
    })
}

fn os_description() -> String {
    #[cfg(windows)]
    let command = Command::new("cmd").args(["/C", "ver"]).output();
    #[cfg(not(windows))]
    let command = Command::new("uname").arg("-srm").output();

    match command {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    }
}

fn git_info(git: &GitRunner) -> Value {
    let (installed, version, error) = match git.version() {
        Ok(version) => (true, Some(version), None),
        Err(error) => (false, None, Some(error.to_string())),
    };

    let mut config = Map::new();
    if installed {
        if let Ok(output) = git.run(["config", "--global", "--list"]) {
            for line in output.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = if key.to_ascii_lowercase().contains("extraheader") {
                        mask_entry_token(value)
                    } else if is_sensitive_key(key) {
                        mask_sensitive_value(value)
                    } else {
                        value.to_string()
                    };
                    config.insert(key.to_string(), Value::String(value));
                }
            }
        }
    }

    json!({
        "installed": installed,
        "version": version,
        "config": config,
        "error": error,
    })
}

fn config_info(paths: &AppPaths) -> Value {
    let store = ConfigStore::new(paths.clone());
    let config = store.read();
    let value = serde_json::to_value(&config).unwrap_or(Value::Object(Map::new()));
    let mut sanitized = sanitize_value(&value, "config");
    if let Value::Object(object) = &mut sanitized {
        let mut preferences = Map::new();
        for (key, value) in merged_preferences(&config) {
            preferences.insert(key, sanitize_value(&value, "preference"));
        }
        object.insert("preferences_merged".to_string(), Value::Object(preferences));
    }
    sanitized
}

fn environment_info() -> Value {
    let relevant = [
        "PATH",
        "HOME",
        "USER",
        "SHELL",
        "LANG",
        "LC_ALL",
        "TERM",
        "FNOS_GIT_AUTH_CONFIG_DIR",
        "FNOS_GIT_AUTH_DIR",
        "FNOS_GIT_AUTH_BIN",
    ];
    let mut environment = BTreeMap::new();
    for key in relevant {
        if let Ok(value) = std::env::var(key) {
            environment.insert(key.to_string(), mask_environment(key, value));
        }
    }
    serde_json::to_value(environment).unwrap_or(Value::Object(Map::new()))
}

fn mask_environment(key: &str, value: String) -> String {
    if key != "PATH" && key != "HOME" && key != "FNOS_GIT_AUTH_CONFIG_DIR" {
        return value;
    }

    let mut result = value;
    if let Some(home) = dirs::home_dir() {
        let home = home.to_string_lossy();
        if !home.is_empty() {
            result = result.replace(home.as_ref(), "~");
        }
    }
    if let Ok(username) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
        if username.len() >= 3 {
            result = result.replace(&username, "****");
        }
    }
    result
}

pub fn collect(paths: &AppPaths, git: &GitRunner) -> Value {
    let config_dir = mask_environment("HOME", paths.dir().to_string_lossy().into_owned());
    let tool = json!({
        "name": "fnos-git-auth",
        "version": env!("CARGO_PKG_VERSION"),
        "implementation": "rust",
        "config_dir": config_dir,
        "config_file_exists": paths.config_file().is_file(),
    });

    json!({
        "generated_at": Local::now().to_rfc3339(),
        "system": system_info(),
        "git": git_info(git),
        "tool": tool,
        "config": config_info(paths),
        "environment": environment_info(),
    })
}

pub fn print_info(paths: &AppPaths, git: &GitRunner) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&collect(paths, git)).context("序列化诊断信息失败")?
    );
    Ok(())
}

pub fn create_package(paths: &AppPaths, git: &GitRunner, output: Option<&Path>) -> Result<PathBuf> {
    let info = collect(paths, git);
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let file_name = format!("fnos-git-auth-diagnostic-{timestamp}.tar.gz");

    let output_dir = match output {
        Some(directory) => {
            std::fs::create_dir_all(directory)
                .with_context(|| format!("创建诊断输出目录失败: {}", directory.display()))?;
            directory.to_path_buf()
        }
        None => std::env::current_dir().context("无法获取当前目录")?,
    };
    let tar_path = output_dir.join(file_name);

    let info_bytes = serde_json::to_vec_pretty(&info).context("序列化诊断信息失败")?;
    let readme = format!(
        "fnos-git-auth 诊断信息包\n\
         ========================\n\n\
         此文件包含系统环境、Git 配置和工具配置信息，用于帮助排查问题。\n\n\
         注意：所有敏感信息（token、密码、密钥等）已自动脱敏。\n\n\
         请将此文件上传到 GitHub Issue 或发送给开发者。\n\n\
         生成时间: {}\n",
        info.get("generated_at")
            .and_then(Value::as_str)
            .unwrap_or_default()
    );

    let file = File::create(&tar_path)
        .with_context(|| format!("创建诊断包失败: {}", tar_path.display()))?;
    let encoder = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(encoder);
    append_bytes(&mut tar, "diagnostic_info.json", info_bytes.as_slice())?;
    append_bytes(&mut tar, "README.txt", readme.as_bytes())?;
    let encoder = tar.into_inner().context("生成 tar 失败")?;
    let mut file = encoder.finish().context("压缩诊断包失败")?;
    file.flush().ok();

    Ok(tar_path)
}

fn append_bytes<W: Write>(tar: &mut tar::Builder<W>, name: &str, data: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(Local::now().timestamp().max(0) as u64);
    header.set_cksum();
    tar.append_data(&mut header, name, data)
        .with_context(|| format!("写入诊断包条目失败: {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigStore, ServerConfig};

    #[test]
    fn masks_sensitive_values() {
        assert_eq!(mask_sensitive_value("12345678"), "********");
        assert_eq!(mask_sensitive_value("abcdefghij"), "abcd**ghij");
        assert_eq!(mask_sensitive_value("short"), "short");
    }

    #[test]
    fn masks_entry_token_in_headers() {
        let value = mask_entry_token("Cookie: entry-token=0123456789abcdef");
        assert!(!value.contains("0123456789abcdef"));
        assert!(value.starts_with("Cookie: entry-token="));
    }

    #[test]
    fn diagnostic_does_not_leak_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path().join("app"));
        let store = ConfigStore::new(paths.clone());
        let mut server = ServerConfig::new("demo.fnos.net");
        server.username = Some("alice".into());
        server.did = Some("device-id-secret-value".into());
        server.fnos_token = Some("super-secret-token-value".into());
        server.entry_token = Some("another-secret-token".into());
        server.sign_key = Some("c2lnbi1rZXktc2VjcmV0".into());
        store.save_server_config(server, true).unwrap();

        let git = GitRunner::with_global_config(dir.path().join("gitconfig"));
        if Command::new("git").arg("--version").output().is_ok() {
            git.set_extra_header("demo.fnos.net", "extra-secret-token-value")
                .unwrap();
        }

        let text = serde_json::to_string(&collect(&paths, &git)).unwrap();
        assert!(!text.contains("super-secret-token-value"));
        assert!(!text.contains("another-secret-token"));
        assert!(!text.contains("extra-secret-token-value"));
        assert!(!text.contains("device-id-secret-value"));
        assert!(!text.contains("c2lnbi1rZXktc2VjcmV0"));
    }

    #[test]
    fn creates_readable_tarball() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path().join("app"));
        let git = GitRunner::with_global_config(dir.path().join("gitconfig"));
        let path = create_package(&paths, &git, Some(dir.path())).unwrap();
        assert!(path.is_file());

        let file = File::open(&path).unwrap();
        let decoder = flate2::read::GzDecoder::new(file);
        let mut archive = tar::Archive::new(decoder);
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec!["diagnostic_info.json", "README.txt"]);
    }
}
