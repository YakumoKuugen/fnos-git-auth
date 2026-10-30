//! 跨平台文件权限、原子写入和 Git 环境检查等通用工具。

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use data_encoding::BASE32_NOPAD;
use rand::RngCore;

/// 创建目录并把权限收紧到仅当前用户可访问。
pub fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("创建配置目录失败: {}", path.display()))?;
    set_private_dir_permissions(path);
    Ok(())
}

/// 原子写入文件，Unix 下使用 0600 权限。
pub fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_private_dir(parent)?;
    }

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fnos-git-auth.tmp".to_string());
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let temp_path =
        path.with_file_name(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));

    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .with_context(|| format!("创建临时文件失败: {}", temp_path.display()))?;
        file.write_all(data)
            .with_context(|| format!("写入临时文件失败: {}", temp_path.display()))?;
        file.sync_all().ok();
        set_private_file_permissions(&temp_path);

        match fs::rename(&temp_path, path) {
            Ok(()) => Ok(()),
            Err(first_error) => {
                // Windows 上目标文件存在时，某些文件系统会拒绝 rename。
                #[cfg(windows)]
                {
                    if path.exists() {
                        fs::remove_file(path)
                            .with_context(|| format!("替换旧文件失败: {}", path.display()))?;
                        fs::rename(&temp_path, path)
                            .with_context(|| format!("写入文件失败: {}", path.display()))?;
                        return Ok(());
                    }
                }
                Err(first_error).with_context(|| format!("写入文件失败: {}", path.display()))
            }
        }
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    } else {
        set_private_file_permissions(path);
    }
    result
}

#[cfg(unix)]
pub fn set_private_file_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
pub fn set_private_file_permissions(path: &Path) {
    set_windows_permissions(path, false);
}

#[cfg(unix)]
pub fn set_private_dir_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
pub fn set_private_dir_permissions(path: &Path) {
    set_windows_permissions(path, true);
}

#[cfg(windows)]
fn set_windows_permissions(path: &Path, _directory: bool) {
    use std::os::windows::process::CommandExt;

    let Some(username) = std::env::var_os("USERNAME").or_else(|| std::env::var_os("USER")) else {
        return;
    };
    let username = username.to_string_lossy();
    let mut command = Command::new("icacls");
    command
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{username}:F"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let _ = command.status();
}

#[cfg(not(windows))]
fn set_windows_permissions(_path: &Path, _directory: bool) {}

/// 检查 Git 是否可用，返回 `git version ...`。
pub fn check_git_installed(git: &Path) -> Result<String> {
    let output = Command::new(git)
        .arg("--version")
        .output()
        .with_context(|| format!("Git 未安装或不在 PATH 中: {}", git.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "Git 执行失败: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// 平台对应的预编译资产名（Rust 版本使用 `-rust-` 前缀，避免误装 Python 构建）。
pub fn release_asset_name() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "fnos-git-auth-rust-windows-x64.exe",
        ("windows", "aarch64") => "fnos-git-auth-rust-windows-arm64.exe",
        ("linux", "x86_64") => "fnos-git-auth-rust-linux-x86_64",
        ("linux", "aarch64") => "fnos-git-auth-rust-linux-arm64",
        ("macos", "x86_64") => "fnos-git-auth-rust-macos-x64",
        ("macos", "aarch64") => "fnos-git-auth-rust-macos-arm64",
        _ => "",
    }
}

/// 生成与 fnOS Web 前端格式一致的设备 ID。
///
/// 形如 `mfrggzdfmztwq2lk-xxxxxxxxxxxxxxx-yyyyyyyyyyyyyyy`，用于登录请求中的
/// `did` 字段，以及“信任此设备”后的免 2FA 识别。调用方应持久化后复用。
pub fn generate_device_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let timestamp = BASE32_NOPAD
        .encode(timestamp.to_string().as_bytes())
        .to_ascii_lowercase();

    let mut rng = rand::rngs::OsRng;
    let mut random = [0u8; 10];
    rng.fill_bytes(&mut random);
    let encoded = BASE32_NOPAD.encode(&random).to_ascii_lowercase();
    let first = &encoded[..15];
    rng.fill_bytes(&mut random);
    let encoded = BASE32_NOPAD.encode(&random).to_ascii_lowercase();
    let second = &encoded[..15];

    format!("{timestamp}-{first}-{second}")
}

/// 去除协议、路径和空白，得到 WebSocket 使用的 `host[:port]`。
pub fn normalize_server(server: &str) -> Option<String> {
    let mut value = server.trim();
    if value.is_empty() {
        return None;
    }

    let lower = value.to_ascii_lowercase();
    for prefix in ["https://", "http://", "wss://", "ws://"] {
        if lower.starts_with(prefix) {
            value = &value[prefix.len()..];
            break;
        }
    }

    let host = value.split(['/', '\\']).next().unwrap_or("").trim();
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_server_addresses() {
        assert_eq!(
            normalize_server("https://demo.fnos.net/some/path"),
            Some("demo.fnos.net".to_string())
        );
        assert_eq!(
            normalize_server("  WSS://demo.fnos.net  "),
            Some("demo.fnos.net".to_string())
        );
        assert_eq!(
            normalize_server("192.168.1.4:5666/"),
            Some("192.168.1.4:5666".to_string())
        );
        assert_eq!(normalize_server("  "), None);
    }

    #[test]
    fn device_id_has_expected_shape() {
        let first = generate_device_id();
        let second = generate_device_id();
        assert_ne!(first, second);
        assert_eq!(first.split('-').count(), 3);
        assert!(first.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        assert_eq!(first.split('-').nth(1).unwrap().len(), 15);
        assert_eq!(first.split('-').nth(2).unwrap().len(), 15);
    }

    #[test]
    fn writes_private_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("config.json");
        write_private_file(&path, b"{\"ok\":true}").unwrap();
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{\"ok\":true}");
    }
}
