//! 从 GitHub Release 检查并更新 Rust 预编译二进制。
//!
//! 默认仓库沿用上游 `donnel666/fnos-git-auth`，可用环境变量
//! `FNOS_GIT_AUTH_UPDATE_REPO` 指向自己的发布仓库。
//! 只匹配带 `-rust-` 的资产名，避免把 Python 构建误装成 Rust 版本。

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::util::release_asset_name;

const DEFAULT_REPO: &str = "donnel666/fnos-git-auth";

#[derive(Debug, Clone, Default)]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub has_update: bool,
    pub download_url: Option<String>,
    pub release_notes: Option<String>,
    pub release_url: Option<String>,
}

#[derive(Debug, Clone)]
struct Release {
    version: String,
    download_url: Option<String>,
    release_notes: Option<String>,
    release_url: Option<String>,
}

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn repository() -> String {
    std::env::var("FNOS_GIT_AUTH_UPDATE_REPO")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REPO.to_string())
}

fn latest_release() -> Result<Release> {
    let url = format!(
        "https://api.github.com/repos/{}/releases/latest",
        repository()
    );
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .build();
    let response = agent
        .get(&url)
        .set("Accept", "application/vnd.github.v3+json")
        .set(
            "User-Agent",
            &format!("fnos-git-auth/{}", current_version()),
        )
        .call()
        .with_context(|| format!("获取版本信息失败: {url}"))?;
    let data: Value = response.into_json().context("解析 GitHub 响应失败")?;

    let version = data
        .get("tag_name")
        .and_then(Value::as_str)
        .context("GitHub Release 缺少 tag_name")?
        .to_string();

    let asset_name = release_asset_name();
    let download_url = if asset_name.is_empty() {
        None
    } else {
        data.get("assets")
            .and_then(Value::as_array)
            .and_then(|assets| {
                assets.iter().find_map(|asset| {
                    if asset.get("name").and_then(Value::as_str) == Some(asset_name) {
                        asset
                            .get("browser_download_url")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                    } else {
                        None
                    }
                })
            })
    };

    Ok(Release {
        version,
        download_url,
        release_notes: data
            .get("body")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        release_url: data
            .get("html_url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    })
}

/// 解析版本号中的数字段；忽略 `v` 前缀和预发布后缀。
pub fn parse_version(version: &str) -> Vec<u64> {
    let version = version.trim();
    let version = version
        .strip_prefix('v')
        .or_else(|| version.strip_prefix('V'))
        .unwrap_or(version);
    version
        .split('.')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

pub fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;

    let mut left = parse_version(left);
    let mut right = parse_version(right);
    while left.last() == Some(&0) {
        left.pop();
    }
    while right.last() == Some(&0) {
        right.pop();
    }
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        match a.cmp(&b) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    Ordering::Equal
}

pub fn check_for_updates() -> Result<UpdateInfo> {
    let release = latest_release()?;
    let current = current_version().to_string();
    let has_update = compare_versions(&current, &release.version).is_lt();
    Ok(UpdateInfo {
        current_version: current,
        latest_version: Some(release.version),
        has_update,
        download_url: release.download_url,
        release_notes: release.release_notes,
        release_url: release.release_url,
    })
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    let mut result: String = value.chars().take(max_chars).collect();
    if value.chars().count() > max_chars {
        result.push_str("...");
    }
    result
}

pub fn print_update_info(info: &UpdateInfo) -> Result<()> {
    println!("当前版本: {}", info.current_version);
    if let Some(latest) = info.latest_version.as_deref() {
        println!("最新版本: {latest}");
    } else {
        println!("无法获取最新版本信息");
        return Ok(());
    }

    if !info.has_update {
        println!("✓ 当前已是最新版本");
        return Ok(());
    }

    println!("✓ 发现新版本!");
    if let Some(notes) = info.release_notes.as_deref() {
        println!("\n更新说明:\n{}\n", truncate_chars(notes, 300));
    }
    if info.download_url.is_none() {
        println!("当前平台没有可用的 Rust 预编译版本。");
        if let Some(url) = info.release_url.as_deref() {
            println!("请访问: {url}");
        }
        println!("也可以使用 `cargo install --path .` 从源码构建。");
    }
    Ok(())
}

pub fn perform_update(force: bool) -> Result<()> {
    let info = check_for_updates()?;
    print_update_info(&info)?;
    if !info.has_update && !force {
        return Ok(());
    }

    install_from_info(&info)
}

/// 使用已获取的更新信息下载并安装。
pub fn install_from_info(info: &UpdateInfo) -> Result<()> {
    let Some(download_url) = info.download_url.as_deref() else {
        println!("没有匹配当前平台的 Rust 预编译资产，未执行自动更新。");
        return Ok(());
    };
    download_and_install(download_url)
}

fn download_and_install(url: &str) -> Result<()> {
    let executable = std::env::current_exe().context("无法获取当前可执行文件路径")?;
    let parent = executable.parent().context("当前可执行文件没有父目录")?;

    println!("正在下载: {url}");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(120))
        .build();
    let response = agent
        .get(url)
        .set(
            "User-Agent",
            &format!("fnos-git-auth/{}", current_version()),
        )
        .call()
        .with_context(|| format!("下载更新失败: {url}"))?;
    let mut reader = response.into_reader();

    let file_name = executable
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fnos-git-auth".to_string());

    #[cfg(windows)]
    {
        let target = parent.join(format!("{file_name}.new"));
        let mut file = fs::File::create(&target)
            .with_context(|| format!("创建更新文件失败: {}", target.display()))?;
        io::copy(&mut reader, &mut file).context("写入更新文件失败")?;
        file.flush().ok();
        println!("更新文件已下载: {}", target.display());
        println!("Windows 无法在程序运行时覆盖自身，请退出后手动替换:");
        println!("  1. 关闭所有 fnos-git-auth 进程");
        println!("  2. 用 {} 替换 {}", target.display(), executable.display());
        Ok(())
    }

    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;

        let target = parent.join(format!(".{file_name}.new"));
        let backup = parent.join(format!("{file_name}.backup"));
        let _ = fs::remove_file(&target);
        let mut file = fs::File::create(&target)
            .with_context(|| format!("创建更新文件失败: {}", target.display()))?;
        io::copy(&mut reader, &mut file).context("写入更新文件失败")?;
        file.flush().ok();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .context("设置新版本执行权限失败")?;

        if executable.exists() {
            fs::copy(&executable, &backup)
                .with_context(|| format!("备份旧版本失败: {}", backup.display()))?;
        }
        fs::rename(&target, &executable)
            .with_context(|| format!("替换可执行文件失败（新文件位于 {}）", target.display()))?;
        println!("更新成功! 旧版本备份: {}", backup.display());
        println!("请重新运行程序。");
        Ok(())
    }
}

/// 返回备份文件路径（供测试或诊断）。
pub fn backup_path(executable: &Path) -> PathBuf {
    let name = executable
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "fnos-git-auth".to_string());
    executable.with_file_name(format!("{name}.backup"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("v1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_version("0.1.0-beta.2"), vec![0, 1, 0, 2]);
        assert_eq!(parse_version("invalid"), vec![0]);
    }

    #[test]
    fn compares_versions_semantically() {
        assert_eq!(compare_versions("1.0.0", "1.0"), Ordering::Equal);
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Ordering::Less);
        assert_eq!(compare_versions("1.2.0", "1.10.0"), Ordering::Less);
        assert_eq!(compare_versions("2.0", "1.99.99"), Ordering::Greater);
    }

    #[test]
    fn truncates_multibyte_text_safely() {
        assert_eq!(truncate_chars("中文更新说明", 2), "中文...");
        assert_eq!(truncate_chars("short", 10), "short");
    }

    #[test]
    fn backup_name_is_next_to_executable() {
        let path = backup_path(Path::new("/tmp/fnos-git-auth"));
        assert_eq!(path, PathBuf::from("/tmp/fnos-git-auth.backup"));
    }
}
