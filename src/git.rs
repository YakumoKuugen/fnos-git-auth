//! Git 全局配置管理：extraHeader、凭证缓存和 hooksPath。

use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::{anyhow, bail, Context, Result};

/// Git 命令执行器。
///
/// `global_config` 仅用于测试隔离：设置后会注入 `GIT_CONFIG_GLOBAL` 并禁用系统配置。
/// 正常运行时不改变用户的 Git 环境。
#[derive(Debug, Clone, Default)]
pub struct GitRunner {
    global_config: Option<PathBuf>,
}

impl GitRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_global_config(path: impl Into<PathBuf>) -> Self {
        Self {
            global_config: Some(path.into()),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        if let Some(path) = &self.global_config {
            command.env("GIT_CONFIG_GLOBAL", path);
            command.env("GIT_CONFIG_NOSYSTEM", "1");
        }
        command
    }

    fn output<I, S>(&self, args: I) -> Result<Output>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command()
            .args(args)
            .output()
            .context("执行 git 失败，请确认 Git 已安装并在 PATH 中")
    }

    /// 执行命令，失败时返回 stderr。
    pub fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.output(args)?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if output.status.success() {
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                bail!("git 命令执行失败（退出码 {:?}）", output.status.code())
            } else {
                bail!("{stderr}")
            }
        }
    }

    /// 执行命令；非零退出码时返回 `None`。
    pub fn try_run<I, S>(&self, args: I) -> Result<Option<String>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.output(args)?;
        if output.status.success() {
            Ok(Some(
                String::from_utf8_lossy(&output.stdout).trim().to_string(),
            ))
        } else {
            Ok(None)
        }
    }

    pub fn version(&self) -> Result<String> {
        self.run(["--version"])
    }

    pub fn set_extra_header(&self, server: &str, token: &str) -> Result<()> {
        self.set_extra_header_for(server, token, true)
    }

    /// 根据 WebSocket 的 SSL 设置写入 Git extraHeader。
    ///
    /// fn connect 域名使用 HTTPS；本地 fnOS 常用 HTTP，因此 `use_ssl=false` 时
    /// 同时写入 HTTP 和 HTTPS 两套配置，兼容不同 Git 远程地址。
    pub fn set_extra_header_for(&self, server: &str, token: &str, use_ssl: bool) -> Result<()> {
        self.set_extra_header_scheme(server, token, "https")?;
        if !use_ssl {
            self.set_extra_header_scheme(server, token, "http")?;
        }
        Ok(())
    }

    fn set_extra_header_scheme(&self, server: &str, token: &str, scheme: &str) -> Result<()> {
        let value = format!("Cookie: entry-token={token}");
        let key = format!("http.{scheme}://{server}.extraHeader");
        self.run(["config", "--global", &key, &value])
            .with_context(|| format!("配置 git extraHeader 失败: {scheme}://{server}"))?;
        println!("已配置 git extraHeader: {scheme}://{server}");

        // Git 2.13+ 支持 `http.<url>.extraHeader` 的通配符。
        let wildcard = format!("http.{scheme}://*.{server}/.extraHeader");
        match self.run(["config", "--global", &wildcard, &value]) {
            Ok(_) => println!("已配置 git extraHeader (通配符): *.{server}"),
            Err(error) => {
                println!("通配符配置失败（可能 Git 版本不支持）: {error}");
            }
        }
        Ok(())
    }

    pub fn remove_extra_header(&self, server: &str) -> Result<()> {
        let mut removed = false;
        let mut removed_wildcard = false;
        for scheme in ["https", "http"] {
            let key = format!("http.{scheme}://{server}.extraHeader");
            if self
                .try_run(["config", "--global", "--unset", &key])?
                .is_some()
            {
                removed = true;
            }

            let wildcard = format!("http.{scheme}://*.{server}/.extraHeader");
            if self
                .try_run(["config", "--global", "--unset", &wildcard])?
                .is_some()
            {
                removed_wildcard = true;
            }
        }
        if removed {
            println!("已移除 git extraHeader: {server}");
        }
        if removed_wildcard {
            println!("已移除 git extraHeader (通配符): *.{server}");
        }
        Ok(())
    }

    pub fn has_extra_header(&self, server: &str) -> bool {
        self.get_extra_header(server).is_some()
    }

    pub fn get_extra_header(&self, server: &str) -> Option<String> {
        for scheme in ["https", "http"] {
            let key = format!("http.{scheme}://{server}.extraHeader");
            if let Some(value) = self
                .try_run(["config", "--global", "--get", &key])
                .ok()
                .flatten()
            {
                return Some(value);
            }
        }
        None
    }

    pub fn list_extra_headers(&self) -> Result<Vec<String>> {
        let output = self.run(["config", "--global", "--list"])?;
        Ok(output
            .lines()
            .filter(|line| line.to_ascii_lowercase().contains("extraheader"))
            .map(ToOwned::to_owned)
            .collect())
    }

    pub fn clear_all_extra_headers(&self) -> Result<Vec<String>> {
        let headers = self.list_extra_headers()?;
        let mut removed = Vec::new();
        for line in headers {
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            if self
                .try_run(["config", "--global", "--unset", key])?
                .is_some()
            {
                removed.push(key.to_string());
            }
        }
        Ok(removed)
    }

    pub fn set_credential_cache(&self, seconds: u64) -> Result<()> {
        if seconds == 0 {
            self.try_run(["config", "--global", "--unset", "credential.helper"])?;
        } else {
            self.run([
                "config",
                "--global",
                "credential.helper",
                &format!("cache --timeout={seconds}"),
            ])?;
        }
        Ok(())
    }

    pub fn hooks_path(&self) -> Result<Option<String>> {
        self.try_run(["config", "--global", "--get", "core.hooksPath"])
    }

    pub fn set_hooks_path(&self, path: &str) -> Result<()> {
        self.run(["config", "--global", "core.hooksPath", path])?;
        Ok(())
    }

    pub fn unset_hooks_path(&self) -> Result<()> {
        self.try_run(["config", "--global", "--unset", "core.hooksPath"])?;
        Ok(())
    }
}

pub fn ensure_git_available(runner: &GitRunner) -> Result<String> {
    runner.version().map_err(|error| {
        anyhow!(
            "错误: {error}\n\n本工具需要 Git 才能工作。请先安装 Git:\n\n  \
             Linux (Debian/Ubuntu): sudo apt install git\n  \
             Linux (RHEL/CentOS): sudo yum install git\n  \
             macOS: brew install git\n  \
             Windows: https://git-scm.com/download/win 或 winget install Git.Git"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Option<(tempfile::TempDir, GitRunner)> {
        if Command::new("git").arg("--version").output().is_err() {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("gitconfig");
        Some((dir, GitRunner::with_global_config(config)))
    }

    #[test]
    fn manages_extra_headers() {
        let Some((_dir, git)) = setup() else {
            return;
        };
        let server = "demo.fnos.net";

        git.set_extra_header(server, "abcdef").unwrap();
        assert!(git.has_extra_header(server));
        assert_eq!(
            git.get_extra_header(server).unwrap(),
            "Cookie: entry-token=abcdef"
        );
        assert_eq!(git.list_extra_headers().unwrap().len(), 2);

        git.remove_extra_header(server).unwrap();
        assert!(!git.has_extra_header(server));
        assert!(git.list_extra_headers().unwrap().is_empty());
    }

    #[test]
    fn configures_http_and_https_for_local_servers() {
        let Some((_dir, git)) = setup() else {
            return;
        };
        git.set_extra_header_for("192.168.1.4:5666", "token", false)
            .unwrap();
        assert_eq!(git.list_extra_headers().unwrap().len(), 4);
        git.remove_extra_header("192.168.1.4:5666").unwrap();
        assert!(git.list_extra_headers().unwrap().is_empty());
    }

    #[test]
    fn clears_all_extra_headers() {
        let Some((_dir, git)) = setup() else {
            return;
        };
        git.set_extra_header("one.fnos.net", "a").unwrap();
        git.set_extra_header("two.fnos.net", "b").unwrap();
        let removed = git.clear_all_extra_headers().unwrap();
        assert_eq!(removed.len(), 4);
        assert!(git.list_extra_headers().unwrap().is_empty());
    }

    #[test]
    fn configures_credential_cache() {
        let Some((_dir, git)) = setup() else {
            return;
        };
        git.set_credential_cache(3600).unwrap();
        assert_eq!(
            git.try_run(["config", "--global", "--get", "credential.helper"])
                .unwrap()
                .as_deref(),
            Some("cache --timeout=3600")
        );
        git.set_credential_cache(0).unwrap();
        assert!(git
            .try_run(["config", "--global", "--get", "credential.helper"])
            .unwrap()
            .is_none());
    }

    #[test]
    fn remove_missing_header_is_ok() {
        let Some((_dir, git)) = setup() else {
            return;
        };
        git.remove_extra_header("none.fnos.net").unwrap();
    }
}
