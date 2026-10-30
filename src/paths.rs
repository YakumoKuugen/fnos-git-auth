//! 应用路径管理。支持通过 `FNOS_GIT_AUTH_CONFIG_DIR` 覆盖配置目录。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct AppPaths {
    dir: PathBuf,
}

impl AppPaths {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// 读取环境变量；未设置时使用 `~/.fnos-git-auth`。
    pub fn from_env() -> Result<Self> {
        if let Some(dir) = std::env::var_os("FNOS_GIT_AUTH_CONFIG_DIR") {
            if !dir.is_empty() {
                return Ok(Self::new(PathBuf::from(dir)));
            }
        }
        let home =
            dirs::home_dir().context("无法确定用户主目录，请设置 FNOS_GIT_AUTH_CONFIG_DIR")?;
        Ok(Self::new(home.join(".fnos-git-auth")))
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn config_file(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    pub fn credentials_file(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    pub fn key_file(&self) -> PathBuf {
        self.dir.join(".key")
    }

    pub fn hooks_dir(&self) -> PathBuf {
        self.dir.join("hooks")
    }

    pub fn hooks_backup_file(&self) -> PathBuf {
        self.dir.join("hooks-path.backup")
    }
}
