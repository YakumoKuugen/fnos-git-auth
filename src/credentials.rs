//! 本地账号密码保存。
//!
//! 密码使用随机生成的 32 字节密钥做 AES-256-CBC 加密，格式与 Python 版本兼容：
//! `credentials.json` 中的 `password` 为 `Base64(IV || Ciphertext)`。
//! 密钥单独保存在 `.key`，文件权限仅当前用户可读写。

use std::fs;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::crypto::{aes_cbc_decrypt, aes_cbc_encrypt};
use crate::paths::AppPaths;
use crate::util::{create_private_dir, write_private_file};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct CredentialsStore {
    paths: AppPaths,
}

#[derive(Serialize, Deserialize)]
struct CredentialsFile {
    username: String,
    password: String,
}

impl CredentialsStore {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn save(&self, username: &str, password: &str) -> Result<()> {
        create_private_dir(self.paths.dir())?;
        let key = self.load_or_create_key()?;
        let encrypted = encrypt_password(password, &key)?;
        let data = CredentialsFile {
            username: username.to_string(),
            password: encrypted,
        };
        let mut encoded = serde_json::to_vec_pretty(&data).context("序列化凭据失败")?;
        encoded.push(b'\n');
        write_private_file(&self.paths.credentials_file(), &encoded)
    }

    pub fn get(&self) -> Option<Credentials> {
        let content = fs::read_to_string(self.paths.credentials_file()).ok()?;
        let data: CredentialsFile = serde_json::from_str(&content).ok()?;
        if data.username.is_empty() || data.password.is_empty() {
            return None;
        }
        // 读取时不创建新密钥；密钥丢失说明旧凭据已无法恢复。
        let key = self.read_key().ok()??;
        let password = decrypt_password(&data.password, &key).ok()?;
        Some(Credentials {
            username: data.username,
            password,
        })
    }

    pub fn delete(&self) -> Result<()> {
        let path = self.paths.credentials_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("删除凭据失败: {}", path.display())),
        }
    }

    fn read_key(&self) -> Result<Option<[u8; 32]>> {
        let path = self.paths.key_file();
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("读取密钥文件失败: {}", path.display()))
            }
        };
        if data.len() != 32 {
            return Ok(None);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(Some(key))
    }

    fn load_or_create_key(&self) -> Result<[u8; 32]> {
        if let Some(key) = self.read_key()? {
            return Ok(key);
        }

        if self.paths.key_file().exists() {
            eprintln!("警告: 密钥文件损坏，将重新生成（已保存的密码需要重新输入）");
        }
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        write_private_file(&self.paths.key_file(), &key)?;
        Ok(key)
    }
}

fn encrypt_password(password: &str, key: &[u8; 32]) -> Result<String> {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    let ciphertext = aes_cbc_encrypt(password.as_bytes(), key, &iv)?;
    let mut payload = Vec::with_capacity(16 + ciphertext.len());
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(payload))
}

fn decrypt_password(encoded: &str, key: &[u8; 32]) -> Result<String> {
    let payload = BASE64.decode(encoded).context("凭据密文不是有效 Base64")?;
    if payload.len() < 32 {
        anyhow::bail!("凭据密文长度无效");
    }
    let plaintext = aes_cbc_decrypt(&payload[16..], key, &payload[..16])?;
    String::from_utf8(plaintext).context("凭据内容不是有效 UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_encrypts_and_reads_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path());
        let store = CredentialsStore::new(paths.clone());

        store.save("alice", "s3cret-密码").unwrap();
        assert_eq!(
            store.get(),
            Some(Credentials {
                username: "alice".into(),
                password: "s3cret-密码".into(),
            })
        );

        let raw = fs::read_to_string(paths.credentials_file()).unwrap();
        assert!(!raw.contains("s3cret"));
        assert!(raw.contains("password"));
    }

    #[test]
    fn missing_key_means_credentials_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path());
        let store = CredentialsStore::new(paths.clone());
        store.save("alice", "password").unwrap();
        fs::remove_file(paths.key_file()).unwrap();
        assert!(store.get().is_none());
    }

    #[test]
    fn delete_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let store = CredentialsStore::new(AppPaths::new(dir.path()));
        store.save("alice", "password").unwrap();
        store.delete().unwrap();
        store.delete().unwrap();
        assert!(store.get().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn credential_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path());
        let store = CredentialsStore::new(paths.clone());
        store.save("alice", "password").unwrap();
        let mode = fs::metadata(paths.credentials_file())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
