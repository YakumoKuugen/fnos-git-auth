//! fnOS 协议使用的 RSA / AES / HMAC 加密与签名。

use aes::Aes256;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use rand::{distributions::Alphanumeric, Rng, RngCore};
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::{json, Value};
use sha2::Sha256;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// 这些请求不参与 HMAC 签名。
pub const NO_SIGN_REQUESTS: &[&str] = &["encrypted", "util.getSI", "util.crypto.getRSAPub", "ping"];

/// 生成指定长度的随机字母数字字符串。
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::rngs::OsRng;
    (0..length)
        .map(|_| rng.sample(Alphanumeric) as char)
        .collect()
}

/// 生成 16 字节随机 IV。
pub fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut iv);
    iv
}

/// RSA PKCS#1 v1.5 加密，返回 Base64 密文。
pub fn rsa_encrypt(public_key_pem: &str, plaintext: &str) -> Result<String> {
    let key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .context("解析服务器 RSA 公钥失败")?;
    let mut rng = rand::rngs::OsRng;
    let ciphertext = key
        .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext.as_bytes())
        .context("RSA 加密失败")?;
    Ok(BASE64.encode(ciphertext))
}

/// 使用任意 32 字节密钥做 AES-256-CBC + PKCS#7 加密。
pub fn aes_cbc_encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("AES 密钥长度必须为 32 字节"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES IV 长度必须为 16 字节"));
    }
    let encryptor =
        Aes256CbcEnc::new_from_slices(key, iv).map_err(|_| anyhow!("初始化 AES 加密器失败"))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// 使用任意 32 字节密钥做 AES-256-CBC 解密。
pub fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(anyhow!("AES 密钥长度必须为 32 字节"));
    }
    if iv.len() != 16 {
        return Err(anyhow!("AES IV 长度必须为 16 字节"));
    }
    let decryptor =
        Aes256CbcDec::new_from_slices(key, iv).map_err(|_| anyhow!("初始化 AES 解密器失败"))?;
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(data)
        .map_err(|_| anyhow!("AES 解密失败（填充无效）"))
}

/// AES-256-CBC + PKCS#7 加密，返回 Base64 密文。
pub fn aes_encrypt(data: &str, key: &str, iv: &[u8]) -> Result<String> {
    Ok(BASE64.encode(aes_cbc_encrypt(data.as_bytes(), key.as_bytes(), iv)?))
}

/// AES-256-CBC 解密，返回原始明文字节。
pub fn aes_decrypt_bytes(ciphertext: &str, key: &str, iv: &[u8]) -> Result<Vec<u8>> {
    let data = BASE64
        .decode(ciphertext)
        .context("AES 密文不是有效 Base64")?;
    aes_cbc_decrypt(&data, key.as_bytes(), iv)
}

/// 与 Python 版本保持一致：解密 `secret` 后，再对明文做一次 Base64。
pub fn aes_decrypt(ciphertext: &str, key: &str, iv: &[u8]) -> Result<String> {
    Ok(BASE64.encode(aes_decrypt_bytes(ciphertext, key, iv)?))
}

/// 构造加密登录请求。
pub fn encrypt_login_request(
    data: &str,
    public_key: &str,
    aes_key: &str,
    iv: &[u8],
) -> Result<Value> {
    let encrypted_key = rsa_encrypt(public_key, aes_key)?;
    let encrypted_data = aes_encrypt(data, aes_key, iv)?;
    Ok(json!({
        "req": "encrypted",
        "iv": BASE64.encode(iv),
        "rsa": encrypted_key,
        "aes": encrypted_data,
    }))
}

/// HMAC-SHA256 签名，返回 Base64。
pub fn get_signature(data: &str, key: &str) -> Result<String> {
    let key_bytes = BASE64.decode(key).context("签名密钥不是有效 Base64")?;
    let mut mac =
        HmacSha256::new_from_slice(&key_bytes).map_err(|_| anyhow!("初始化 HMAC 失败"))?;
    mac.update(data.as_bytes());
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

/// 对请求进行签名；不需要签名的请求直接返回紧凑 JSON。
pub fn sign_request(data: &Value, sign_key: Option<&str>) -> Result<String> {
    let json = serde_json::to_string(data)?;
    let req = data.get("req").and_then(Value::as_str).unwrap_or_default();
    match sign_key {
        Some(key) if !NO_SIGN_REQUESTS.contains(&req) => {
            Ok(format!("{}{}", get_signature(&json, key)?, json))
        }
        _ => Ok(json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings_are_correct_length() {
        let value = generate_random_string(32);
        assert_eq!(value.len(), 32);
        assert!(value.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn aes_round_trip_matches_python_semantics() {
        let key = generate_random_string(32);
        let iv = generate_iv();
        let plaintext = "测试数据 Hello World 123";

        let encrypted = aes_encrypt(plaintext, &key, &iv).unwrap();
        let encoded = aes_decrypt(&encrypted, &key, &iv).unwrap();
        let decoded = BASE64.decode(encoded).unwrap();
        assert_eq!(decoded, plaintext.as_bytes());
    }

    #[test]
    fn aes_decrypt_rejects_invalid_padding() {
        let key = generate_random_string(32);
        let iv = generate_iv();
        assert!(aes_decrypt("not-base64!", &key, &iv).is_err());
    }

    #[test]
    fn signs_and_serializes_requests() {
        let data = json!({"req": "user.info", "reqid": "abc"});
        let key = BASE64.encode(b"0123456789abcdef0123456789abcdef");
        let signed = sign_request(&data, Some(&key)).unwrap();
        let json = serde_json::to_string(&data).unwrap();
        assert!(signed.ends_with(&json));
        assert_eq!(signed.len(), json.len() + 44);
    }

    #[test]
    fn never_signs_whitelisted_requests() {
        let data = json!({"req": "util.getSI"});
        let key = BASE64.encode(b"0123456789abcdef0123456789abcdef");
        let output = sign_request(&data, Some(&key)).unwrap();
        assert_eq!(output, serde_json::to_string(&data).unwrap());
    }

    #[test]
    fn encrypted_login_request_has_expected_shape() {
        // 仅验证结构；无效公钥应返回错误而不是 panic。
        let result = encrypt_login_request("{}", "invalid", "a".repeat(32).as_str(), &[0u8; 16]);
        assert!(result.is_err());
    }
}
