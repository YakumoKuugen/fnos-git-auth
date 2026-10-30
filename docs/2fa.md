# 飞牛 fnOS 两步验证（2FA）实现说明

本文记录本项目实现 2FA 登录时确认的协议行为。内容参考：

- [pyfnos 2FA 规格](https://github.com/Timandes/pyfnos/blob/main/specs/twofa-login-spec.md)
- [fnos-mock-server](https://github.com/Timandes/fnos-mock-server)
- [fnOS Web API 文档](https://fnosp.github.io/fnnas-api/)

## 登录状态

`user.login` 除了正常成功/失败，还可能返回三种结果：

### 1. 普通登录成功

```json
{
  "result": "succ",
  "token": "fnos-token",
  "secret": "AES 加密的签名密钥",
  "longToken": "long-token",
  "uid": 1000,
  "admin": true,
  "backId": "0000000000000001"
}
```

### 2. 已绑定 TOTP，需要验证码

```json
{
  "result": "succ",
  "isTwofaEnforced": true,
  "isBindTwofaSecret": true,
  "isBindSecureEmail": true,
  "secureEmail": "ti*****@example.com",
  "isTrustedDevice": false,
  "accessToken": "challenge-access-token"
}
```

关键判断：`isBindTwofaSecret == true`、`isTrustedDevice == false`、有
`accessToken`，且没有 `token` / `secret`。

### 3. 强制 2FA，但尚未绑定 TOTP

```json
{
  "result": "succ",
  "isTwofaEnforced": true,
  "isBindTwofaSecret": false,
  "isTrustedDevice": false,
  "accessToken": "setup-access-token",
  "twofaSecret": "BASE32_SECRET",
  "otpauth": "otpauth://totp/fnOS?..."
}
```

这种情况需要先在 fnOS Web 界面完成 TOTP 绑定。本项目会显示
`twofaSecret` / `otpauth` 作为辅助信息，但不会自动调用首绑接口。

## 提交验证码

请求名：

```text
user.2fa.loginVerify
```

请求体（加密前）：

```json
{
  "req": "user.2fa.loginVerify",
  "reqid": "<reqid>",
  "code": "583213",
  "isTrustedDevice": false,
  "accessToken": "<challenge-access-token>",
  "stay": 1,
  "deviceName": "fnos-git-auth",
  "deviceType": "Browser",
  "did": "<device-id>",
  "si": "<session-id>"
}
```

注意：

- `stay` 在前端抓包中是整数 `1` / `0`，不是布尔值；
- 请求必须像登录请求一样做 RSA + AES 加密，不能只签名；
- 每次 2FA 提交都会生成新的 AES key / IV，最终响应里的 `secret`
  用这套新密钥加密；
- `did` 是稳定的设备 ID，用于“信任此设备”。本项目会把它持久化到
  `config.json` 的 `server.did`，后续登录复用。

请求外层结构：

```json
{
  "req": "encrypted",
  "iv": "Base64(aes_iv)",
  "rsa": "Base64(RSA_Encrypt(aes_key))",
  "aes": "Base64(AES_Encrypt(login_verify_json))"
}
```

## 验证结果

成功响应：

```json
{
  "result": "succ",
  "token": "fnos-token",
  "secret": "AES 加密的签名密钥",
  "longToken": "long-token（可能没有）",
  "uid": 1001,
  "admin": true,
  "backId": "0000000000000002"
}
```

2FA 的最终响应可能没有 `longToken`，所以不能把 `longToken` 作为登录成功的必要条件。
最终成功应判断 `token` 和 `secret`，或至少判断 `token` 后再验证后续签名请求。

## 错误码

| errno | 含义 | 处理 |
| --- | --- | --- |
| `135168` | 验证码错误 / 凭证无效 | 提示重新输入 |
| `102570109` | 2FA 登录凭证过期 | 重新执行 `login` |

## 设备信任

登录和 2FA 请求都带 `did`。如果用户在 2FA 时提交
`isTrustedDevice: true`，服务器会把这个设备 ID 标记为可信，后续登录可能直接
返回最终 token，而不再返回 2FA 挑战。

因此 `did` 必须稳定保存，不能每次登录随机生成。当前实现把它保存在：

```json
{
  "server": {
    "url": "nas.example.com",
    "did": "mfrggzdfmztwq2lk-xxxxxxxxxxxxxxx-yyyyyyyyyyyyyyy"
  }
}
```

## 尚未实现

- 首次 TOTP 绑定的 `appcgi.tfa.security.v1.login.totpVerify` 流程；
- 安全邮箱验证码的 `appcgi.tfa.security.v1.login.sendEmailCode` 流程；
- 自动生成 TOTP（本工具只接受用户输入或 `--code`，不保存 TOTP secret）。

已有 TOTP 的账号可以正常完成登录；没有绑定 TOTP 的账号需要先在 Web 端绑定。
