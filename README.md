# fnos-git-auth (Rust)

飞牛 fnOS Git 认证工具的 Rust 实现。它通过 fn connect 的 WebSocket 服务登录 fnOS，
获取用于 HTTP 认证的 `entry-token`，并自动写入 Git 全局 `extraHeader`，从而免密
`clone` / `fetch` / `push` NAS 上的 Git 仓库。

> 本项目参考 [donnel666/fnos-git-auth](https://github.com/donnel666/fnos-git-auth)
> 的 Python 实现重写，协议、配置格式和命令行为保持兼容。

## 功能

- 🔐 WebSocket + RSA/AES 加密登录 fnOS，不把明文密码发给服务器
- 🛡️ 支持已绑定 TOTP 的两步验证（2FA），可交互输入或 `--code` 非交互传入
- 🔑 自动获取并配置 `entry-token`
- 🔄 通过全局 Git hooks 在 `push` 前按需刷新 token
- 💾 默认加密保存账号密码，后续登录无需重复输入
- 🌐 同时配置主域名和子域名通配符 `extraHeader`
- 🔒 配置目录 `0700`、敏感文件 `0600`（Windows 使用 `icacls`）
- 🖥️ 支持 Linux / macOS / Windows，纯 Rust 单文件二进制
- 🩺 内置脱敏诊断包，便于反馈问题

## 安装

### 从源码构建

需要 Rust 1.88 或更新版本，以及 Git：

```bash
git clone <this-repo>
cd fnos-git-auth
cargo build --release
```

产物位于 `target/release/fnos-git-auth`（Windows 为 `fnos-git-auth.exe`）。

安装到 Cargo 的 bin 目录：

```bash
cargo install --path .
```

### 直接运行

```bash
cargo run -- --help
```

## 快速开始

```bash
# 首次登录（交互式输入服务器、用户名、密码）
fnos-git-auth login

# 已保存凭据时直接登录
fnos-git-auth login

# 切换用户
fnos-git-auth login -u newuser

# 切换服务器
fnos-git-auth login -s other.fnos.net

# 已开启两步验证：交互输入验证码
fnos-git-auth login

# 非交互传入 6 位 TOTP 验证码，并信任当前设备
fnos-git-auth login --code 583213 --trust-device

# 登录后直接使用 Git
git clone https://your-server.fnos.net/repo.git
git push origin main
```

登录成功后，只要不执行 `logout`，token 会通过 Git hook 在需要时自动刷新，
无需手动关心过期时间。

### 局域网 / 自签名证书

默认使用 `wss://`。访问本地 fnOS 且没有有效证书时：

```bash
fnos-git-auth config -k use_ssl -v false
fnos-git-auth login -s 192.168.1.4:5666
```

恢复默认：

```bash
fnos-git-auth config -k use_ssl -v true
```

`use_ssl=false` 时，工具会同时写入 HTTP 和 HTTPS 两套 `extraHeader`，
无论仓库地址是 `http://` 还是 `https://` 都能匹配。

## 命令参考

### `login`

```text
fnos-git-auth login [OPTIONS]

-s, --server <SERVER>      服务器地址（可带 https://，会自动去掉协议和路径）
-u, --username <USERNAME>  用户名
-p, --password <PASSWORD>  密码
-n, --no-save              不保存凭据
    --code <CODE>          6 位两步验证码
    --trust-device         将当前设备标记为可信设备，减少后续 2FA
```

登录逻辑：

| 场景 | 行为 |
| --- | --- |
| 首次登录 | 交互式询问服务器、用户名、密码 |
| 已有服务器和保存的凭据 | 直接登录，无需输入 |
| 仅切换用户 | 使用已保存服务器，提示输入新密码 |
| 切换服务器 | 提示输入用户名和密码 |
| 账号开启 2FA | 提示输入 6 位 TOTP 验证码，或用 `--code` 传入 |
| 传入全部参数 | 完全非交互（2FA 账号需同时传 `--code`） |

登录成功后会：

1. 写入 `~/.fnos-git-auth/config.json`；
2. 设置 Git 全局 `http.https://<server>.extraHeader` 和通配符配置；
3. 设置全局 `core.hooksPath`，安装 `pre-push` / `pre-auto-gc` hook。

#### 两步验证（2FA）

fnOS 对开启了 2FA 的账号会在密码校验后返回挑战，而不是直接返回 token。
本工具会：

1. 识别 `isBindTwofaSecret=true`、`isTrustedDevice=false` 且带 `accessToken` 的挑战；
2. 提示输入认证器中的 6 位 TOTP 验证码；
3. 使用一套全新的 AES 会话密钥加密 `user.2fa.loginVerify`；
4. 提交 `code`、`accessToken`、`did`、`stay`、设备信息并完成登录。

`--trust-device` 会把 `isTrustedDevice=true` 发给服务器。工具会在配置中保存稳定的
设备 ID（`did`），后续登录继续复用，服务器可据此跳过 2FA。

如果账号被强制要求 2FA 但还没有绑定 TOTP，工具会显示 `twofaSecret` / `otpauth`
并提示先到 fnOS Web 界面完成绑定。目前不自动执行首次 TOTP 绑定，也不会发送
安全邮箱验证码；请使用认证器生成的 TOTP 验证码。

完整请求/响应字段和错误码见 [docs/2fa.md](docs/2fa.md)。

建议 2FA 账号登录时加上 `--trust-device`，这样后续自动刷新 token 时更不容易
再次被要求输入验证码。没有 long-token 且设备又不受信任时，hook 无法代替你
完成 2FA，需要手动执行 `login --code <CODE>`。

### `logout`

```bash
fnos-git-auth logout
fnos-git-auth logout -a   # 同时删除保存的凭据
```

清除 token、Git `extraHeader` 和自动刷新 hooks，保留服务器地址（和默认情况下的凭据）。
安装 hooks 时若检测到用户原有 `core.hooksPath`，会备份并在登出时恢复。

### `status`

```bash
fnos-git-auth status
```

输出服务器、用户名、登录状态、过期时间、Git 配置和自动刷新状态。

### `refresh`

```bash
fnos-git-auth refresh
```

刷新顺序：

1. `fnos-token` 未过期：`authToken` 验证后重新获取 `entry-token`；
2. `fnos-token` 过期、`long-token` 未过期：`tokenLogin` 换新会话；
3. 都不可用：使用保存的账号密码重新登录。

`tokenLogin` 是登录态接口，请求必须使用已有 `sign_key` 做 HMAC 签名。旧实现漏掉签名时，
服务器返回 `65534`（验签失败），随后会错误地回退到“账号密码 + 2FA”。当前版本已修复：
`fnos-token` 失效后会优先静默使用 `long-token` 刷新，正常不会再要求输入验证码。

push 前 hook 会主动执行一次 `refresh`，确保 Git 使用最新的 `entry-token`，避免服务端
提前失效导致 401/403。手动执行 `refresh` 也可以随时刷新。
本地记录的过期时间只是估算；如果服务端提前让 token 失效，push 返回 401/403 时执行一次
`fnos-git-auth refresh` 即可。

### `config`

```bash
fnos-git-auth config                         # 显示所有配置
fnos-git-auth config -k timeout              # 显示单项
fnos-git-auth config -k timeout -v 60        # 修改
fnos-git-auth config -r                      # 恢复默认
```

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `timeout` | `30.0` | WebSocket 连接和请求超时（秒） |
| `use_ssl` | `true` | 是否使用 `wss://` / `https://` |
| `fn_connect_cookie` | `mode=relay; language=zh` | fn connect WebSocket Cookie |
| `device_type` | `Browser` | 登录设备类型 |
| `device_name` | `fnos-git-auth` | 登录设备名称 |
| `language` | `zh` | 客户端语言 |
| `entry_token_expire_hours` | `8` | 本地记录的 entry-token 有效期 |
| `fnos_token_expire_hours` | `8` | 本地记录的 fnos-token 有效期 |
| `long_token_expire_days` | `25` | 本地记录的 long-token 有效期 |
| `token_refresh_threshold_hours` | `1.0` | 提前多久触发自动刷新 |
| `auto_save_credentials` | `true` | 登录成功后询问保存凭据 |
| `auto_refresh_token` | `true` | 登录时是否安装自动刷新 hooks |

### `git`

```bash
fnos-git-auth git                         # 显示 extraHeader
fnos-git-auth git -c                      # 清除全部 extraHeader
fnos-git-auth git -r old.fnos.net         # 清除指定服务器
fnos-git-auth git -t 3600                 # 设置 credential helper 缓存
fnos-git-auth git -t 0                    # 禁用 credential helper
```

### `diagnostic`

```bash
fnos-git-auth diagnostic                  # 当前目录生成 tar.gz
fnos-git-auth diagnostic -o ./out         # 指定输出目录
fnos-git-auth diagnostic -p               # 仅打印 JSON
```

会自动脱敏 token、密码、签名密钥和 Git `extraHeader` 中的 `entry-token`。

### `update`

```bash
fnos-git-auth update          # 检查并安装（若有匹配的 Rust 资产）
fnos-git-auth update -c       # 仅检查
fnos-git-auth update -f       # 强制重新下载
```

默认检查 `donnel666/fnos-git-auth` 的 GitHub Release，可用
`FNOS_GIT_AUTH_UPDATE_REPO=owner/repo` 覆盖。自动更新只匹配
`fnos-git-auth-rust-*` 资产名，不会误装 Python 版本。
Windows 不允许覆盖正在运行的可执行文件，因此会下载 `.new` 文件并提示手动替换。

## 工作原理

```text
┌─────────────┐   1. wss /websocket?type=main    ┌──────────────┐
│ Rust CLI    │ ───────────────────────────────> │ fnOS         │
│             │   2. util.crypto.getRSAPub       │ fn connect   │
│             │ <─────────────────────────────── │              │
│             │   3. user.login（RSA+AES）        │              │
│             │ <─────────────────────────────── │              │
│             │   4. exchangeEntryToken          │              │
│             │ <─────────────────────────────── │              │
└──────┬──────┘                                  └──────────────┘
       │
       │ 写入 ~/.fnos-git-auth/config.json
       │ git config --global http.https://<server>.extraHeader
       │ git config --global core.hooksPath ~/.fnos-git-auth/hooks
       ▼
   git clone / push 时自动携带 Cookie: entry-token=...
```

关键协议细节：

- 登录请求：32 字节随机 AES 密钥 + 随机 IV，AES-256-CBC/PKCS#7 加密请求体，
  RSA PKCS#1 v1.5 加密 AES 密钥；
- 服务端返回的 `secret` 解密后需要再做一次 Base64，作为 HMAC-SHA256 的签名密钥；
- 除 `encrypted`、`util.getSI`、`util.crypto.getRSAPub`、`ping` 外，请求格式为
  `Base64(HMAC-SHA256(compact_json)) + compact_json`；
- WebSocket `Cookie` 头仅在 SSL 模式下发送。

## 文件与安全

配置目录默认为 `~/.fnos-git-auth`，可通过 `FNOS_GIT_AUTH_CONFIG_DIR` 覆盖：

```text
~/.fnos-git-auth/
├── config.json          # token、服务器、用户偏好（0600）
├── credentials.json     # AES-256-CBC 加密后的密码（0600）
├── .key                 # 32 字节本地加密密钥（0600）
└── hooks/
    ├── pre-push
    └── pre-auto-gc
```

注意事项：

- token 会以明文保存在 `config.json`，与 Python 版本一致；请保护配置目录。
- 保存的密码只用本地 `.key` 加密。删除 `.key` 后旧凭据无法恢复，需要重新输入密码。
- `entry-token` 同时会出现在 Git 全局配置中，这是 Git 认证机制决定的。
- 2FA 目前支持已绑定 TOTP 的账号。首次绑定请在 fnOS Web 界面完成；仅安全邮箱验证码的流程尚未实现。
- 自动刷新 token 时不会交互式询问 2FA；如果 long-token 也失效且账号开启了 2FA，需要手动执行 `login --code <CODE>`。
- 仓库读写权限仍由 fnOS / Git 账号权限控制，本工具只解决认证。

## 与 Python 版本的兼容性

- 读取和写入相同位置的 `config.json`、`credentials.json`、`.key`；
- 凭据加密格式兼容，可以在两个版本之间切换；
- 新增 `did` 字段会随配置保留，不影响 Python 版本读取；
- Git `extraHeader` 键名和 hooks 路径一致；
- 额外的 Rust 特性：2FA 登录、原有 hooks 路径备份/恢复、push 前主动刷新、
  Windows 更新下载提示。

## 开发

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

测试覆盖加密、配置/凭据、Git 配置、hooks、诊断脱敏、CLI 参数，以及本地模拟
fnOS WebSocket 服务上的普通登录、2FA 验证、fnos-token 和 long-token 刷新。
测试不会修改真实的全局 Git 配置，也不会访问真实 fnOS 服务器。

## 许可证

MIT，见 [LICENSE](LICENSE)。原 Python 项目版权归 donnel 所有。
