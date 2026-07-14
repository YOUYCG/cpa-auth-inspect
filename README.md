# CPA Auth Inspect

一个面向 CLIProxyAPI / CLIProxyAPIPlus 的本地认证巡检工具。它由一个原生管理菜单插件和一个独立巡检服务组成，支持查看、探测和批量管理多厂商认证文件。

> This repository contains a native management-menu plugin plus a local inspection service for CLIProxyAPI-compatible authentication pools.

## 功能

- 支持 xAI、Codex、Claude、Gemini / Antigravity 认证识别。
- 本地检查 JSON、Token 到期时间、刷新能力和禁用状态。
- 可选在线探测；默认只做本地检查。
- 支持 xAI 与 Gemini 的可选 Token 刷新。
- 支持批量启用或禁用认证文件。
- 在 CLIProxyAPI 管理中心注册“认证巡检”菜单。
- 对外 API 结果会剔除 access token、refresh token、session token 和文件真实路径。

## 组成

```text
.
├── main.go                    # CLIProxyAPI 原生 C ABI 菜单插件
├── cpasdk/                    # 插件所需的最小 ABI 类型
├── inspector/                 # FastAPI 巡检服务
├── abi_smoke_test.py          # 共享库 ABI 冒烟测试
├── docker-compose.example.yml # 巡检服务运行示例
└── scripts/                   # Linux / Windows 构建脚本
```

## 要求

- Docker
- CLIProxyAPI / CLIProxyAPIPlus v7，且启用了原生插件系统
- Linux amd64 插件宿主（Docker 默认部署方式）

已在 CLIProxyAPIPlus `v7.2.62-5-plus` 上验证。

## 构建插件

Windows PowerShell：

```powershell
.\scripts\build-plugin.ps1
```

Linux / macOS：

```bash
./scripts/build-plugin.sh
```

产物位于 `dist/auth-inspect-linux-amd64.so`。

## 安装插件

将共享库复制到 CLIProxyAPI 插件目录：

```text
plugins/linux/amd64/auth-inspect-v0.2.0.so
```

在 CLIProxyAPI 配置中显式启用：

```yaml
plugins:
  enabled: true
  configs:
    auth-inspect:
      enabled: true
      priority: 10
```

## 启动巡检服务

将 `CPA_AUTH_DIR` 指向 CLIProxyAPI 的认证目录：

```powershell
$env:CPA_AUTH_DIR = "D:\path\to\auths"
docker compose -f docker-compose.example.yml up -d --build
```

Linux：

```bash
CPA_AUTH_DIR=/path/to/auths docker compose -f docker-compose.example.yml up -d --build
```

访问：

- 独立巡检页面：<http://127.0.0.1:18318/>
- 管理中心菜单：`认证巡检`
- 健康检查：<http://127.0.0.1:18318/healthz>

### xAI 重新授权（自动 / 手动）

完成一次 xAI 巡检后，点击“待重授权 xAI”可筛出 `invalid`、`token_expired`
和 `needs_refresh` 文件。

默认走**自动授权**（参考 `grok_bytao` 的 device-code + Chromium 确认链路）：

1. 解析登录凭据，优先级：
   - 认证 JSON 内的 `email` / `password` / `sso`（含 `oauth_record`）
   - 旁路目录 `SSO_AUTH_DIR`（默认 `/sso_auths`）里的 `sso-<email>.json`
     （`grok_bytao/sso_auths` 导出物，含 password + sso cookie）
2. 申请 xAI Device OAuth `device_code`；
3. 启动 Chromium（`DrissionPage` + `turnstilePatch`），可先注入 SSO cookie，
   再打开 `verification_uri_complete` 自动完成登录/Turnstile/「允许」；
4. 轮询 token，成功后原子回写认证文件并实探。

Chromium 授权运行在一次性隔离子进程中；即使浏览器或 Turnstile 卡住，巡检
页面、健康检查和取消接口仍可响应，取消/超时会连同 Chromium 子进程一起清理。

UI：

- **自动授权**：单条自动重授权
- **手动**：回退为打开 xAI 官方确认页，由你在浏览器里点允许
- **自动重授权当前筛选**：对筛选结果串行批量自动重授权

环境变量：

| 变量 | 默认 | 说明 |
|------|------|------|
| `XAI_REAUTH_AUTO` | `1` | 默认自动授权；`0` 则强制手动 |
| `XAI_REAUTH_HEADLESS` | `0` | 推荐有头模式；Docker 通过 Xvfb 提供虚拟显示。`1` 的真无头模式常被 Turnstile 拦截 |
| `XAI_REAUTH_PROXY` | 空 | accounts.x.ai / auth.x.ai 出站代理 |
| `XAI_REAUTH_TIMEOUT` | `240` | 浏览器确认超时秒 |
| `XAI_REAUTH_CONCURRENCY` | `1` | 同时进行的自动授权数（建议 1） |
| `SSO_AUTH_DIR` | `/sso_auths` | grok_bytao `sso_auths` 挂载路径，按 email 补 password/sso |

授权成功后，巡检服务会：

1. 在原文件旁生成带 UTC 时间戳的 `.bak` 备份；
2. 原子回写新的 Access Token、Refresh Token 和到期时间；
3. 立即执行一次 xAI 上游实探；
4. 由共享认证目录触发 CLIProxyAPI 热加载。

注意：自动授权依赖认证文件里的明文 `password`。没有密码时会自动回退到手动
Device OAuth。批量默认串行，避免多开浏览器触发风控。

### Codex / ChatGPT 重新授权

完成 Codex 巡检后，可点击“待重授权 Codex/ChatGPT”，对 `invalid`、
`token_expired` 和 `needs_refresh` 文件执行单条或当前筛选批量授权。

处理顺序：

1. 文件含 `refresh_token` 时，先调用 Codex OAuth 刷新；
2. 刷新不可用且文件含 `email` + `password` 时，由 Chromium 完成 ChatGPT
   登录和 Codex Device OAuth；若同时保存了 `session_token`，会先尝试注入该会话；
3. 成功后生成 `.bak`、原子回写平铺字段及 `tokens` 嵌套字段，并立即实探；
4. 缺少上述两类凭据的文件会被批量任务预先跳过，不会反复启动失败任务。

Codex 自动授权与 xAI 共用浏览器隔离、超时、代理及并发设置。当前只提供自动
模式；如果账号要求 MFA、邮箱验证码或第三方身份提供商交互，任务会保留原文件
并报告失败，需先补齐可复用凭据或手动更新认证文件。

## 安全说明

- 认证 JSON 是敏感数据，不要提交到 Git，也不要上传到 Issue。
- 在线探测会把当前认证发送给其对应的官方上游服务。
- 启用“尝试刷新”后，新 Token 会写回认证文件。
- 批量启用/禁用会修改 JSON 中的 `disabled` 字段。
- 建议只把巡检端口绑定到 `127.0.0.1`。
- 操作前请备份认证目录。

更多安全报告方式见 [SECURITY.md](SECURITY.md)。

## 开发与验证

```bash
go test ./...
go build -buildmode=c-shared -o dist/auth-inspect-linux-amd64.so .
python abi_smoke_test.py dist/auth-inspect-linux-amd64.so
python -m py_compile inspector/app.py
cd inspector && python -m unittest -v
```

## License

[MIT](LICENSE)
