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
```

## License

[MIT](LICENSE)
