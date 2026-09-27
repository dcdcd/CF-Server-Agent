# CF-Server-Agent

CF-Server-Monitor 的轻量 Go Agent。Agent 采集主机资源、网络流量、磁盘 I/O 和动态网络检测结果，并通过当前协议（配置 schema 8）上报到 Cloudflare Worker。

本仓库仅维护当前实现：本地配置与控制端配置均要求 schema 8，不读取旧版固定检测节点字段，也不迁移 Shell Agent 的配置或数据。

## 安装

Linux、macOS、FreeBSD：

```sh
curl -fsSL https://raw.githubusercontent.com/dengchangdong/CF-Server-Agent/main/install.sh \
  | sh -s -- install -id=SERVER_ID -secret=SECRET -url=https://monitor.example.com/update
```

Windows PowerShell：

```powershell
$script = Join-Path $env:TEMP "cf-server-agent-install.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/dengchangdong/CF-Server-Agent/main/install.ps1" -OutFile $script -UseBasicParsing
& $script install -id=SERVER_ID -secret=SECRET -url=https://monitor.example.com/update
```

卸载：

```sh
curl -fsSL https://raw.githubusercontent.com/dengchangdong/CF-Server-Agent/main/install.sh | sh -s -- uninstall
```

## 当前配置

安装阶段只需提供身份和控制端地址。服务器分组、检测节点及运行参数均由控制端动态下发：

- `collect_interval`、`report_interval`：资源采样与上报间隔。
- `probes`：每台服务器选择的动态节点；每个节点可使用 `tcp` 或 `icmp`。
- `probe_interval`、`probe_window`：检测频率与滚动统计窗口。
- `probe_concurrency`：同时执行的最大检测任务数。
- `probe_timeout_ms`：单次检测超时。
- `ip_refresh_interval`：公网 IPv4/IPv6 刷新间隔。
- `report_timeout_ms`：HTTP 上报和修正请求超时。
- `dns_cache_seconds`：检测目标的 DNS 缓存时间。
- `ip_lookup_timeout_ms`：公网 IP 查询的单个请求超时。
- `ipv4_lookup_urls`、`ipv6_lookup_urls`：公网 IP 查询地址列表，仅接受 HTTPS。
- `interface`、`reset_day`、`connection_mode`：网卡、月流量重置日与传输模式。

自动更新检查间隔由本机安装参数 `-update_check_interval` 设置，取值范围为 300–604800 秒；其余运行参数由控制端统一配置。

运行参数会经过边界校验，并以 `0600` 权限写入 Agent 配置文件。动态节点最多 64 个；并发和超时均有安全上限，避免错误配置导致资源耗尽。

## 传输与资源策略

- 默认使用 WebSocket 上报，连接不可用时按配置回退到 HTTP。
- WSS 断线采用有上限的指数退避；HTTP 上报不会在同一周期重复提交。
- 网络检测使用有界并发和单次采样，并在配置窗口内计算中位延迟与丢包率。
- DNS 结果复用，公网 IP 低频刷新，静态主机信息复用，降低服务器 CPU、DNS 与网络开销。
- 控制端配置带 MD5 状态，配置未变化时不重复写本地文件。

ICMP 使用原始套接字。在 Linux 上请让服务以具备相应权限的用户运行；权限不足时该节点会返回不可用，TCPing 节点不受影响。

## 本地构建与验证

```sh
go test ./...
go vet ./...
go build ./cmd/cf-probe
```

发布工作流会为支持的平台构建 `cf-probe-*` 二进制和 `checksums.txt`。自动更新会校验 SHA-256 后再替换程序。
