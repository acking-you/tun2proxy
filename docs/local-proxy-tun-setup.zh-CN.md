# 使用本地 HTTP 或 SOCKS5 代理接管 TUN 流量

本文介绍如何在本机已经有 HTTP 或 SOCKS5 代理的情况下，使用
`tun2proxy` 创建 TUN 设备并将系统流量交给该代理。

典型数据路径如下：

```text
应用程序 -> 系统路由 -> TUN -> tun2proxy -> 本地代理 -> 远端服务器
```

## 1. 使用前确认

开始前需要确认以下信息：

- 本地代理监听地址，例如 `127.0.0.1:8080` 或 `127.0.0.1:1080`。
- 本地代理协议是 HTTP、SOCKS4 还是 SOCKS5，协议必须与 `--proxy` URL 一致。
- 本地代理访问外网时使用固定远端 IP，还是会直接连接任意目标地址。
- 如果需要代理通用 UDP，SOCKS5 服务必须真正支持 RFC 1928 `UDP ASSOCIATE`。

可以先验证本地代理是否可用：

```powershell
# HTTP
curl.exe --proxy "http://127.0.0.1:8080" https://example.com

# SOCKS5，并由代理端解析域名
curl.exe --proxy "socks5h://127.0.0.1:1080" https://example.com
```

Windows 用户还需要保证 `wintun.dll` 与 `tun2proxy-bin.exe` 位于同一目录。使用
`--setup` 时可以直接在普通 PowerShell 或终端中启动；程序检测到权限不足后会保留
全部参数、工作目录和当前控制台，通过 UAC 弹窗请求管理员权限，不会另外打开终端
窗口。Linux 用户需要使用 root 权限或等效的网络管理能力。

### Windows 自动提权的行为和限制

Windows 的 UAC 不能把正在运行的进程原地变成管理员进程。tun2proxy 会保留一个
普通权限父进程，由它请求 UAC、等待管理员子进程，并把子进程的退出码传回当前终端。
因此在任务管理器中看到两个 `tun2proxy-bin.exe` 属于正常现象，父进程只占用少量
内存和句柄。

管理员子进程启动后会重新连接到原控制台，并把标准输入、标准输出和标准错误绑定到
`CONIN$`/`CONOUT$`。这种方式不会修改终端模拟器的永久配置，但存在以下边界：

- 原终端必须在程序运行期间保持打开。正常情况下在原终端按 `Ctrl+C`，让子进程清理
  TUN 和路由后退出。
- 输出重定向和管道不一定能够保留。例如 `tun2proxy-bin.exe ... > run.log 2>&1`
  可能仍把管理员子进程的日志写回终端，而不是目标文件。
- 自动提权适合 PowerShell、CMD 和 Windows Terminal 等交互式控制台，不适合
  `CREATE_NO_WINDOW`、IDE 后台任务、任务计划程序或 Windows 服务等无控制台环境。
  这些环境应当直接配置为以最高权限运行，避免触发交互式 UAC。
- 如果子进程无法重新连接原控制台，它最初处于隐藏状态，错误信息可能不可见，只能
  从非零退出码判断启动失败。
- 如果管理员子进程被强制结束或崩溃，正常退出时执行的路由恢复可能来不及完成。这与
  直接在管理员终端中强制结束程序具有相同风险。
- 用户拒绝 UAC 请求时不会启动 TUN，原进程会返回启动错误。

服务化或无人值守部署不应依赖此自动提权流程，应使用 Windows 服务账户或任务计划
程序的“使用最高权限运行”选项。

## 2. 首先解决路由循环

本地代理是 TUN 的上游，但它自己的出站连接同样可能被 TUN 捕获。如果不做绕过，
流量会不断回到本地代理，形成循环。

根据本地代理的工作方式，选择以下一种方案。

| 本地代理情况 | 推荐方案 |
| --- | --- |
| 所有流量都发往一个或少数固定远端 IP | 使用 `--bypass <IP/CIDR>` |
| 在 Windows 或 Linux 本机运行，并直接连接动态目标 | 使用 `--bypass-process <PROCESS>` |
| 代理运行在 WSL，而 tun2proxy 运行在 Windows | 让 WSL 代理只连接固定远端 IP，再使用 `--bypass` |
| macOS、iOS 或 Android 上的本地代理 | 使用固定远端 IP 和 `--bypass` |

### 2.1 固定远端 IP

假设本地代理最终只连接 `203.0.113.10`，将这个地址排除在 TUN 路由之外：

```text
--bypass "203.0.113.10/32"
```

如果有多个固定远端地址，可以重复指定：

```text
--bypass "203.0.113.10/32" --bypass "198.51.100.20/32"
```

不要把 `127.0.0.1` 当作真正的循环绕过目标。回环地址本来就留在本机；需要绕过的
是本地代理连接的真实远端服务器。

### 2.2 按进程绕过

如果本地代理会直接连接任意目标地址，无法提前列出远端 IP，可以按进程名绕过：

```text
--bypass-process "my-proxy.exe"
```

该功能仅在 Windows 和 Linux 上实现。进程名匹配不区分大小写，Windows 下 `.exe`
后缀可以省略。tun2proxy 会自动检测真实出口网卡，也可以显式指定：

```text
--bypass-process "my-proxy.exe" --bind-interface "WLAN"
```

Linux 示例：

```text
--bypass-process "my-proxy" --bind-interface "eth0"
```

### 2.3 WSL 特别说明

当 tun2proxy 运行在 Windows、代理运行在 WSL2 时，Windows 无法把 WSL 中的 Linux
PID 识别为 Windows TCP/UDP 连接的所有者，因此 `--bypass-process` 通常无法匹配这个
代理进程。

这种情况下应当让 WSL 代理关闭直连分流，使其所有出站连接只去往固定代理服务器，
然后在 Windows 上使用该服务器 IP 的 `--bypass`。如果 WSL 代理仍会直接连接动态
目标，单个固定 IP 无法完整阻止循环。

## 3. 使用本地 HTTP 代理

假设：

- 本地 HTTP 代理监听 `127.0.0.1:8080`。
- 它只连接固定远端服务器 `203.0.113.10`。

Windows PowerShell（权限不足时会自动弹出 UAC）：

```powershell
.\tun2proxy-bin.exe `
  --setup `
  --proxy "http://127.0.0.1:8080" `
  --dns virtual `
  --bypass "203.0.113.10/32"
```

Linux：

```bash
sudo ./tun2proxy-bin \
  --setup \
  --proxy "http://127.0.0.1:8080" \
  --dns virtual \
  --bypass "203.0.113.10/32"
```

如果 HTTP 代理在同一个 Windows 或 Linux 系统中运行，并且会动态直连目标，可改用：

```powershell
.\tun2proxy-bin.exe `
  --setup `
  --proxy "http://127.0.0.1:8080" `
  --dns virtual `
  --bypass-process "my-http-proxy.exe"
```

HTTP `CONNECT` 只能承载 TCP。普通 UDP 不会通过 HTTP 代理发送；`--dns virtual` 可以
在 tun2proxy 内部处理 DNS，但不会让游戏、QUIC、语音等通用 UDP 获得 HTTP 代理能力。
如需通过 HTTP 上游承载 UDP，需要另外部署 UdpGW 并使用 `--udpgw-server`。

## 4. 使用本地 SOCKS5 代理

假设：

- 本地 SOCKS5 代理监听 `127.0.0.1:1080`。
- 它只连接固定远端服务器 `203.0.113.10`。

Windows PowerShell（权限不足时会自动弹出 UAC）：

```powershell
.\tun2proxy-bin.exe `
  --setup `
  --proxy "socks5://127.0.0.1:1080" `
  --dns virtual `
  --bypass "203.0.113.10/32"
```

Linux：

```bash
sudo ./tun2proxy-bin \
  --setup \
  --proxy "socks5://127.0.0.1:1080" \
  --dns virtual \
  --bypass "203.0.113.10/32"
```

带用户名和密码时使用标准代理 URL：

```text
socks5://username:password@127.0.0.1:1080
```

用户名或密码中的 `@`、`:`、`/` 等保留字符需要进行百分号编码。例如密码
`pass@word` 应写成 `pass%40word`。

### SOCKS5 UDP

如果 SOCKS5 服务支持 `UDP ASSOCIATE`，tun2proxy 会为普通单播 UDP 建立 SOCKS5 UDP
转发，TCP 与 UDP 可以使用同一条启动命令。代理返回的 UDP Relay 地址必须能够从
运行 tun2proxy 的系统访问。

以下情况不能视为完整的 SOCKS5 UDP 支持：

- 服务只支持 SOCKS5 `CONNECT`。
- UDP Relay 仅绑定在远端回环地址，客户端无法访问。
- UDP Relay 使用另一个会被 TUN 再次捕获的 IP，且没有为该 IP 配置绕过。
- 仅在产品界面中写有“UDP”，但实际上使用的是其他私有隧道协议。

广播、组播、DHCP 和 mDNS 等本地链路 UDP 不适合通过普通 SOCKS5 UDP 代理。IPv6
流量还需要添加 `--ipv6-enabled`，并确保代理端与 UDP Relay 都支持 IPv6。

## 5. DNS 策略

推荐本地代理场景使用：

```text
--dns virtual
```

它会拦截 DNS 请求，分配 `198.18.0.0/15` 中的虚拟地址，并在连接代理时恢复域名。
这样既能避免依赖本地 UDP DNS，也能实现类似 SOCKS5h 的远端域名访问效果。

其他策略：

- `--dns over-tcp`：把 DNS 请求转换为 TCP，并通过代理发送到 `--dns-addr`。
- `--dns direct`：保留普通 DNS 流程，要求当前代理路径能够处理对应的 UDP；HTTP
  上游通常不适合使用此选项。

## 6. 常见完整示例

### Windows + WSL 本地 HTTP 代理 + 固定远端

先保证 WSL 代理只连接固定远端，不再直接连接任意目标，然后在 PowerShell 中运行
（权限不足时会自动弹出 UAC）：

```powershell
.\tun2proxy-bin.exe `
  --setup `
  --proxy "http://127.0.0.1:11111" `
  --dns virtual `
  --bypass "203.0.113.10/32"
```

### Windows 本机动态分流代理

```powershell
.\tun2proxy-bin.exe `
  --setup `
  --proxy "socks5://127.0.0.1:1080" `
  --dns virtual `
  --bypass-process "local-proxy.exe" `
  --bind-interface "WLAN"
```

`--bind-interface` 可以省略；只有自动检测选错真实出口网卡时才需要指定。

## 7. 验证和退出

启动时可以增加日志级别：

```text
--verbosity debug
```

Windows 可以检查 TUN 适配器和路由：

```powershell
Get-NetAdapter | Where-Object InterfaceDescription -Match "wintun"
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric
```

Linux 可以检查：

```bash
ip address
ip route
```

然后使用 `curl https://example.com` 或浏览器验证出口地址。需要验证 UDP 时，应使用
实际依赖 UDP 的测试程序，并同时观察 tun2proxy 的 debug 日志是否建立了 UDP 会话。

正常情况下按 `Ctrl+C` 退出。`--setup` 创建的路由配置会在程序正常退出时自动恢复。

## 8. 故障排查

### 启动后立即断网

最常见原因是本地代理的出站流量被再次捕获。检查真实远端 IP 是否已加入
`--bypass`，或者本机代理进程是否正确加入 `--bypass-process`。

### HTTP 可以访问，游戏或 QUIC 不工作

HTTP 上游不支持通用 UDP。改用支持 `UDP ASSOCIATE` 的 SOCKS5 服务，或部署 UdpGW。

### SOCKS5 TCP 正常但 UDP 不工作

确认服务端实现了 `UDP ASSOCIATE`，防火墙允许 UDP Relay 端口，并检查服务端返回的
Relay IP 是否可以从本机访问。如果 Relay IP 与控制连接 IP 不同，还需要为它配置
不会形成循环的出口路径。

### WSL 代理使用 `--bypass-process` 仍然循环

Windows 侧无法可靠匹配 WSL Linux 进程。改为固定上游 IP 加 `--bypass`，或者把代理
进程移动到 Windows 本机运行。
