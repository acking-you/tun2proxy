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

开始透明接管前，建议先退出其他全局 TUN/VPN 软件。同一台 Windows 机器上同时存在
多个低 metric 默认路由时，最终由 Windows 路由选择决定流量进入哪个设备；“适配器已
创建”并不等于“流量已进入 tun2proxy”。本地代理端口也必须先监听成功，再启用 TUN。

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

### 2.4 Windows 安全路由

Windows 可能同时保存 Wi-Fi、以太网、Hyper-V、WSL 和其他 VPN 的多条默认路由。
当前 Windows `--setup` 使用 IP Helper API 精确创建两条 `/1` TUN 捕获路由和绕过
路由；状态中记录本次实际创建的路由，启动失败时按相反顺序回滚，停止时也只删除这些
路由。它不会为了恢复网络而删除系统的全部默认路由再猜测性地重建一条。TUN 接口的
原 DNS 设置也会在修改前保存，并在停止或启动失败时恢复。

转发循环创建的 TCP、UDP、UdpGW 心跳和 Linux socket-transfer 后台任务现在由同一个
任务集合管理。正常停止或热切换时会先取消并回收旧任务，再进入路由与 DNS 清理，
避免旧连接在新 TUN 启动后继续后台运行。

尤其不要手工使用下面这种不带网关或接口限定的清理方式：

```powershell
# 危险示例：可能删除机器上的全部 IPv4 默认路由，请勿执行
route.exe delete 0.0.0.0 mask 0.0.0.0
```

安全路由还需要遵守以下使用边界：

- 创建 TUN 路由前先确定真实出口接口、网关和接口索引；不要在 TUN 默认路由生效后
  再次把“当前默认接口”误判成 Wintun。
- 保留系统原有默认路由。通过更具体的路由或 metric 让流量进入 TUN，而不是先删除
  物理网卡默认路由。
- 代理服务器和显式 `--bypass` 路由必须同时关联原网关与原接口。仅记录网关 IP 在
  多网卡、同名网关或 VPN 场景下并不足够。
- Windows 使用两条 `/1` 路由接管 IPv4，因此会拒绝无法可靠压过捕获路由的 `/0`
  或 `/1` bypass；请提供更具体的网段。这样会明确报错，而不是显示启动成功后仍代理。
- 切换 Wi-Fi、插拔网线、休眠唤醒或 VPN 上下线后，真实出口可能变化。在出口监控与
  自动重绑定完整生效前，应停止并重新开启 TUN，而不是继续沿用旧网关。

当前安全路由主要解决路由所有权和事务回滚，还不等同于 Mihomo 的完整
`strict-route`：项目尚未通过 WFP 阻止所有非 TUN DNS、IPv6 或其他旁路流量。需要
严格防泄漏时，应关闭不使用的 IPv6、避免并行 VPN，并通过抓包或路由检查实际出口。

Windows 上的 `--ipv6-enabled` 目前只启用 userspace IPv6 处理；自动 `--setup` 尚未
安装 IPv6 捕获路由。需要代理 IPv6 时必须另行配置路由并验证出口，否则应在物理网卡
上禁用 IPv6，避免 IPv6 绕过 TUN。Linux/macOS 的路由行为不受此限制。

可在启用前后分别记录路由，确认物理默认路由仍然存在：

```powershell
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 |
  Where-Object DestinationPrefix -eq "0.0.0.0/0" |
  Sort-Object RouteMetric, InterfaceMetric |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
```

不要通过强制结束进程测试清理。应在原终端按 `Ctrl+C`，等待日志确认 TUN 和系统配置
已恢复后再关闭终端。进程崩溃、系统掉电或被任务管理器强制结束时，不可能保证用户态
清理代码得到执行。

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

`198.18.0.0/15` 是专门保留的基准测试地址段，不是目标网站的真实公网地址。看到
`example.com -> 198.18.x.x` 并不表示 DNS 出错；它表示 DNS 控制面已经进入 virtual
DNS。随后到该 Fake IP 的 TCP/UDP 数据也必须进入同一个 tun2proxy 实例，才能根据
映射恢复域名。DNS 查询被接管、业务数据却绕过 TUN 时，就会出现“能够解析但连接
超时”。

Fake IP 映射保存在当前 tun2proxy 进程内，不应持久化给其他实例使用。重启 TUN 后，
应用或系统 DNS 缓存里残留的旧 Fake IP 可能已没有对应映射；遇到这种情况应重新解析
域名，Windows 上还可以执行：

```powershell
ipconfig.exe /flushdns
```

其他策略：

- `--dns over-tcp`：把 DNS 请求转换为 TCP，并通过代理发送到 `--dns-addr`。
- `--dns direct`：保留普通 DNS 流程，要求当前代理路径能够处理对应的 UDP；HTTP
  上游通常不适合使用此选项。

三种策略的关键差异如下：

| 策略 | 返回给应用的地址 | 域名在哪里解析 | 主要限制 |
| --- | --- | --- | --- |
| `virtual` | `198.18.0.0/15` 中的 Fake IP | 最终交给代理路径 | DNS 与业务流量必须进入同一实例 |
| `over-tcp` | 上游 DNS 返回的真实地址 | `--dns-addr` 指定的 DNS | DNS 可走 TCP，但后续连接仍受上游协议能力限制 |
| `direct` | 本地 DNS 返回的真实地址 | 系统配置的 DNS | 可能绕过代理或泄漏 DNS；HTTP 上游不能承载普通 UDP DNS |

HTTP `CONNECT` 还有一个容易混淆的现象：使用显式 HTTP 代理访问 HTTPS 时，客户端通常
直接向代理发送 `CONNECT example.com:443`，无需先在本机解析目标域名。因此显式 HTTP
代理能够访问，并不能证明 TUN 的 DNS 或数据路由正常。

## 6. Windows 与 WSL2

### 6.1 推荐使用 NAT 模式

WSL2 默认使用 NAT 网络。Windows 上运行 tun2proxy 时，NAT 模式通常也是最稳定的
透明接管方式：

```text
WSL 应用 -> WSL NAT -> Windows 网络栈 -> Wintun -> tun2proxy -> 本地代理
```

在此模式下，一般只需要在 Windows 创建 TUN，不需要在 WSL 内再创建设备。若曾经在
`%UserProfile%\.wslconfig` 中启用 Mirrored，可改为：

```ini
[wsl2]
networkingMode=NAT
```

配置只在 WSL 虚拟机重启后生效。下面的命令会结束所有发行版及其中正在运行的任务，
请先保存工作：

```powershell
wsl.exe --shutdown
```

Windows 设置会保留物理网卡原有的默认路由，同时创建两条 `/1` 捕获路由和一条仅由
当前 TUN 会话拥有的 `0.0.0.0/0` 兼容路由。后者用于让 WSL HNS NAT 等转发组件无论在
TUN 启动前还是启动后初始化，都能把 Wintun 识别为当前默认出口；正常退出时只删除这
条会话自己创建的精确路由，不会删除或重写物理、WSL 或其他 VPN 的默认路由。

启动事务还会通过 IP Helper API 记录 Wintun 和 WSL HNS `vEthernet` 的 IPv4 接口状态，
为两端启用转发，并仅在 Wintun 上启用 weak-host send/receive，使 HNS NAT 转换后的地址
即使属于其他接口也能进入和返回 TUN。后台监视器会处理 TUN 启动后新建或替换的 WSL
接口。正常退出和启动失败回滚都只恢复本会话实际修改过的字段，不会永久开启系统级路由。

透明 TUN 模式下，WSL 不应再依赖 `HTTP_PROXY`、`HTTPS_PROXY` 或桌面代理自动注入，
否则测试结果只能证明显式代理可用，还可能形成双重代理。可以这样检查：

```bash
env | grep -i proxy
curl --noproxy '*' --connect-timeout 10 https://www.google.com/
curl --noproxy '*' --connect-timeout 10 https://api.openai.com/
```

第二个请求返回 `401` 也代表网络与 TLS 已经连通，只是没有提供 API 凭据。

### 6.2 Mirrored 模式的限制

Mirrored 模式不保证 WSL 的业务流量一定重新经过 Windows 默认路由。常见的不对称
路径是：

```text
DNS：WSL -> Windows DNS tunneling -> tun2proxy virtual DNS -> 198.18.x.x
TCP：WSL -> Linux eth0/物理网关 -> 198.18.x.x -> 超时
```

也就是说，WSL 可以通过宿主 DNS 转发拿到 Fake IP，但其 Linux 路由表仍可能把后续
数据直接发往物理网关。DNS 控制面和 TCP/UDP 数据面是两条独立路径，这两个现象并不
矛盾。

必须保留 Mirrored 时，可以选择显式 HTTP/SOCKS5h 代理，或在 WSL 内单独部署 Linux
TUN；前者不属于透明接管，并且 HTTP 只能代理 TCP。不要直接把 WSL 默认路由指向
Windows Wintun 的 `10.0.0.x` 地址：Wintun 是三层设备，镜像接口未必具备可用的邻居、
转发和回程配置，这样很容易让 WSL 完全断网。

## 7. 常见完整示例

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

## 8. 验证和退出

启动时可以增加日志级别：

```text
--verbosity debug
```

Windows 可以检查 TUN 适配器和路由：

```powershell
Get-NetAdapter | Where-Object InterfaceDescription -Match "wintun"
Get-NetRoute -AddressFamily IPv4 | Sort-Object RouteMetric
```

同时比较显式代理与透明路径，能够快速区分“本地代理故障”和“TUN 路由故障”：

```powershell
# 只验证本地代理
curl.exe --proxy "http://127.0.0.1:8080" --connect-timeout 10 https://example.com/

# 强制不读取环境代理，验证透明 TUN
curl.exe --noproxy "*" --connect-timeout 10 https://example.com/

# 查看域名是否处于 virtual DNS/Fake-IP 模式
Resolve-DnsName example.com -Type A
```

Linux 可以检查：

```bash
ip address
ip route
```

然后使用 `curl https://example.com` 或浏览器验证出口地址。需要验证 UDP 时，应使用
实际依赖 UDP 的测试程序，并同时观察 tun2proxy 的 debug 日志是否建立了 UDP 会话。

正常情况下按 `Ctrl+C` 退出。`--setup` 创建的路由配置会在程序正常退出时自动恢复。

## 9. 故障排查

### 启动后立即断网

最常见原因是本地代理的出站流量被再次捕获。检查真实远端 IP 是否已加入
`--bypass`，或者本机代理进程是否正确加入 `--bypass-process`。

还应确认没有第二个 TUN/VPN 抢占默认路由，并比较 TUN 启用前后的默认路由列表。
如果本地代理测试成功，而 `--noproxy "*"` 的测试失败，问题位于 TUN 路由、DNS 或
回环排除，而不是远端代理账号。

### 网站偶尔可用，但换网站很慢或频繁 reset

依次检查：

1. 本地代理进程或其真实服务器是否被 TUN 再次捕获。回环通常表现为大量重复连接、
   reset 或超时，而不是稳定报一次连接失败。
2. HTTP 上游无法代理 QUIC/UDP。浏览器可能先等待 QUIC 失败再退回 TCP，因此看起来
   每个新网站都要等待很久。可以临时关闭浏览器 QUIC，或换用真正支持 UDP 的 SOCKS5。
3. MTU 是否过大。小响应正常、较大 TLS/HTTP 响应卡住时，尝试逐步降低 `--mtu`，
   并检查物理链路或上游隧道是否还附加了额外封装。
4. IPv4 与 IPv6 是否只有一条路径可用。未启用 `--ipv6-enabled` 时，先用 `curl.exe -4`
   对照；不要让不可用的 IPv6 连接一直等待后才回退 IPv4。
5. 是否残留旧 Fake IP。刷新 DNS 缓存并让应用重新建立连接。

### HTTP 可以访问，游戏或 QUIC 不工作

HTTP 上游不支持通用 UDP。改用支持 `UDP ASSOCIATE` 的 SOCKS5 服务，或部署 UdpGW。
UDP 失败不会自动“回退成 HTTP TCP”；只有应用自身支持回退时，例如浏览器从 QUIC
回退到 HTTPS/TCP，才会继续工作。

### SOCKS5 TCP 正常但 UDP 不工作

确认服务端实现了 `UDP ASSOCIATE`，防火墙允许 UDP Relay 端口，并检查服务端返回的
Relay IP 是否可以从本机访问。如果 Relay IP 与控制连接 IP 不同，还需要为它配置
不会形成循环的出口路径。

服务端拒绝 `UDP ASSOCIATE` 时，tun2proxy 也不会把该数据报自动转换为 SOCKS5
`CONNECT`。只启用 SOCKS5 TCP 与使用 HTTP 上游对通用 UDP 的效果相同：UDP 会失败，
但 TCP 仍可正常代理。

### WSL 代理使用 `--bypass-process` 仍然循环

Windows 侧无法可靠匹配 WSL Linux 进程。改为固定上游 IP 加 `--bypass`，或者把代理
进程移动到 Windows 本机运行。

### WSL 能解析 Fake IP，但 curl 或 Codex 超时

先强制忽略环境代理并查看实际路由：

```bash
env | grep -i proxy
getent ahostsv4 api.openai.com
ip route
curl --noproxy '*' --connect-timeout 10 -v https://api.openai.com/
```

如果域名得到 `198.18.x.x`，但路由从 WSL 的物理 `eth0` 发出，说明只有 DNS 进入了
Windows，数据面没有进入 Wintun。优先切换回 WSL NAT 模式并执行 `wsl.exe --shutdown`；
显式设置 HTTP 代理只能绕过这个问题，不能证明透明 TUN 已修复。

### 异常退出后怀疑路由残留

不要先执行宽泛的 `route delete`。先退出残留的 tun2proxy 实例，再检查默认路由：

```powershell
Get-Process tun2proxy-bin -ErrorAction SilentlyContinue
Get-NetRoute -AddressFamily IPv4 |
  Where-Object DestinationPrefix -eq "0.0.0.0/0" |
  Format-Table ifIndex, InterfaceAlias, NextHop, RouteMetric, InterfaceMetric
Get-NetIPConfiguration
```

物理网卡没有默认网关时，可先禁用再启用该网卡，或通过 DHCP 重新获取配置。只有在
确认某条路由确实由本次 TUN 创建，并且明确知道其 `ifIndex`、`NextHop` 和前缀时，才
应精确删除它。最后执行 `ipconfig.exe /flushdns` 清除旧 Fake IP。

### 更新进程 bypass 后旧连接仍然异常

按进程匹配发生在新会话建立时。已经存在的 TCP 连接和 UDP 会话不会在中途改变出口；
修改 bypass 列表后需要让目标应用断开并重新连接。验证时同时观察日志中的 PID、进程
名和“bypassing”记录，避免只根据任务管理器里的显示名称判断实际可执行文件名。
