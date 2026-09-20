# lnproxy

[English](README.md) | 简体中文

`lnproxy` 是一个跨平台的局域网 TCP 代理工具，围绕三种角色设计：

- **C（Client，客户端）**：在无法直接访问外网的机器上运行 `lnproxy-client`。它提供仅监听回环地址的 HTTP 代理（可选 SOCKS5），连接 S 完成认证，并自动设置当前用户的系统代理。
- **S（Server，服务端）**：在可被局域网访问且具有外网出口的机器上运行 `lnproxy-node server`。S 是控制平面中心，维护出口目录，也可以直接代理流量。
- **E（Exit，出口）**：在具有外网出口、但没有可被访问入站地址的机器上运行 `lnproxy-node exit`。E 只主动连接 S，不开放入站代理端口，并代表 C 拨号访问目标地址。

`lnproxy-node server-exit` 将 S 和直接出口功能合并在一个进程中。

> **当前状态：** v1 仅支持 TCP。UDP、TUN/透明代理、公网会合服务以及 C 到 E 的端到端加密尚未实现。

## 架构

```text
 应用程序
      |
      v
 系统 HTTP 代理 / 可选 SOCKS5
      |
      v
 lnproxy-client (C)
      |
      | TLS 1.3 over QUIC（优先）或 TCP
      v
 lnproxy-node server (S)
      |
      +--> 直接访问目标（S/直接出口）
      |
      +--> 反向隧道到 E --> 目标
```

S 终止经过认证的 C 和 E 会话。E 不监听入站代理流量。目标域名由 S 或 E 在拨号时解析；C 不会在转发前解析目标地址。

## 功能特性

- 一个 Go 模块构建以下可执行文件：
  - `lnproxy-client`：C 客户端。
  - `lnproxy-node`：S、E 或 S/E 节点。
  - `lnproxy-init.exe`：用于 S、E 或 S/E 节点的一次性初始化工具。
  - `lnproxy-windows-server.exe`：无参数、GUI 子系统的 Windows S/E 静默服务端。
  - `lnproxy-probe`：用于受控诊断 C 到 S 数据路径的控制台工具。
- TLS 1.3 加密，优先使用 QUIC，QUIC 不可用时回退到 TLS over TCP。
- 协议 v2 增加 QUIC 控制流就绪握手，避免对端流可见性死锁。
- 带帧的复用会话协议，支持独立请求 ID、有界流缓冲、取消、半关闭和空闲处理。
- 每个部署使用一个共享口令。
- S 存储 Argon2id 盐值和哈希；原始口令不会通过网络发送。
- 在加密会话内执行基于随机数的挑战响应认证。
- 认证失败限速。
- C 和 E 均使用首次信任（TOFU）方式验证证书指纹。
- C 和 E 均支持固定 S 证书指纹，以便无人值守启动。
- 支持 HTTP CONNECT 和普通 HTTP 代理。
- 可选的仅回环 SOCKS5 `CONNECT` 监听器。
- 出口目录包含 ID、名称、类型、健康状态、延迟、负载、容量、特性和心跳时间。
- S/S-E 的本地直接出口永久保留；心跳过期仅作用于远端 E 条目。
- 根据健康状态、可用容量和延迟自动选择出口。
- 支持显式指定出口，并可配置不可用时回退。
- E 定期发送心跳，S 自动移除过期出口。
- 当前用户系统代理集成：
  - Windows WinINet 注册表；
  - Linux GNOME GSettings；
  - Linux KDE/KIO。
- 系统代理日志支持崩溃恢复，并仅在当前值匹配时恢复。
- 节点进程支持轮转 JSON 日志。
- 支持 `quit`、EOF、Ctrl-C、SIGINT 和 SIGTERM 优雅退出。

## 仓库结构

```text
cmd/lnproxy-client/       C 可执行文件
cmd/lnproxy-init/         独立节点初始化工具
cmd/lnproxy-node/         S/E 可执行文件
cmd/lnproxy-windows-server/ GUI 子系统的 Windows S/E 可执行文件
cmd/lnproxy-probe/        不启动本地代理、不修改系统设置的 C 路径诊断工具
internal/auth/            Argon2id、挑战响应、限速
internal/client/          客户端管理、运行期、代理生命周期、命令交互
internal/config/          节点配置和证书生成
internal/initnode/        共享节点初始化操作
internal/logging/         轮转结构化日志
internal/node/            服务端、出口、注册表、目标拨号
internal/silentserver/    静默 Windows 服务端的已初始化配置包加载器
internal/protocol/        帧格式、目录、请求和控制消息
internal/proxy/           公共代理转发辅助代码
internal/proxy/httpconnect HTTP 和 CONNECT 代理
internal/proxy/socks5     SOCKS5 代理
internal/session/         复用流/会话层
internal/systemproxy/     Windows/Linux 系统代理适配器
internal/transport/       QUIC/TLS 传输和已知主机存储
integration/e2e_test.go   C 到 S 以及 C 到 S 到 E 的集成测试
```

## 环境要求

- 从源码构建需要 Go 1.26 或更高版本。
- Linux 桌面系统代理集成需要：
  - 使用 `gsettings` 的 GNOME；或
  - 使用 `kwriteconfig6`/`kwriteconfig5` 和 `kreadconfig6`/`kreadconfig5` 的 KDE。
- Linux 无桌面环境或不受支持的桌面环境不会修改系统代理，并会记录相应限制。
- S 默认监听端口为 `443`。

主要依赖为 `quic-go`、`x/crypto` 和 `x/term`。

协议版本 2 使用 ALPN `lnproxy/2`。S、C 和所有 E 必须同时升级到 v2；v1 与 v2 节点故意不兼容。

## 构建

如果仓库没有有效的 VCS 元数据，请使用 `-buildvcs=false`。

### Linux

```bash
go build -buildvcs=false -o lnproxy-client ./cmd/lnproxy-client
go build -buildvcs=false -o lnproxy-node ./cmd/lnproxy-node
go build -buildvcs=false -o lnproxy-probe ./cmd/lnproxy-probe
```

### 交叉编译 Windows

```bash
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-client.exe ./cmd/lnproxy-client
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-init.exe ./cmd/lnproxy-init
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-node.exe ./cmd/lnproxy-node
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-probe.exe ./cmd/lnproxy-probe
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags=-H=windowsgui -o lnproxy-windows-server.exe ./cmd/lnproxy-windows-server
```

构建 `lnproxy-windows-server.exe` 时必须使用 `-H=windowsgui`。该参数生成 GUI 子系统的 PE 文件，使 Windows 启动进程时不创建控制台窗口。该命令仅用于 Windows；源码中提供了非 Windows 回退入口，因此整个仓库仍可在其他平台构建和测试。

### 测试和竞态检查

```bash
go test ./...
go test -race ./integration ./internal/node ./internal/proxy/httpconnect
go vet ./...
```

完整集成测试会绑定回环套接字。如果运行环境限制创建套接字，需要为该操作授权。

## CI 和发布

GitHub Actions 会在每个拉取请求上运行 `verify`：执行 `go test ./...`、`go vet ./...`、构建所有包，并编译 Linux 和 Windows amd64 可执行文件。合并到 `main` 前必须通过 `verify` 检查。

推送到 `main` 后，系统根据 Conventional Commits 计算下一个 SemVer 标签。首个版本为 `v1.0.0`；`fix:` 增加补丁版本，`feat:` 增加次版本，`!` 或 `BREAKING CHANGE:` 页脚增加主版本。仅包含 `docs:`、`ci:`、`chore:` 等不可发布提交的推送仍会执行验证，但不会创建发布。

创建发布时，GitHub 会附带带版本号的 Linux 和 Windows 二进制文件，例如 `lnproxy-node-v1.0.0` 和 `lnproxy-node-v1.0.0.exe`。合并压缩包名为 `lnproxy-v1.0.0-amd64.zip`；`README.md` 和 `README.zh-CN.md` 保持固定资源名称，但文件内 H1 标题会写入发布版本。可以手动运行 `Release` 工作流的 `workflow_dispatch` 重试发布。生成的 `dist/` 输出不会提交到 Git。

## 快速开始

以下示例假设 C 和 E 都可以访问地址 `192.0.2.10`。

### 1. 初始化并启动 S

```bash
./lnproxy-node server --init
./lnproxy-node server
```

首次启动 E 时，可以让 E 询问并保存 SHA-256 指纹，也可以在启动前从 `server.crt` 计算指纹并显式配置。

### 2. 启动 E

```bash
export LNPROXY_PASSPHRASE='替换为 S 的共享口令'

./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --exit-id edge-1
```

### 3. 启动 C

```bash
./lnproxy-client --socks5
```

然后连接：

```text
> connect 192.0.2.10
Please input password:
Authentication success!
HTTP proxy listening on 127.0.0.1:...
SOCKS5 proxy listening on 127.0.0.1:...
>
```

使用 `exits` 查看可用出口，使用 `use <exit-id>` 覆盖自动选择。

## 初始化 S

第一次使用前，在 S 机器上运行：

```bash
./lnproxy-node server --init
```

独立初始化工具要求将角色作为第一个参数。对于 S-E 节点：

```bash
./lnproxy-init server-exit
```

原有的 `lnproxy-node` 角色初始化形式继续保留，并支持相同的初始化参数：

```bash
./lnproxy-node server-exit --init
```

`lnproxy-init` 必须显式指定角色，不支持省略角色的初始化语法。可用角色为 `server`、`exit` 和 `server-exit`。

初始化过程会：

1. 创建数据目录。
2. 以隐藏输入方式两次提示输入共享口令。
3. 将 Argon2id 盐值、哈希和参数写入 `passphrase.json`。
4. 生成自签名 TLS 证书和私钥。
5. 写入 `node.json`。

默认数据目录为平台用户配置目录下的 `lnproxy`：

- Linux：通常为 `~/.config/lnproxy`。
- Windows：通常为 `%AppData%\\lnproxy`。

可以指定数据目录和配置文件路径：

```bash
./lnproxy-node server \
  --init \
  --data-dir /var/lib/lnproxy \
  --config /etc/lnproxy/server.json
```

如果验证器文件已经存在，初始化会拒绝覆盖。

`server-exit` 的初始化方式相同：

```bash
./lnproxy-node server-exit --init
```

`exit` 也会在初始化时创建验证器文件，但不会生成服务端证书；E 使用首次信任保存的 S 证书指纹或显式配置的指纹，并通过已配置的口令来源完成认证。

省略 `--config` 时，节点不会自动发现 `node.json`。如果配置文件不在进程默认数据目录中，运行时应始终传入初始化时使用的同一个 `--config` 路径。

## 运行 S

```bash
./lnproxy-node server
```

也可以在命令行中覆盖设置：

```bash
./lnproxy-node server \
  --config /etc/lnproxy/server.json \
  --listen 0.0.0.0:443
```

`server` 和 `server-exit` 会在同一个地址和端口上同时监听：

- UDP：QUIC；
- TCP：TLS 回退。

如果希望 S 同时作为直接出口：

```bash
./lnproxy-node server-exit --config /etc/lnproxy/server-exit.json
```

### S 日志

- Linux 默认将 JSON 日志输出到 stderr。
- Windows 服务端模式默认静默运行。
- 日志同时写入 `<数据目录>/lnproxy.log`。
- 日志文件约 5 MiB 轮转一次，并保留三个历史文件。
- Windows 诊断时可使用 `--console` 或设置 `"console": true`。

> 普通 `lnproxy-node.exe` 是控制台子系统程序，并支持诊断控制台参数。`lnproxy-windows-server.exe` 是下文所述的专用 GUI 子系统静默服务端。事件日志集成尚未实现。

### Windows S-E 静默服务端

`lnproxy-windows-server.exe` 是面向已初始化 S-E 节点的 Windows 专用构建目标。它没有 GUI、控制台、提示符、弹窗或命令行界面。包括 `--init` 在内的所有参数都会被忽略；该程序只负责运行现有配置包。

使用 GUI 链接参数构建：

```bash
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags=-H=windowsgui -o lnproxy-windows-server.exe ./cmd/lnproxy-windows-server
```

静默服务端始终从以下目录读取配置包：

```text
%AppData%\lnproxy
```

该目录必须包含全部四个已初始化文件：

```text
node.json
passphrase.json
server.crt
server.key
```

可以在目标机器上运行 `lnproxy-init.exe server-exit` 或普通节点程序进行初始化，也可以从已初始化的 Windows S-E 部署中复制全部四个文件。复制配置包时，静默服务端会把 `data_directory`、`certificate_file`、`key_file` 和 `verifier_file` 重定位到当前用户的 `%AppData%\lnproxy`，因此配置不依赖源机器的用户名或绝对路径。传输过程中应妥善保护 `server.key` 和 `passphrase.json`。

加载后角色始终强制为 `server-exit`，`console` 始终强制为 `false`。其余配置字段会保留，包括监听地址、连接数限制、空闲超时、容量、出口名称和出口 ID。

成功启动后不会显示任何窗口。诊断信息仅写入以下轮转 JSON 文件：

```text
%AppData%\lnproxy\lnproxy.log
```

日志文件约 5 MiB 轮转一次，并保留三个历史文件。如果 `node.json` 或任一必需配置包文件缺失或无效，进程会将错误写入日志并以非零状态退出，绝不会尝试自动初始化。

静默可执行文件是后台进程，不是 Windows 服务。如果需要开机启动，请使用任务计划程序、启动快捷方式或其他外部进程管理器。

## 运行 E

E 需要知道如何连接 S，并完成认证。建议无人值守运行时从环境变量或受保护文件读取口令：

```bash
export LNPROXY_PASSPHRASE='共享部署口令'

./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --exit-id edge-1 \
  --capacity 128
```

或使用受保护文件：

```bash
chmod 600 /etc/lnproxy/passphrase
./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase file:/etc/lnproxy/passphrase
```

交互式 `prompt` 适合初始化和控制台调试，但无人值守 E 应使用 `env:` 或 `file:`。

未提供 `--fingerprint` 的首次连接中，E 使用与 C 相同的 TOFU 流程：显示 S 证书指纹并询问 `Trust this server? [y/N]`。接受后，E 将指纹保存到 `<data_directory>/known-hosts.json`，后续启动直接复用；指纹发生变化时会拒绝连接。无人值守运行时，应配置 `--fingerprint`，或先以交互方式运行一次 E 写入信任记录；两者都没有时，启动会带提示直接失败，不会自动信任。

E 不开放入站监听器。它会主动连接 S、注册自身、每 10 秒发送心跳，并通过控制会话接收新的流请求，然后拨号目标地址并转发 TCP 数据。

如果连接 S 中断，E 会使用指数退避重试，最大间隔约为 30 秒。

## 运行 C

启动前台客户端：

```bash
./lnproxy-client
```

在提示符中执行：

```text
> connect 192.0.2.10
Please input password:
Authentication success!
HTTP proxy listening on 127.0.0.1:...
>
```

如果地址没有指定端口，默认使用 `443`：

```text
> connect 192.0.2.10:8443
```

启动时启用 SOCKS5：

```bash
./lnproxy-client --socks5
```

### TOFU 行为

C 和 E 在未配置显式指纹时，首次连接都会显示 S 证书的 SHA-256 指纹，并询问：

```text
Trust this server? [y/N]
```

对于 C，确认后指纹会保存到：

```text
<用户配置目录>/lnproxy/known-hosts.json
```

对于 E，指纹会保存到 `<data_directory>/known-hosts.json`。以后如果证书指纹发生变化，连接会被拒绝。只有在独立验证新的 S 证书后，才应删除或修改已知主机记录。

### 客户端命令

| 命令 | 说明 |
| --- | --- |
| `connect <S IP>` | 连接 S、完成认证、启动本地监听并应用系统代理。 |
| `status` | 显示连接状态、传输方式、当前出口和本地监听地址。 |
| `exits` | 显示 S 当前维护的出口目录。 |
| `use <exit-id>` | 为新连接指定出口。 |
| `use auto` | 恢复自动选择。 |
| `use <exit-id> true` | 指定出口，不可用时回退到自动选择。 |
| `reconnect` | 关闭当前 S 会话并重新连接。 |
| `disconnect` | 断开当前 S 会话。 |
| `help` | 显示命令帮助。 |
| `quit` | 优雅关闭并退出。 |

显式出口选择只影响新连接，已有连接不会迁移。

客户端会在随机回环端口启动 HTTP 代理。如果传入 `--socks5`，还会在另一个随机回环端口启动 SOCKS5 监听器。

客户端没有服务端/配置档案文件。它只会在用户数据目录下保存证书信任和系统代理恢复所需的状态。

### 客户端退出

以下操作会触发优雅退出：

- `quit`
- EOF
- Ctrl-C
- SIGINT
- SIGTERM

退出流程：

1. 停止接受新的本地代理请求。
2. 拒绝新流。
3. 在 `--drain-timeout` 时间内等待已有流结束。
4. 关闭 S 会话。
5. 如果当前系统代理解仍与本进程应用的值一致，则恢复原始设置。
6. 仅在恢复成功后删除日志。

默认等待时间为 10 秒：

```bash
./lnproxy-client --drain-timeout 30s
```

## 诊断客户端故障

`lnproxy-probe` 使用与 C 相同的连接、TLS 验证、认证、会话和流协议，但不会启动本地代理、修改系统设置或保存证书指纹。当 `lnproxy-client` 卡住、在认证后退出，或始终没有输出 `Authentication success!` 时，可以使用它定位故障阶段。

可以在目标平台构建，也可以直接复制发布包中对应的程序：

```bash
go build -buildvcs=false -o lnproxy-probe ./cmd/lnproxy-probe
```

以下命令通过 S/直接出口完整检查 S 上监听 8080 端口的 HTTP 服务：

```bash
./lnproxy-probe \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --transport tcp \
  --target 127.0.0.1:8080 \
  --http-path /
```

未提供 `--fingerprint` 时，程序会先要求输入口令，再显示证书指纹确认提示。提供 `--fingerprint` 可以跳过两个交互提示；该值只保存在内存中，不会写入 `known-hosts.json`。

典型输出如下：

```text
[    0.000s] config: server=192.0.2.10:443 transport=tcp session_mode=safe target=127.0.0.1:8080
[    0.012s] transport: TCP/TLS dial
[    0.024s] tls: verified fingerprint=AA:BB:CC:...
[    0.025s] auth: challenge and Argon2id
[    0.048s] auth: ok duration=23ms heap_total_delta=1.12MiB sys=...
[    0.049s] session: starting (safe mode)
[    0.050s] catalog: waiting
[    0.051s] catalog: 1 exit(s)
[    0.051s] stream: opening 127.0.0.1:8080 via auto
[    0.052s] stream: opened
[    0.054s] http: status=200 bytes=...
[    0.054s] transport: tls
[    0.054s] PASS
```

可使用以下命令分别隔离故障：

```bash
# 仅测试 TCP 和安全的启动顺序。
./lnproxy-probe --server HOST --transport tcp --session-mode safe \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080

# 仅测试 QUIC。
./lnproxy-probe --server HOST --transport quic --session-mode safe \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080

# 使用与当前 Windows 客户端相同的已修复会话启动顺序。
./lnproxy-probe --server HOST --transport tcp --session-mode client \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080
```

`--transport auto` 会先尝试 QUIC；只有 QUIC 拨号失败时才回退到 TCP。如果 QUIC 已连接但无法打开控制流，程序会明确报告 `QUIC control stream`，不会用 TCP 回退掩盖该故障。

故障判断表：

| 现象 | 含义 |
| --- | --- |
| 在 `auth` 之前失败 | DNS、路由、TCP/UDP、防火墙、TLS 或证书指纹问题。 |
| `auth` 超时或异常缓慢 | Argon2id 对该客户端开销过高；检查 S 验证器参数和可用内存。 |
| `catalog` 成功但 `stream open` 失败 | 没有可用出口、流被拒绝，或 S/E 路由失败。 |
| `stream open` 成功但 HTTP 超时 | S/E 无法访问目标 `127.0.0.1:8080`，或该服务没有提供 HTTP。 |
| TCP 成功但 QUIC 失败 | 路径上的 QUIC/UDP 被阻断或异常；诊断时可先使用 TCP。 |
| 所有阶段通过 | 协议和服务端路径正常；剩余问题位于 Windows 客户端、系统代理、安全软件或进程生命周期。 |

退出码：成功为 `0`，网络阶段超时为 `2`，其他失败为 `1`。

## 配置文件

`lnproxy-node` 支持 `--config <路径>`。配置文件为 JSON；加载后，部分命令行参数可以覆盖对应字段。

服务端配置示例：

```json
{
  "role": "server",
  "listen_address": ":443",
  "data_directory": "/var/lib/lnproxy",
  "certificate_file": "/var/lib/lnproxy/server.crt",
  "key_file": "/var/lib/lnproxy/server.key",
  "verifier_file": "/var/lib/lnproxy/passphrase.json",
  "passphrase_source": "prompt",
  "connection_limit": 256,
  "idle_timeout": 300000000000,
  "exit_name": "server",
  "exit_id": "direct",
  "capacity": 128,
  "console": false
}
```

`idle_timeout` 使用 Go `time.Duration` 的纳秒值。`300000000000` 表示 5 分钟。

出口配置示例：

```json
{
  "role": "exit",
  "data_directory": "/var/lib/lnproxy",
  "certificate_file": "/var/lib/lnproxy/server.crt",
  "key_file": "/var/lib/lnproxy/server.key",
  "verifier_file": "/var/lib/lnproxy/passphrase.json",
  "server_address": "192.0.2.10:443",
  "server_fingerprint": "AA:BB:CC:...",
  "passphrase_source": "env:LNPROXY_PASSPHRASE",
  "connection_limit": 256,
  "idle_timeout": 300000000000,
  "exit_name": "edge-1",
  "exit_id": "edge-1",
  "capacity": 128,
  "console": false
}
```

### 节点参数

| 参数 | 含义 |
| --- | --- |
| `--init` | 位于节点角色参数之后时，初始化指定角色。 |
| `--config PATH` | 加载 JSON 节点配置。 |
| `--data-dir PATH` | 覆盖数据目录。 |
| `--listen ADDRESS` | 覆盖 S/S-E 监听地址。 |
| `--server ADDRESS` | 设置 E 使用的 S 地址。 |
| `--fingerprint VALUE` | 将 E 的 S 证书 SHA-256 指纹设为硬固定值，并跳过 TOFU。 |
| `--passphrase SOURCE` | 口令来源：`prompt`、`env:NAME` 或 `file:PATH`。 |
| `--console` | 在 Windows 上强制输出控制台日志。 |
| `--capacity N` | E 声明的最大并发流数量。 |
| `--idle-timeout DURATION` | 流/会话空闲超时时间。 |

### 客户端参数

| 参数 | 含义 |
| --- | --- |
| `--socks5` | 启用可选 SOCKS5 监听器。 |
| `--drain-timeout DURATION` | 限制优雅排空时间，默认 `10s`。 |

### 诊断工具参数

| 参数 | 含义 |
| --- | --- |
| `--server ADDRESS` | 必填的 S 地址；未指定端口时使用 `443`。 |
| `--passphrase SOURCE` | `prompt`、`env:NAME` 或 `file:PATH`；默认 `prompt`。 |
| `--fingerprint VALUE` | 期望的 S 证书 SHA-256 指纹。 |
| `--transport MODE` | `auto`、`quic` 或 `tcp`；默认 `auto`。 |
| `--session-mode MODE` | `safe` 或 `client`；两者现在都会在会话启动前安装目录处理器。 |
| `--target HOST:PORT` | 由 S 或 E 解析的 HTTP 目标；默认 `127.0.0.1:8080`。 |
| `--timeout DURATION` | 每个网络阶段的超时；默认 `15s`。 |
| `--http-path PATH` | 最终 HTTP GET 使用的路径；默认 `/`。 |

## 安全和数据处理

- TLS 最低版本为 1.3。
- 原始口令不会发送给 S 或 E。
- S 仅存储盐值、Argon2id 参数和派生验证器。
- 认证使用基于随机数派生的 HMAC 证明。
- 认证失败按对端地址限速。
- C 和 E 固定或通过 TOFU 保存的证书指纹可以防止 S 证书被静默替换。
- S 被视为可信中继，可以看到代理元数据和转发流量。
- E 仅向 S 建立出站连接。
- 仅当系统代理当前值与本进程应用的值一致时才恢复，避免覆盖之后的人工修改。
- 如果恢复失败，将保留日志，供下次启动处理。

本项目不是匿名系统。S 可以观察连接元数据和流量；任何持有共享口令的人都可以访问所有已注册出口和目标地址。

## 故障行为

| 情况 | 行为 |
| --- | --- |
| 口令错误 | 认证失败；S 会对重复失败限速。 |
| S 证书指纹变化 | C 或 E 立即拒绝连接并保持信任存储不变。 |
| 启动 C 时 S 不可用 | `connect` 报告传输错误，不启动本地监听器。 |
| 已连接后 S 不可用 | C 报告断开，并使用退避策略重连。 |
| E 不可用 | 新建立的显式指定流失败；自动选择会优先使用其他健康出口。 |
| 流传输中 E 断开 | 已有流失败；E 重连后可为新流继续服务。 |
| DNS 或目标地址错误 | 使用“目标不可用”错误拒绝该流。 |
| 协议版本不匹配 | 握手阶段拒绝不兼容版本。 |
| 系统代理被外部修改 | 跳过恢复并保留日志。 |
| Linux 无桌面或不受支持 | 不修改代理设置，并报告限制。 |
| 验证器或证书缺失 | 节点启动失败，并提示先运行 `--init`。 |
| 静默 Windows 配置包缺失或无效 | `lnproxy-windows-server.exe` 将错误写入 `lnproxy.log`，以非零状态退出，并且不初始化文件。 |

## 平台说明

### Windows

- WinINet 当前用户设置位于：

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

- 快照会保留代理启用状态、代理服务器、绕过列表和 PAC URL。
- 修改后会调用 `InternetSetOptionW` 通知 WinINet。
- Windows 服务端默认只写文件日志，除非传入 `--console` 或设置 `console: true`。
- `lnproxy-windows-server.exe` 使用 GUI 子系统构建并忽略全部参数，仅用于运行已有的 `%AppData%\lnproxy` 配置包。
- 未包含事件日志集成和 Windows 服务安装功能。

### Linux

- GNOME 使用 `gsettings`。
- KDE/KIO 使用 `kwriteconfig`/`kreadconfig`。
- 需要桌面会话以及相应命令行工具。
- 无桌面环境会返回 `ErrUnsupported`，不修改代理设置，并记录限制。

## 协议概要

控制消息和流数据使用带长度前缀的帧：

```text
第 0 字节       帧类型
第 1..8 字节    请求/流 ID，大端 uint64
第 9..12 字节   负载长度，大端 uint32
第 13.. 字节    JSON 或流数据
```

帧类型包括流就绪、挑战、认证响应/结果、出口注册、心跳、目录、打开/打开确认、数据、关闭和错误。协议 v2 在打开 QUIC 控制流后立即发送一个零负载的流就绪帧，使对端能在认证开始前接受该流。

打开请求包含：

```json
{
  "request_id": 1,
  "exit_id": "auto",
  "destination_host": "example.com",
  "destination_port": 443,
  "protocol": "tcp",
  "client_selected": false
}
```

最大帧大小为 1 MiB，流数据分块上限为 64 KiB。

## 当前限制和后续工作

- 仅支持 TCP，尚未实现 UDP。
- `idle_timeout` 会被解析和保存，但尚未实现应用层流空闲超时；当前空闲行为主要由 QUIC 库提供。
- 尚未实现透明代理/TUN 模式。
- 尚未提供公网会合服务。
- 尚未实现 C 到 E 的端到端加密，S 会转发会话内容。
- 没有按客户端划分的账户、ACL 或目标策略。
- 出口失败时不会迁移已有流。
- 协议版本为 2，并且故意不与 v1 节点互通。

## 许可证

当前仓库没有许可证文件。分发项目或接受外部贡献前，应补充明确许可证。
