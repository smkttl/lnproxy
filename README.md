# lnproxy

English | [简体中文](README.zh-CN.md)

`lnproxy` is a cross-platform local-network TCP proxy built around three roles:

- **C (Client)** runs `lnproxy-client` on a machine that cannot directly reach the outer network. It exposes a loopback HTTP proxy (and optional SOCKS5), authenticates to S, and applies the current user's system proxy settings.
- **S (Server)** runs `lnproxy-node server` on a LAN-reachable machine with outbound network access. It is the control-plane authority, owns the exit catalog, and can also proxy directly.
- **E (Exit)** runs `lnproxy-node exit` on a machine with outbound network access but no reachable inbound address. E creates only outbound connections to S and dials destinations on behalf of C.

`lnproxy-node server-exit` combines S and direct-exit behavior in one process.

> **Status:** v1 supports TCP only. UDP, TUN/transparent proxying, public rendezvous, and end-to-end C-to-E encryption are not implemented.

## Architecture

```text
 Applications
      |
      v
 System HTTP proxy / optional SOCKS5
      |
      v
 lnproxy-client (C)
      |
      | TLS 1.3 over QUIC (preferred) or TCP
      v
 lnproxy-node server (S)
      |
      +--> direct destination (S/direct exit)
      |
      +--> reverse tunnel to E --> destination
```

S terminates the authenticated C and E sessions. E never listens for inbound proxy traffic. DNS resolution happens on S or E when `DialDestination` is invoked; C does not resolve destination hostnames before forwarding them.

## Features

- One Go module and these binaries:
  - `lnproxy-client` for C.
  - `lnproxy-node` for S, E, or S/E.
  - `lnproxy-init.exe` for one-time S, E, or S/E initialization.
  - `lnproxy-windows-server.exe` for a GUI-subsystem, argument-free Windows S/E server.
  - `lnproxy-probe` for bounded, console-only diagnosis of the C-to-S data path.
- TLS 1.3 encryption with QUIC preferred and TLS-over-TCP fallback.
- Protocol v2 QUIC control-stream readiness handshake, preventing the peer-stream visibility deadlock.
- Framed, multiplexed session protocol with independent request IDs, bounded per-stream buffering, cancellation, half-close, and idle handling.
- One shared passphrase per deployment.
- Argon2id salt and hash stored by S; the raw passphrase is never sent over the wire.
- Nonce-based challenge-response authentication over the encrypted session.
- Authentication failure rate limiting.
- Trust-on-first-use (TOFU) certificate fingerprint verification for C and E.
- Pinned S certificate fingerprint support for unattended C/E startup.
- HTTP CONNECT and plain HTTP proxy handling.
- Optional loopback SOCKS5 `CONNECT` listener.
- Exit catalog with ID, name, type, health, latency, load, capacity, features, and heartbeat timestamp.
- Permanently available local direct exit on S/S-E; heartbeat expiry applies only to remote E entries.
- Automatic selection by health, available capacity, and latency.
- Explicit exit selection with optional fallback.
- Heartbeats and stale E removal.
- Current-user system proxy integration:
  - Windows WinINet registry settings;
  - Linux GNOME GSettings;
  - Linux KDE/KIO.
- Crash-safe system proxy journal and guarded restore.
- Rotating JSON logs for node processes.
- Graceful shutdown on `quit`, EOF, Ctrl-C, SIGINT, and SIGTERM.

## Repository Layout

```text
cmd/lnproxy-client/       C executable
cmd/lnproxy-init/         Dedicated node initializer
cmd/lnproxy-node/         S/E executable
cmd/lnproxy-windows-server/ GUI-subsystem Windows S/E executable
cmd/lnproxy-probe/        Diagnostic C-path client without listeners or system changes
internal/auth/            Argon2id, challenge-response, rate limiting
internal/client/          Client manager, runtime, proxy lifecycle, shell
internal/config/          Node configuration and certificate generation
internal/initnode/        Shared node initialization operations
internal/logging/         Rotating structured logs
internal/node/            Server, exit, registry, destination dialer
internal/silentserver/    Initialized-bundle loader for the silent Windows server
internal/protocol/        Frame format, catalog, request/control messages
internal/proxy/           Shared proxy relay helpers
internal/proxy/httpconnect HTTP and CONNECT proxy
internal/proxy/socks5     SOCKS5 proxy
internal/session/         Multiplexed stream/session layer
internal/systemproxy/     Windows/Linux system proxy adapters
internal/transport/       QUIC/TLS transports and known-host store
integration/e2e_test.go   C-to-S and C-to-S-to-E integration tests
```

## Requirements

- Go 1.26 or newer for building from source.
- For a Linux desktop integration:
  - GNOME with `gsettings`; or
  - KDE with `kwriteconfig6`/`kwriteconfig5` and `kreadconfig6`/`kreadconfig5`.
- Linux headless or unsupported desktop sessions leave system proxy settings unchanged and log the limitation.
- Port `443` is the default S listener.

The module dependencies are `quic-go`, `x/crypto`, and `x/term`.

Protocol version 2 uses ALPN `lnproxy/2`. S, C, and every E must run v2 binaries together; v1 and v2 peers are intentionally incompatible.

## Build

The repository may be present without valid VCS metadata. Use `-buildvcs=false` in that situation.

### Linux

```bash
go build -buildvcs=false -o lnproxy-client ./cmd/lnproxy-client
go build -buildvcs=false -o lnproxy-node ./cmd/lnproxy-node
go build -buildvcs=false -o lnproxy-probe ./cmd/lnproxy-probe
```

### Windows cross-build

```bash
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-client.exe ./cmd/lnproxy-client
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-init.exe ./cmd/lnproxy-init
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-node.exe ./cmd/lnproxy-node
GOOS=windows GOARCH=amd64 go build -buildvcs=false -o lnproxy-probe.exe ./cmd/lnproxy-probe
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags=-H=windowsgui -o lnproxy-windows-server.exe ./cmd/lnproxy-windows-server
```

The `-H=windowsgui` linker flag is required for `lnproxy-windows-server.exe`. It produces a GUI-subsystem PE binary that Windows can run without creating a console window. The command is Windows-only; a non-Windows source fallback keeps repository-wide builds and tests portable.

### Test and race-check

```bash
go test ./...
go test -race ./integration ./internal/node ./internal/proxy/httpconnect
go vet ./...
```

The full integration test binds loopback sockets. Environments that restrict socket creation must allow those operations.

## Quick Start

The following example uses `192.0.2.10` as the address reachable from both C and E.

### 1. Initialize and start S

```bash
./lnproxy-node server --init
./lnproxy-node server
```

For the first E connection, you may either let E prompt for and store the SHA-256 fingerprint, or calculate the fingerprint from `server.crt` and configure it explicitly.

### 2. Start E

```bash
export LNPROXY_PASSPHRASE='replace with the S passphrase'

./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --exit-id edge-1
```

### 3. Start C

```bash
./lnproxy-client --socks5
```

Then connect:

```text
> connect 192.0.2.10
Please input password:
Authentication success!
HTTP proxy listening on 127.0.0.1:...
SOCKS5 proxy listening on 127.0.0.1:...
>
```

Use `exits` to inspect available exits and `use <exit-id>` to override automatic selection.

## Initializing S

Run initialization once on the S machine:

```bash
./lnproxy-node server --init
```

The dedicated initializer takes the role as its first argument. For an S-E node:

```bash
./lnproxy-init server-exit
```

The role-specific `lnproxy-node` form remains available and supports the same initialization options:

```bash
./lnproxy-node server-exit --init
```

`lnproxy-init` requires an explicit role; there is no role-free initialization syntax. It supports `server`, `exit`, and `server-exit`.

Initialization:

1. Creates the data directory.
2. Prompts twice for the shared passphrase with hidden input.
3. Stores an Argon2id salt, hash, and parameters in `passphrase.json`.
4. Generates a self-signed TLS certificate and private key.
5. Writes `node.json`.

The default data directory is the platform user-config directory plus `lnproxy`:

- Linux: normally `~/.config/lnproxy`.
- Windows: normally `%AppData%\\lnproxy`.

You can choose a data directory and explicit config path:

```bash
./lnproxy-node server \
  --init \
  --data-dir /var/lib/lnproxy \
  --config /etc/lnproxy/server.json
```

Initialization refuses to overwrite an existing verifier file.

`server-exit` can be initialized the same way:

```bash
./lnproxy-node server-exit --init
```

`exit` also creates a verifier file during initialization but does not generate a server certificate; E uses S's trust-on-first-use fingerprint or an explicitly configured S fingerprint, plus its configured passphrase source.

The node does not automatically discover `node.json` when `--config` is omitted. Always pass the same `--config` path used during initialization if the file is not in the process's default data directory.

## Running S

```bash
./lnproxy-node server
```

Override settings on the command line:

```bash
./lnproxy-node server \
  --config /etc/lnproxy/server.json \
  --listen 0.0.0.0:443
```

`server` and `server-exit` listen on both UDP (QUIC) and TCP (TLS fallback) using the same address and port.

For an S that also proxies directly:

```bash
./lnproxy-node server-exit --config /etc/lnproxy/server-exit.json
```

### S logging

- Linux defaults to JSON logs on stderr.
- Windows server mode is silent by default.
- Logs are also written to `<data-directory>/lnproxy.log`.
- The log rotates at approximately 5 MiB and retains three rotated files.
- Use `--console` or set `"console": true` for Windows diagnostics.

> The normal `lnproxy-node.exe` is a console-subsystem binary and supports the diagnostic console flag. `lnproxy-windows-server.exe` is the dedicated GUI-subsystem silent server described below. Event Log integration is not implemented.

### Silent Windows S-E server

`lnproxy-windows-server.exe` is a Windows-only build target for an initialized S-E node. It has no GUI, console, prompt, popup, or command-line interface. Every argument is ignored, including `--init`; the executable only serves an existing bundle.

Build it with the GUI linker flag:

```bash
GOOS=windows GOARCH=amd64 go build -buildvcs=false -ldflags=-H=windowsgui -o lnproxy-windows-server.exe ./cmd/lnproxy-windows-server
```

The silent server always reads its bundle from:

```text
%AppData%\lnproxy
```

The directory must contain all four initialized files:

```text
node.json
passphrase.json
server.crt
server.key
```

Initialize on the target machine with `lnproxy-init.exe server-exit` or the normal node binary, or copy all four files from an initialized Windows S-E deployment. When a bundle is copied, the silent server rebases `data_directory`, `certificate_file`, `key_file`, and `verifier_file` to the current `%AppData%\lnproxy` directory, so the copied config does not depend on the source machine's username or absolute paths. Protect `server.key` and `passphrase.json` during transfer.

The loaded role is always forced to `server-exit`, and `console` is forced to `false`. The remaining configuration fields are preserved, including the listen address, connection limit, idle timeout, capacity, exit name, and exit ID.

Successful startup creates no visible window. Diagnostics are written only to the rotating JSON file:

```text
%AppData%\lnproxy\lnproxy.log
```

The log rotates at approximately 5 MiB and retains three historical files. If `node.json` or any required bundle file is missing or invalid, the process writes an error to the log and exits nonzero. It never attempts to initialize the bundle.

The silent executable is a background process, not a Windows Service. Use Task Scheduler, a startup shortcut, or another external supervisor if it must run at boot.

## Running E

E must know how to reach S and authenticate to it. Recommended unattended configuration uses an environment variable or a protected file:

```bash
export LNPROXY_PASSPHRASE='shared deployment passphrase'

./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --exit-id edge-1 \
  --capacity 128
```

Or with a protected file:

```bash
chmod 600 /etc/lnproxy/passphrase
./lnproxy-node exit \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase file:/etc/lnproxy/passphrase
```

Interactive `prompt` is available for setup or console use, but unattended E startup should use `env:` or `file:`.

For the first connection without `--fingerprint`, E uses the same TOFU flow as C. It prints S's certificate fingerprint and asks `Trust this server? [y/N]`. If accepted, E stores the fingerprint in `<data_directory>/known-hosts.json` and reuses it on later starts. A changed fingerprint is rejected. In unattended mode, configure `--fingerprint`, or run E once interactively to populate the trust store; without either, startup fails with guidance instead of trusting automatically.

E has no inbound listener. It connects outbound to S, registers itself, sends heartbeats every 10 seconds, receives new stream requests over its control session, dials destinations, and relays TCP bytes.

If the connection to S ends, E retries with exponential backoff up to approximately 30 seconds between attempts.

## Running C

Start the foreground client:

```bash
./lnproxy-client
```

At the prompt:

```text
> connect 192.0.2.10
Please input password:
Authentication success!
HTTP proxy listening on 127.0.0.1:...
>
```

Port `443` is used when the address has no port:

```text
> connect 192.0.2.10:8443
```

Enable SOCKS5 at startup:

```bash
./lnproxy-client --socks5
```

### TOFU behavior

On the first connection, C prints the S certificate SHA-256 fingerprint and asks:

```text
Trust this server? [y/N]
```

For C, the fingerprint is stored in:

```text
<user-config-directory>/lnproxy/known-hosts.json
```

For E, it is stored in `<data_directory>/known-hosts.json`. Future connections reject a changed certificate fingerprint. Remove or edit the known-host entry only after independently verifying the new S certificate.

### Client command reference

| Command | Description |
| --- | --- |
| `connect <S IP>` | Connect to S, authenticate, start listeners, and apply the system proxy. |
| `status` | Show connection state, transport, selected exit, and listener addresses. |
| `exits` | Show the current S exit catalog. |
| `use <exit-id>` | Select an exit for new streams. |
| `use auto` | Return to automatic selection. |
| `use <exit-id> true` | Select an exit and fall back to automatic selection if it is unavailable. |
| `reconnect` | Close the current S session and connect again. |
| `disconnect` | Disconnect the current S session. |
| `help` | Print command help. |
| `quit` | Gracefully shut down and exit. |

Explicit exit selection affects new streams only. Existing streams are never migrated.

The client starts an HTTP proxy on a random loopback port. If `--socks5` is supplied, it starts a SOCKS5 listener on another random loopback port.

The client has no server/profile configuration file. It stores only trust and recovery state under the user data directory for certificate pinning and system proxy restoration.

### Client shutdown

`quit`, EOF, Ctrl-C, SIGINT, or SIGTERM triggers shutdown:

1. Stop accepting new local proxy requests.
2. Reject new streams.
3. Drain active streams for `--drain-timeout`.
4. Close the S session.
5. Restore system proxy settings if the current values still match the values applied by this process.
6. Remove the journal only after successful restoration.

The default drain timeout is 10 seconds:

```bash
./lnproxy-client --drain-timeout 30s
```

## Diagnosing Client Failures

`lnproxy-probe` runs the same connection, TLS verification, authentication, session, and stream code as C, but it does not start a local proxy, change system settings, or save a fingerprint. Use it when `lnproxy-client` hangs, exits after authentication, or never prints `Authentication success!`.

Build it on each target platform, or copy the matching artifact from the release bundle:

```bash
go build -buildvcs=false -o lnproxy-probe ./cmd/lnproxy-probe
```

Run a complete check through S/direct to the HTTP service listening on S at port 8080:

```bash
./lnproxy-probe \
  --server 192.0.2.10:443 \
  --fingerprint 'AA:BB:CC:...' \
  --passphrase env:LNPROXY_PASSPHRASE \
  --transport tcp \
  --target 127.0.0.1:8080 \
  --http-path /
```

The passphrase is requested before the fingerprint prompt when `--fingerprint` is omitted. Supplying `--fingerprint` avoids both prompts: the value is used only in memory and is never written to `known-hosts.json`.

Typical output:

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

Use these runs to isolate the failure:

```bash
# Probe only TCP and the safe startup ordering.
./lnproxy-probe --server HOST --transport tcp --session-mode safe \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080

# Probe only QUIC.
./lnproxy-probe --server HOST --transport quic --session-mode safe \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080

# Exercise the same corrected session ordering as the current Windows client.
./lnproxy-probe --server HOST --transport tcp --session-mode client \
  --passphrase env:LNPROXY_PASSPHRASE --target 127.0.0.1:8080
```

`--transport auto` tries QUIC first and falls back to TCP if the QUIC dial fails. If QUIC connects but its control stream cannot open, the probe reports `QUIC control stream` and does not hide that failure with a TCP fallback.

Diagnosis matrix:

| Observation | Meaning |
| --- | --- |
| Fails before `auth` | DNS, routing, TCP/UDP, firewall, TLS, or fingerprint problem. |
| `auth` times out or takes unexpectedly long | Argon2id is too expensive for the client; inspect S's verifier parameters and available memory. |
| `catalog` succeeds but `stream open` fails | No usable exit, stream rejection, or S/E routing failure. |
| `stream open` succeeds but HTTP times out | Target `127.0.0.1:8080` is not reachable from S/E, or the service is not serving HTTP. |
| TCP succeeds while QUIC fails | QUIC/UDP is blocked or broken along the path; use TCP while diagnosing. |
| All stages pass | The protocol and server path work. The remaining failure is local to the Windows client, system proxy, security software, or process lifetime. |

Exit codes are `0` for success, `2` for a network-stage timeout, and `1` for other failures.

## Configuration

`lnproxy-node` accepts `--config <path>`. The file is JSON. Command-line flags override selected fields after loading.

Example server configuration:

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

`idle_timeout` is encoded as a Go `time.Duration` in nanoseconds. `300000000000` is 5 minutes.

Example exit configuration:

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

### Node options

| Flag | Meaning |
| --- | --- |
| `--init` | After a node role, initialize that role. |
| `--config PATH` | Load a JSON node config. |
| `--data-dir PATH` | Override the data directory. |
| `--listen ADDRESS` | Override the S/S-E listener. |
| `--server ADDRESS` | S address used by E. |
| `--fingerprint VALUE` | Hard-pin S's SHA-256 certificate fingerprint for E; skips TOFU. |
| `--passphrase SOURCE` | `prompt`, `env:NAME`, or `file:PATH`. |
| `--console` | Force console logging on Windows. |
| `--capacity N` | Maximum concurrent streams advertised by E. |
| `--idle-timeout DURATION` | Stream/session idle timeout. |

### Client options

| Flag | Meaning |
| --- | --- |
| `--socks5` | Enable the optional SOCKS5 listener. |
| `--drain-timeout DURATION` | Bound graceful drain time; default `10s`. |

### Diagnostic probe options

| Flag | Meaning |
| --- | --- |
| `--server ADDRESS` | Required S address; port `443` is used when omitted. |
| `--passphrase SOURCE` | `prompt`, `env:NAME`, or `file:PATH`; default `prompt`. |
| `--fingerprint VALUE` | Expected S certificate SHA-256 fingerprint. |
| `--transport MODE` | `auto`, `quic`, or `tcp`; default `auto`. |
| `--session-mode MODE` | `safe` or `client`; both now install the catalog handler before session startup. |
| `--target HOST:PORT` | HTTP endpoint resolved by S or E; default `127.0.0.1:8080`. |
| `--timeout DURATION` | Per-stage timeout; default `15s`. |
| `--http-path PATH` | Path for the final HTTP GET; default `/`. |

## Security and Data Handling

- TLS minimum version is 1.3.
- The raw passphrase is never sent to S or E.
- S stores only salt, Argon2id parameters, and the derived verifier.
- Authentication uses a nonce-derived HMAC proof.
- Authentication failures are rate-limited by peer address.
- C's and E's pinned or TOFU-stored fingerprints protect against silent S certificate replacement.
- S is trusted to observe proxy metadata and relay traffic.
- E accepts only outbound connections to S.
- The system proxy is restored only when its current values match what this process applied, preventing accidental overwrite of later manual changes.
- If restoration fails, the journal is retained for the next startup.

This is not an anonymity system. S can observe connection metadata and traffic, and the shared passphrase grants unrestricted access to every registered exit and destination.

## Failure Behavior

| Situation | Behavior |
| --- | --- |
| Wrong passphrase | Authentication fails; S rate-limits repeated failures. |
| Changed S fingerprint | C or E rejects the connection immediately and leaves its trust store unchanged. |
| S unavailable at C startup | `connect` reports the transport error and does not start listeners. |
| S unavailable after connection | C reports disconnected and retries with backoff. |
| E unavailable | New explicitly selected streams fail; automatic selection prefers another healthy exit. |
| E disconnects mid-stream | Existing streams fail; E reconnects for new streams. |
| DNS or destination failure | The stream is rejected with a destination-unavailable error. |
| Protocol mismatch | The handshake rejects the incompatible version. |
| System proxy changed externally | Restoration is skipped and the journal is preserved. |
| Unsupported desktop/headless Linux | Settings are left unchanged and the limitation is reported. |
| Missing verifier/certificate | Node startup fails with a message directing you to `--init`. |
| Silent Windows bundle missing or invalid | `lnproxy-windows-server.exe` writes to `lnproxy.log` and exits nonzero without initializing files. |

## Platform Notes

### Windows

- WinINet current-user settings are read and written under:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
```

- Proxy enable/server values, bypass list, and PAC URL are preserved in the snapshot.
- `InternetSetOptionW` is called to notify WinINet after changes.
- Windows server logging defaults to file-only unless `--console` or `console: true` is set.
- `lnproxy-windows-server.exe` is built with the GUI subsystem and ignores all arguments; it is intended only for serving an existing `%AppData%\lnproxy` bundle.
- Event Log integration and Windows Service installation are not included.

### Linux

- GNOME support uses `gsettings`.
- KDE/KIO support uses `kwriteconfig`/`kreadconfig`.
- Detection requires a desktop session and the relevant tools.
- Headless sessions return `ErrUnsupported`, leave proxy settings unchanged, and log the limitation.

## Protocol Summary

Control and stream data use length-prefixed frames:

```text
byte 0       frame type
bytes 1..8   request/stream ID, big-endian uint64
bytes 9..12  payload length, big-endian uint32
bytes 13..   JSON or stream payload
```

Frame types include stream-ready, challenge, authentication response/result, exit registration, heartbeat, catalog, open/open acknowledgement, data, close, and error. Protocol v2 sends a zero-length stream-ready frame immediately after opening the QUIC control stream so the peer can accept it before authentication starts.

An open request carries:

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

Maximum frame size is 1 MiB. Stream data chunks are capped at 64 KiB.

## Limitations and Future Work

- TCP only; UDP is not implemented.
- `idle_timeout` is parsed and stored, but application-level stream idle enforcement is not yet implemented; transport idle behavior is currently provided by the QUIC library.
- No transparent/TUN mode.
- No public rendezvous service.
- No end-to-end C-to-E encryption; S relays the session.
- No per-client accounts, ACLs, or destination policy.
- No stream migration when an exit fails.
- The protocol is version 2 and intentionally does not interoperate with v1 peers.

## License

No license file is included in this repository. Add an explicit license before distributing or accepting external contributions.
