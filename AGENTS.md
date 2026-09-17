# Repository Guidelines

## Project Structure & Module Organization

`cmd/` contains one `main` package per executable: client, initializer, node, probe, and Windows server. Shared implementation lives under `internal/`; keep packages focused and avoid cross-package shortcuts that bypass exported APIs. Real network tests live in `integration/`. Generated release output belongs in `dist/`, which is ignored by Git.

## Build, Test, and Development Commands

```bash
go build -o lnproxy-node ./cmd/lnproxy-node
go test ./...
go vet ./...
go test -race ./integration ./internal/node ./internal/proxy/httpconnect
```

Cross-compile Windows binaries with `GOOS=windows GOARCH=amd64`. Always add `-ldflags=-H=windowsgui` when building `cmd/lnproxy-windows-server`.

## Coding Style & Naming Conventions

Use standard Go formatting with `gofmt`. Keep package names short and lowercase. Exported identifiers require doc comments; favor descriptive local names over abbreviations. Tests use `TestXxx` names and table-driven cases where they improve clarity. Keep security-sensitive defaults explicit, and never log passphrases, private keys, verifier material, or unredacted credentials.

## Testing Guidelines

Add focused unit tests beside implementation files. Changes to transport, authentication, session behavior, or exit selection should also update `integration/e2e_test.go`, covering TCP and QUIC where applicable. Integration tests bind loopback sockets; run them in an environment that permits local networking. No coverage percentage is currently enforced, but new behavior must have regression coverage.

## Commit & Pull Request Guidelines

Use Conventional Commits: `feat:`, `fix:`, `docs:`, `ci:`, `refactor:`, `test:`, or `chore:`. Add `!` or a `BREAKING CHANGE:` footer for incompatible changes. Pull requests must target `main`, describe behavior and validation, link relevant issues, and include screenshots only for user-visible interface changes.

All pull requests require the `verify` check. After merge to `main`, releasable commits generate the next SemVer tag and GitHub Release. Non-releasable commits still run verification but do not release.

## Security & Configuration

Initialize nodes with `go run ./cmd/lnproxy-init <role>`, protect generated certificate and passphrase files, and use an explicit S fingerprint for unattended exits. Treat changes to authentication, trust-on-first-use storage, system-proxy journals, and release permissions as security-sensitive.
