package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/node"
	"lnproxy/internal/protocol"
	"lnproxy/internal/transport"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
		check   func(t *testing.T, options options)
	}{
		{
			name:    "server required",
			wantErr: "--server is required",
		},
		{
			name: "defaults",
			args: []string{"--server", "127.0.0.1"},
			check: func(t *testing.T, options options) {
				t.Helper()
				if options.server != "127.0.0.1:443" {
					t.Fatalf("server = %q", options.server)
				}
				if options.transport != "auto" {
					t.Fatalf("transport = %q", options.transport)
				}
				if options.sessionMode != "safe" {
					t.Fatalf("session mode = %q", options.sessionMode)
				}
				if options.target != "127.0.0.1:8080" {
					t.Fatalf("target = %q", options.target)
				}
				if options.timeout != 15*time.Second {
					t.Fatalf("timeout = %s", options.timeout)
				}
				if options.httpPath != "/" {
					t.Fatalf("http path = %q", options.httpPath)
				}
			},
		},
		{
			name: "explicit values",
			args: []string{
				"--server", "example.test:9443",
				"--transport", "tcp",
				"--session-mode", "client",
				"--target", "example.test:8080",
				"--timeout", "3s",
				"--http-path", "/health",
			},
			check: func(t *testing.T, options options) {
				t.Helper()
				if options.transport != "tcp" || options.sessionMode != "client" {
					t.Fatalf("unexpected modes: %q %q", options.transport, options.sessionMode)
				}
				if options.target != "example.test:8080" || options.httpPath != "/health" {
					t.Fatalf("unexpected target/path: %q %q", options.target, options.httpPath)
				}
			},
		},
		{
			name:    "invalid transport",
			args:    []string{"--server", "127.0.0.1", "--transport", "udp"},
			wantErr: "invalid --transport",
		},
		{
			name:    "invalid session mode",
			args:    []string{"--server", "127.0.0.1", "--session-mode", "legacy"},
			wantErr: "invalid --session-mode",
		},
		{
			name:    "invalid target",
			args:    []string{"--server", "127.0.0.1", "--target", "localhost"},
			wantErr: "invalid --target",
		},
		{
			name:    "invalid target port",
			args:    []string{"--server", "127.0.0.1", "--target", "localhost:70000"},
			wantErr: "invalid --target port",
		},
		{
			name:    "non-positive timeout",
			args:    []string{"--server", "127.0.0.1", "--timeout", "0s"},
			wantErr: "--timeout must be positive",
		},
		{
			name:    "invalid HTTP path",
			args:    []string{"--server", "127.0.0.1", "--http-path", "health"},
			wantErr: "--http-path must start",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, err := parseOptions(test.args, io.Discard)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.check != nil {
				test.check(t, options)
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	var output bytes.Buffer
	if code := run([]string{"--help"}, strings.NewReader(""), io.Discard, &output); code != 0 {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(output.String(), "Usage: lnproxy-probe") {
		t.Fatalf("help output = %q", output.String())
	}
}

func TestMemoryTrust(t *testing.T) {
	const fingerprint = "AA:BB:CC"

	t.Run("accepted prompt", func(t *testing.T) {
		var output bytes.Buffer
		trust := newMemoryTrust("", strings.NewReader("yes\n"), &output)
		if err := trust.Save("server", fingerprint); err != nil {
			t.Fatal(err)
		}
		if trust.Get("server") != fingerprint {
			t.Fatalf("fingerprint = %q", trust.Get("server"))
		}
		if !strings.Contains(output.String(), fingerprint) {
			t.Fatalf("prompt output = %q", output.String())
		}
	})

	t.Run("rejected prompt", func(t *testing.T) {
		trust := newMemoryTrust("", strings.NewReader("no\n"), io.Discard)
		if err := trust.Save("server", fingerprint); err == nil {
			t.Fatal("expected trust rejection")
		}
	})

	t.Run("expected mismatch", func(t *testing.T) {
		trust := newMemoryTrust(fingerprint, strings.NewReader("yes\n"), io.Discard)
		if err := trust.Save("server", "DD:EE:FF"); err == nil {
			t.Fatal("expected fingerprint mismatch")
		}
	})

	t.Run("stored mismatch", func(t *testing.T) {
		trust := newMemoryTrust("", strings.NewReader("yes\n"), io.Discard)
		if err := trust.Save("server", fingerprint); err != nil {
			t.Fatal(err)
		}
		if err := trust.Check("server", "DD:EE:FF"); err == nil {
			t.Fatal("expected stored fingerprint mismatch")
		}
	})
}

func TestProbeSafeTCPThroughDirectExit(t *testing.T) {
	root := t.TempDir()
	cfg, verifier, tlsConfig, fingerprint := setupProbeServer(t, root)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server := node.NewServer(cfg, verifier, tlsConfig, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() {
		if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("server: %v", err)
		}
	}()
	serverAddress := waitForProbeServer(t, server.Ready(), ctx)

	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/probe" {
			http.NotFound(writer, request)
			return
		}
		_, _ = io.WriteString(writer, "probe-ok")
	}))
	defer target.Close()

	var output bytes.Buffer
	p := &probe{
		options: options{
			server:      serverAddress,
			transport:   "tcp",
			sessionMode: "safe",
			target:      strings.TrimPrefix(target.URL, "http://"),
			timeout:     5 * time.Second,
			httpPath:    "/probe",
		},
		stdin:  strings.NewReader(""),
		stdout: &output,
		stderr: io.Discard,
		start:  time.Now(),
		trust:  newMemoryTrust(fingerprint, strings.NewReader(""), io.Discard),
	}
	if err := p.run(ctx, "integration-passphrase"); err != nil {
		t.Fatalf("probe: %v\noutput:\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "http: status=200 bytes=8") {
		t.Fatalf("probe output:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "transport: tls") {
		t.Fatalf("probe output:\n%s", output.String())
	}
}

func TestProbeSessionModesHandleImmediateCatalog(t *testing.T) {
	for _, mode := range []string{"safe", "client"} {
		t.Run(mode, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			go func() {
				_ = protocol.NewWriter(serverConn).WriteJSON(
					protocol.FrameCatalog,
					0,
					protocol.Catalog{Exits: []protocol.ExitInfo{{ID: "direct", Capacity: 1}}},
				)
			}()

			p := &probe{
				options: options{sessionMode: mode, timeout: time.Second},
				stdin:   strings.NewReader(""),
				stdout:  io.Discard,
				stderr:  io.Discard,
				start:   time.Now(),
				trust:   newMemoryTrust("", strings.NewReader(""), io.Discard),
			}
			sess, exits, err := p.startSession(clientConn)
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			if len(exits) != 1 || exits[0].ID != "direct" {
				t.Fatalf("catalog = %#v", exits)
			}
		})
	}
}

func TestProbeTimeoutIsExitCodeTwo(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	opts := options{
		server:      listener.Addr().String(),
		transport:   "tcp",
		sessionMode: "safe",
		target:      "127.0.0.1:8080",
		timeout:     50 * time.Millisecond,
		httpPath:    "/",
	}
	p := &probe{
		options: opts,
		stdin:   strings.NewReader(""),
		stdout:  io.Discard,
		stderr:  io.Discard,
		start:   time.Now(),
		trust:   newMemoryTrust("", strings.NewReader(""), io.Discard),
	}
	err = p.run(context.Background(), "integration-passphrase")
	var stageErr *stageError
	if !errors.As(err, &stageErr) || !stageErr.timeout {
		t.Fatalf("error = %v, want timeout stage error", err)
	}
}

func setupProbeServer(t *testing.T, root string) (config.Node, auth.Verifier, *tls.Config, string) {
	t.Helper()
	cfg, err := config.DefaultNode(config.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataDirectory = root
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.CertificateFile = filepath.Join(root, "server.crt")
	cfg.KeyFile = filepath.Join(root, "server.key")
	cfg.VerifierFile = filepath.Join(root, "passphrase.json")
	cfg = cfg.FillPaths()
	verifier, err := auth.NewVerifier("integration-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := config.GenerateCertificate(cfg.CertificateFile, cfg.KeyFile, "localhost"); err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return cfg, verifier, transport.BaseTLSConfig(&certificate), transport.Fingerprint(leaf)
}

func waitForProbeServer(t *testing.T, ready <-chan net.Addr, ctx context.Context) string {
	t.Helper()
	select {
	case address := <-ready:
		return address.String()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		return ""
	}
}
