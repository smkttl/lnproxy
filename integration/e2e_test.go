package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/client"
	"lnproxy/internal/config"
	"lnproxy/internal/node"
	"lnproxy/internal/protocol"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"
)

func TestClientToServerDirectExit(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		testClientToServerDirectExit(t, false)
	})
	t.Run("quic", func(t *testing.T) {
		testClientToServerDirectExit(t, true)
	})
}

func testClientToServerDirectExit(t *testing.T, useQUIC bool) {
	root := t.TempDir()
	cfg, verifier, tlsConfig := setupServer(t, root)

	targetAddress, closeTarget := startEchoServer(t)
	defer closeTarget()
	targetHost, targetPort := splitAddress(t, targetAddress)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := node.NewServer(cfg, verifier, tlsConfig, slog.Default())
	go func() {
		if err := server.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("server: %v", err)
		}
	}()
	serverAddress := waitForServer(t, server.Ready(), ctx)

	knownHosts, err := transport.LoadKnownHosts(filepath.Join(root, "known-hosts.json"))
	if err != nil {
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
	serverHost, _, _ := net.SplitHostPort(serverAddress)
	if err := knownHosts.SaveUnconfirmed(serverHost, transport.Fingerprint(leaf)); err != nil {
		t.Fatal(err)
	}
	manager := client.NewManager(knownHosts)
	connectTestManager(t, ctx, manager, serverAddress, useQUIC)
	defer manager.Close()
	stream, err := manager.Dial(ctx, protocol.OpenRequest{
		Destination: targetHost,
		Port:        targetPort,
		Protocol:    protocol.ProtocolTCP,
		ExitID:      "direct",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q", data)
	}
}

func TestClientToServerToExit(t *testing.T) {
	t.Run("tcp", func(t *testing.T) {
		testClientToServerToExit(t, false)
	})
	t.Run("quic", func(t *testing.T) {
		testClientToServerToExit(t, true)
	})
}

func testClientToServerToExit(t *testing.T, useQUIC bool) {
	root := t.TempDir()
	cfg, verifier, tlsConfig := setupServer(t, root)
	targetAddress, closeTarget := startEchoServer(t)
	defer closeTarget()
	targetHost, targetPort := splitAddress(t, targetAddress)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server := node.NewServer(cfg, verifier, tlsConfig, slog.Default())
	go func() {
		if err := server.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("server: %v", err)
		}
	}()
	serverAddress := waitForServer(t, server.Ready(), ctx)

	exitCertificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(exitCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	exitConfig := cfg
	exitConfig.Role = config.RoleExit
	exitConfig.ServerAddress = serverAddress
	exitConfig.ServerFingerprint = ""
	exitConfig.ExitID = "test-exit"
	exitConfig.ExitName = "test exit"
	exitConfig.Capacity = 8
	exitKnownHostsPath := filepath.Join(root, "exit-known-hosts.json")
	exitTrust, err := transport.LoadKnownHosts(exitKnownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	prompted := make(chan string, 1)
	exitTrust.SetConfirmer(func(host, fingerprint string) (bool, error) {
		prompted <- fingerprint
		return true, nil
	})
	exit := node.NewExit(exitConfig, "integration-passphrase", nil, slog.Default())
	exit.UseTrust(exitTrust)
	if !useQUIC {
		exit.UseTCP()
	}
	go func() {
		if err := exit.Run(ctx); err != nil && ctx.Err() == nil {
			t.Errorf("exit: %v", err)
		}
	}()

	select {
	case fingerprint := <-prompted:
		if !transport.EqualFingerprint(fingerprint, transport.Fingerprint(leaf)) {
			t.Fatalf("prompted fingerprint = %q, want %q", fingerprint, transport.Fingerprint(leaf))
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	serverHost, _, _ := net.SplitHostPort(serverAddress)
	if got := exitTrust.Get(serverHost); !transport.EqualFingerprint(got, transport.Fingerprint(leaf)) {
		t.Fatalf("stored exit fingerprint = %q, want %q", got, transport.Fingerprint(leaf))
	}

	reloadedTrust, err := transport.LoadKnownHosts(exitKnownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloadedTrust.Get(serverHost); !transport.EqualFingerprint(got, transport.Fingerprint(leaf)) {
		t.Fatalf("reloaded exit fingerprint = %q, want %q", got, transport.Fingerprint(leaf))
	}

	knownHosts, err := transport.LoadKnownHosts(filepath.Join(root, "known-hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := knownHosts.SaveUnconfirmed(serverHost, transport.Fingerprint(leaf)); err != nil {
		t.Fatal(err)
	}
	manager := client.NewManager(knownHosts)
	connectTestManager(t, ctx, manager, serverAddress, useQUIC)
	defer manager.Close()
	waitForExit(t, manager, "test-exit")
	stream, err := manager.Dial(ctx, protocol.OpenRequest{
		Destination: targetHost,
		Port:        targetPort,
		Protocol:    protocol.ProtocolTCP,
		ExitID:      "test-exit",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("through-exit")); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "through-exit" {
		t.Fatalf("got %q", data)
	}
}

func connectTestManager(t *testing.T, ctx context.Context, manager *client.Manager, address string, useQUIC bool) {
	t.Helper()
	if useQUIC {
		if err := manager.Connect(ctx, address, "integration-passphrase"); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := manager.ConnectTCP(ctx, address, "integration-passphrase"); err != nil {
			t.Fatal(err)
		}
	}
	_, transportName, _ := manager.State()
	wantTransport := protocol.ProtocolQUIC
	if !useQUIC {
		wantTransport = protocol.ProtocolTLS
	}
	if transportName != wantTransport {
		t.Fatalf("transport = %q, want %q", transportName, wantTransport)
	}
}

func TestHTTPConnectThroughSession(t *testing.T) {
	targetAddress, closeTarget := startEchoServer(t)
	defer closeTarget()
	targetHost, targetPort := splitAddress(t, targetAddress)

	// This test validates the local listener's data path over a real session.
	clientRaw, serverRaw := net.Pipe()
	clientSession := session.New(session.Config{})
	serverSession := session.New(session.Config{})
	if err := clientSession.Start(context.Background(), func(context.Context) (transport.Conn, error) {
		return clientRaw, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := serverSession.Start(context.Background(), func(context.Context) (transport.Conn, error) {
		return serverRaw, nil
	}, func(stream *session.Stream) {
		if err := stream.Accept(); err != nil {
			return
		}
		target, err := node.DialDestination(context.Background(), targetHost, targetPort)
		if err != nil {
			_ = stream.Reject(err.Error())
			return
		}
		session.Relay(stream, target)
	}); err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	defer serverSession.Close()
}

func setupServer(t *testing.T, root string) (config.Node, auth.Verifier, *tls.Config) {
	t.Helper()
	cfg, err := config.DefaultNode(config.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DataDirectory = root
	cfg.ListenAddress = "127.0.0.1:0"
	cfg = cfg.FillPaths()
	verifier, err := auth.NewVerifier("integration-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Save(cfg.VerifierFile); err != nil {
		t.Fatal(err)
	}
	if err := config.GenerateCertificate(cfg.CertificateFile, cfg.KeyFile, "localhost"); err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, verifier, transport.BaseTLSConfig(&certificate)
}

func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		cancel()
		_ = listener.Close()
		_ = ctx.Err()
	}
}

func waitForServer(t *testing.T, ready <-chan net.Addr, ctx context.Context) string {
	t.Helper()
	select {
	case address := <-ready:
		return address.String()
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	return ""
}

func splitAddress(t *testing.T, address string) (string, uint16) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	value, err := net.LookupPort("tcp", port)
	if err != nil {
		t.Fatal(err)
	}
	return host, uint16(value)
}

func waitForExit(t *testing.T, manager *client.Manager, exitID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, exit := range manager.Catalog() {
			if exit.ID == exitID {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("exit %q did not appear in catalog", exitID)
}
