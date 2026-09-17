package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/protocol"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"
)

const maxHTTPResponseBody = 1 << 20

type options struct {
	server      string
	passphrase  string
	fingerprint string
	transport   string
	sessionMode string
	target      string
	timeout     time.Duration
	httpPath    string
}

type probe struct {
	options options
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	start   time.Time
	trust   *memoryTrust
}

type stageError struct {
	stage   string
	timeout bool
	err     error
}

func (e *stageError) Error() string {
	return fmt.Sprintf("%s: %v", e.stage, e.err)
}

func (e *stageError) Unwrap() error {
	return e.err
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseOptions(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "lnproxy-probe:", err)
		return 1
	}

	passphrase, err := auth.ResolvePassphrase(opts.passphrase)
	if err != nil {
		fmt.Fprintln(stderr, "lnproxy-probe:", err)
		return 1
	}
	p := &probe{
		options: opts,
		stdin:   stdin,
		stdout:  stdout,
		stderr:  stderr,
		start:   time.Now(),
		trust:   newMemoryTrust(opts.fingerprint, stdin, stderr),
	}
	if err := p.run(context.Background(), passphrase); err != nil {
		p.stage("FAIL %v", err)
		var stageErr *stageError
		if errors.As(err, &stageErr) && stageErr.timeout {
			return 2
		}
		return 1
	}
	p.stage("PASS")
	return 0
}

func parseOptions(args []string, output io.Writer) (options, error) {
	opts := options{
		passphrase:  "prompt",
		transport:   "auto",
		sessionMode: "safe",
		target:      "127.0.0.1:8080",
		timeout:     15 * time.Second,
		httpPath:    "/",
	}
	flags := flag.NewFlagSet("lnproxy-probe", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.server, "server", "", "S address (host or host:port)")
	flags.StringVar(&opts.passphrase, "passphrase", opts.passphrase, "passphrase source: prompt, env:NAME, or file:PATH")
	flags.StringVar(&opts.fingerprint, "fingerprint", "", "expected S certificate SHA-256 fingerprint")
	flags.StringVar(&opts.transport, "transport", opts.transport, "transport: auto, quic, or tcp")
	flags.StringVar(&opts.sessionMode, "session-mode", opts.sessionMode, "session startup mode: safe or client")
	flags.StringVar(&opts.target, "target", opts.target, "HTTP target resolved by S or E")
	flags.DurationVar(&opts.timeout, "timeout", opts.timeout, "timeout for each network stage")
	flags.StringVar(&opts.httpPath, "http-path", opts.httpPath, "HTTP request path")
	flags.Usage = func() {
		fmt.Fprintln(output, "Usage: lnproxy-probe --server ADDRESS [options]")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if opts.server == "" {
		return options{}, errors.New("--server is required")
	}
	normalized, err := config.NormalizeServerAddress(opts.server)
	if err != nil {
		return options{}, fmt.Errorf("invalid --server: %w", err)
	}
	opts.server = normalized
	switch opts.transport {
	case "auto", "quic", "tcp":
	default:
		return options{}, fmt.Errorf("invalid --transport %q", opts.transport)
	}
	switch opts.sessionMode {
	case "safe", "client":
	default:
		return options{}, fmt.Errorf("invalid --session-mode %q", opts.sessionMode)
	}
	if _, _, err := parseTarget(opts.target); err != nil {
		return options{}, err
	}
	if opts.timeout <= 0 {
		return options{}, errors.New("--timeout must be positive")
	}
	if opts.httpPath == "" || opts.httpPath[0] != '/' {
		return options{}, errors.New("--http-path must start with /")
	}
	return opts, nil
}

func (p *probe) run(ctx context.Context, passphrase string) error {
	p.stage("config: server=%s transport=%s session_mode=%s target=%s", p.options.server, p.options.transport, p.options.sessionMode, p.options.target)
	conn, transportName, err := p.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := p.authenticate(conn, passphrase); err != nil {
		return err
	}
	sess, catalog, err := p.startSession(conn)
	if err != nil {
		return err
	}
	defer sess.Close()
	p.stage("catalog: %d exit(s)", len(catalog))

	if err := p.testHTTP(ctx, sess); err != nil {
		return err
	}
	p.stage("transport: %s", transportName)
	return nil
}

func (p *probe) connect(parent context.Context) (transport.Conn, string, error) {
	switch p.options.transport {
	case "quic":
		conn, err := p.connectQUIC(parent)
		return conn, protocol.ProtocolQUIC, err
	case "tcp":
		conn, err := p.connectTCP(parent)
		return conn, protocol.ProtocolTLS, err
	default:
		conn, err := p.connectQUIC(parent)
		if err == nil {
			return conn, protocol.ProtocolQUIC, nil
		}
		var stageErr *stageError
		if errors.As(err, &stageErr) && stageErr.stage == "QUIC control stream" {
			return nil, "", err
		}
		p.stage("transport: QUIC unavailable (%v); falling back to TCP", err)
		conn, err = p.connectTCP(parent)
		return conn, protocol.ProtocolTLS, err
	}
}

func (p *probe) connectQUIC(parent context.Context) (transport.Conn, error) {
	p.stage("transport: QUIC dial")
	ctx, cancel := context.WithTimeout(parent, p.options.timeout)
	config := transport.ClientTLSConfig("", p.trust, addressHost(p.options.server))
	conn, err := transport.DialQUIC(ctx, p.options.server, config)
	cancel()
	if err != nil {
		return nil, p.transportError("QUIC dial", err)
	}
	p.stage("tls: verified fingerprint=%s", p.trust.Fingerprint())

	p.stage("transport: QUIC control stream")
	ctx, cancel = context.WithTimeout(parent, p.options.timeout)
	stream, err := transport.OpenControlStream(ctx, conn)
	cancel()
	if err != nil {
		_ = conn.CloseWithError(0, "control stream failed")
		return nil, p.transportError("QUIC control stream", err)
	}
	return transport.StreamConn(stream), nil
}

func (p *probe) connectTCP(parent context.Context) (transport.Conn, error) {
	p.stage("transport: TCP/TLS dial")
	ctx, cancel := context.WithTimeout(parent, p.options.timeout)
	config := transport.ClientTLSConfig("", p.trust, addressHost(p.options.server))
	conn, err := transport.DialTLS(ctx, p.options.server, config)
	cancel()
	if err != nil {
		return nil, p.transportError("TCP/TLS dial", err)
	}
	p.stage("tls: verified fingerprint=%s", p.trust.Fingerprint())
	return conn, nil
}

func (p *probe) authenticate(conn transport.Conn, passphrase string) error {
	p.stage("auth: challenge and Argon2id")
	before := readMemory()
	started := time.Now()
	result := make(chan error, 1)
	go func() {
		result <- auth.ClientHandshakePassword(conn, passphrase, auth.RoleClient)
	}()
	timer := time.NewTimer(p.options.timeout)
	defer timer.Stop()
	select {
	case err := <-result:
		if err != nil {
			return &stageError{stage: "authentication", err: err}
		}
	case <-timer.C:
		return &stageError{stage: "authentication", timeout: true, err: context.DeadlineExceeded}
	}
	after := readMemory()
	p.stage(
		"auth: ok duration=%s heap_total_delta=%s sys=%s",
		time.Since(started).Round(time.Millisecond),
		formatBytes(delta(after.TotalAlloc, before.TotalAlloc)),
		formatBytes(after.Sys),
	)
	return nil
}

func (p *probe) startSession(conn transport.Conn) (*session.Session, []protocol.ExitInfo, error) {
	sess := session.New(session.Config{IdleTimeout: 5 * time.Minute})
	catalog := make(chan []protocol.ExitInfo, 1)
	handleControl := func(frame protocol.Frame) {
		if frame.Type != protocol.FrameCatalog {
			return
		}
		value, err := protocol.DecodeJSON[protocol.Catalog](frame)
		if err != nil {
			return
		}
		select {
		case catalog <- value.Exits:
		default:
		}
	}
	sess.SetControlHandler(handleControl)

	p.stage("session: starting (%s mode)", p.options.sessionMode)
	if err := sess.Start(context.Background(), func(context.Context) (transport.Conn, error) {
		return conn, nil
	}, nil); err != nil {
		return nil, nil, &stageError{stage: "session start", err: err}
	}
	p.stage("catalog: waiting")
	timer := time.NewTimer(p.options.timeout)
	defer timer.Stop()
	select {
	case exits := <-catalog:
		return sess, exits, nil
	case <-sess.Done():
		err := sess.Err()
		if err == nil {
			err = errors.New("session closed before catalog")
		}
		return nil, nil, &stageError{stage: "catalog", err: err}
	case <-timer.C:
		return nil, nil, &stageError{stage: "catalog", timeout: true, err: context.DeadlineExceeded}
	}
}

func (p *probe) testHTTP(parent context.Context, sess *session.Session) error {
	host, port, err := parseTarget(p.options.target)
	if err != nil {
		return err
	}
	p.stage("stream: opening %s via auto", net.JoinHostPort(host, strconv.Itoa(int(port))))
	ctx, cancel := context.WithTimeout(parent, p.options.timeout)
	stream, err := sess.Dial(ctx, protocol.OpenRequest{
		Destination: host,
		Port:        port,
		Protocol:    protocol.ProtocolTCP,
		ExitID:      "auto",
	})
	cancel()
	if err != nil {
		return p.transportError("stream open", err)
	}
	defer stream.Close()
	p.stage("stream: opened exit=%s", stream.ExitID())

	type httpResult struct {
		status int
		bytes  int64
		err    error
	}
	result := make(chan httpResult, 1)
	go func() {
		request := fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: lnproxy-probe/1\r\nConnection: close\r\n\r\n",
			p.options.httpPath,
			p.options.target,
		)
		if _, err := io.WriteString(stream, request); err != nil {
			result <- httpResult{err: err}
			return
		}
		if err := stream.CloseWrite(); err != nil {
			result <- httpResult{err: err}
			return
		}
		response, err := http.ReadResponse(bufio.NewReader(stream), &http.Request{Method: http.MethodGet})
		if err != nil {
			result <- httpResult{err: err}
			return
		}
		defer response.Body.Close()
		count, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxHTTPResponseBody))
		result <- httpResult{status: response.StatusCode, bytes: count, err: err}
	}()

	timer := time.NewTimer(p.options.timeout)
	defer timer.Stop()
	select {
	case response := <-result:
		if response.err != nil {
			return &stageError{stage: "HTTP request", err: response.err}
		}
		p.stage("http: status=%d bytes=%d", response.status, response.bytes)
		return nil
	case <-timer.C:
		return &stageError{stage: "HTTP request", timeout: true, err: context.DeadlineExceeded}
	}
}

func (p *probe) transportError(stage string, err error) error {
	return &stageError{stage: stage, timeout: isTimeout(err), err: err}
}

func (p *probe) stage(format string, args ...any) {
	fmt.Fprintf(p.stdout, "[%9.3fs] %s\n", time.Since(p.start).Seconds(), fmt.Sprintf(format, args...))
}

type memoryStats struct {
	TotalAlloc uint64
	Sys        uint64
}

func readMemory() memoryStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return memoryStats{TotalAlloc: stats.TotalAlloc, Sys: stats.Sys}
}

func delta(after, before uint64) uint64 {
	if after < before {
		return 0
	}
	return after - before
}

func formatBytes(value uint64) string {
	const mib = 1 << 20
	if value >= mib {
		return fmt.Sprintf("%.2fMiB", float64(value)/mib)
	}
	return fmt.Sprintf("%dB", value)
}

func parseTarget(value string) (string, uint16, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return "", 0, fmt.Errorf("invalid --target %q: %w", value, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid --target port %q", portText)
	}
	if host == "" {
		return "", 0, errors.New("--target host is required")
	}
	return host, uint16(port), nil
}

func addressHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

type memoryTrust struct {
	mu          sync.Mutex
	expected    string
	fingerprint string
	confirmed   bool
	in          io.Reader
	out         io.Writer
}

func newMemoryTrust(expected string, in io.Reader, out io.Writer) *memoryTrust {
	return &memoryTrust{
		expected: transport.NormalizeFingerprint(expected),
		in:       in,
		out:      out,
	}
}

func (t *memoryTrust) Get(string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.expected == "" {
		return t.fingerprint
	}
	return t.expected
}

func (t *memoryTrust) Check(_ string, fingerprint string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	expected := t.expected
	if expected == "" {
		expected = t.fingerprint
	}
	if expected == "" || transport.EqualFingerprint(expected, fingerprint) {
		return nil
	}
	return errors.New("server certificate fingerprint changed")
}

func (t *memoryTrust) Save(_ string, fingerprint string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	fingerprint = transport.NormalizeFingerprint(fingerprint)
	if t.expected != "" && !transport.EqualFingerprint(t.expected, fingerprint) {
		return fmt.Errorf("server certificate fingerprint mismatch: expected %s, got %s", t.expected, fingerprint)
	}
	t.fingerprint = fingerprint
	if t.confirmed || t.expected != "" {
		t.confirmed = true
		return nil
	}
	fmt.Fprintf(t.out, "Server certificate fingerprint:\n%s\n", fingerprint)
	fmt.Fprint(t.out, "Trust this server? [y/N] ")
	var answer string
	if _, err := fmt.Fscanln(t.in, &answer); err != nil {
		return err
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		return errors.New("server certificate fingerprint was not accepted")
	}
	t.confirmed = true
	return nil
}

func (t *memoryTrust) Fingerprint() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.fingerprint
}
