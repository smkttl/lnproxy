package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"lnproxy/internal/protocol"

	"github.com/quic-go/quic-go"
)

type Conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

type streamConn struct {
	stream *quic.Stream
}

func (c *streamConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

func (c *streamConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

func (c *streamConn) Close() error {
	return c.stream.Close()
}

func (c *streamConn) CloseRead() error {
	return c.stream.Close()
}

func (c *streamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func Fingerprint(certificate *x509.Certificate) string {
	sum := sha256.Sum256(certificate.Raw)
	parts := make([]string, len(sum))
	for i, value := range sum {
		parts[i] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, ":")
}

func NormalizeFingerprint(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "")
	value = strings.ReplaceAll(value, "-", ":")
	return value
}

func EqualFingerprint(a, b string) bool {
	return NormalizeFingerprint(a) == NormalizeFingerprint(b)
}

func BaseTLSConfig(certificate *tls.Certificate) *tls.Config {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{protocol.ALPN},
	}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return config
}

type Trust interface {
	Check(host, fingerprint string) error
	Save(host, fingerprint string) error
}

// TrustError identifies certificate trust failures. Callers can use it to
// distinguish permanent trust decisions from transient network failures.
type TrustError struct {
	Err error
}

func (e *TrustError) Error() string {
	return e.Err.Error()
}

func (e *TrustError) Unwrap() error {
	return e.Err
}

func IsTrustError(err error) bool {
	var trustErr *TrustError
	return errors.As(err, &trustErr)
}

func ClientTLSConfig(expectedFingerprint string, trust Trust, host string) *tls.Config {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{protocol.ALPN},
		InsecureSkipVerify: true,
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return &TrustError{Err: errors.New("server did not present a certificate")}
		}
		actual := Fingerprint(state.PeerCertificates[0])
		if expectedFingerprint != "" {
			if !EqualFingerprint(expectedFingerprint, actual) {
				return &TrustError{Err: fmt.Errorf("server certificate fingerprint changed: expected %s, got %s", expectedFingerprint, actual)}
			}
			return nil
		}
		if trust == nil {
			return &TrustError{Err: errors.New("server is not trusted and no trust store is available")}
		}
		if err := trust.Save(host, actual); err != nil {
			return &TrustError{Err: err}
		}
		return nil
	}
	return config
}

func DialTLS(ctx context.Context, address string, config *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

func FingerprintBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func ListenQUIC(address string, config *tls.Config) (*quic.Listener, *net.UDPConn, error) {
	udpAddress, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return nil, nil, err
	}
	listener, err := quic.Listen(conn, config, &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 16,
		Allow0RTT:             false,
	})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	return listener, conn, nil
}

func ListenTLS(address string, config *tls.Config) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

func DialQUIC(ctx context.Context, address string, config *tls.Config) (*quic.Conn, error) {
	return quic.DialAddr(ctx, address, config, &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 16,
		Allow0RTT:             false,
	})
}

func AcceptQUIC(ctx context.Context, listener *quic.Listener) (*quic.Conn, error) {
	return listener.Accept(ctx)
}

func OpenControlStream(ctx context.Context, connection *quic.Conn) (*quic.Stream, error) {
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(deadline)
		defer stream.SetWriteDeadline(time.Time{})
	}
	if err := protocol.WriteFrame(stream, protocol.Frame{Type: protocol.FrameStreamReady}); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("write QUIC control readiness: %w", err)
	}
	return stream, nil
}

func AcceptControlStream(ctx context.Context, connection *quic.Conn) (*quic.Stream, error) {
	stream, err := connection.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetReadDeadline(deadline)
		defer stream.SetReadDeadline(time.Time{})
	}
	frame, err := protocol.ReadFrame(stream)
	if err != nil {
		return nil, fmt.Errorf("read QUIC control readiness: %w", err)
	}
	if frame.Type != protocol.FrameStreamReady || frame.ID != 0 || len(frame.Payload) != 0 {
		return nil, fmt.Errorf("invalid QUIC control readiness frame: type=%d id=%d payload=%d", frame.Type, frame.ID, len(frame.Payload))
	}
	return stream, nil
}

func StreamConn(stream *quic.Stream) Conn {
	return &streamConn{stream: stream}
}
