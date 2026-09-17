package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/protocol"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"
)

type Exit struct {
	config     config.Node
	passphrase string
	tlsConfig  *tls.Config
	logger     *slog.Logger
	active     atomic.Int64
	forceTCP   bool
	trust      exitTrust
}

type exitTrust interface {
	transport.Trust
	Get(host string) string
}

func (e *Exit) UseTCP() {
	e.forceTCP = true
}

func (e *Exit) UseTrust(trust exitTrust) {
	e.trust = trust
}

func NewExit(cfg config.Node, passphrase string, tlsConfig *tls.Config, logger *slog.Logger) *Exit {
	return &Exit{
		config:     cfg,
		passphrase: passphrase,
		tlsConfig:  tlsConfig,
		logger:     logger,
	}
}

func (e *Exit) Run(ctx context.Context) error {
	delay := time.Second
	for {
		err := e.connectOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if transport.IsTrustError(err) {
			return err
		}
		e.logger.Warn("exit connection ended; reconnecting", "error", err, "delay", delay)
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

func (e *Exit) connectOnce(ctx context.Context) error {
	address, err := config.NormalizeServerAddress(e.config.ServerAddress)
	if err != nil {
		return err
	}
	host := addressHost(address)
	expected, trust := e.trustConfig(host)
	tlsConfig := transport.ClientTLSConfig(expected, trust, host)

	if !e.forceTCP {
		quicConn, err := transport.DialQUIC(ctx, address, tlsConfig)
		if err == nil {
			stream, err := transport.OpenControlStream(ctx, quicConn)
			if err == nil {
				return e.runConnection(ctx, transport.StreamConn(stream))
			}
			_ = quicConn.CloseWithError(0, "control stream failed")
			return err
		}
		if transport.IsTrustError(err) {
			return err
		}
		tcpConfig := transport.ClientTLSConfig(expected, trust, host)
		tcpConn, tcpErr := transport.DialTLS(ctx, address, tcpConfig)
		if tcpErr != nil {
			if transport.IsTrustError(tcpErr) {
				return tcpErr
			}
			return fmt.Errorf("connect to S over QUIC: %v; over TLS: %w", err, tcpErr)
		}
		return e.runConnection(ctx, tcpConn)
	}
	tcpConn, err := transport.DialTLS(ctx, address, tlsConfig)
	if err != nil {
		return err
	}
	return e.runConnection(ctx, tcpConn)
}

func (e *Exit) trustConfig(host string) (string, transport.Trust) {
	if e.config.ServerFingerprint != "" {
		return e.config.ServerFingerprint, nil
	}
	if e.trust != nil {
		return e.trust.Get(host), e.trust
	}
	return "", nil
}

func (e *Exit) runConnection(ctx context.Context, conn transport.Conn) error {
	if err := auth.ClientHandshakePassword(conn, e.passphrase, auth.RoleExit); err != nil {
		_ = conn.Close()
		return err
	}
	sess := session.New(session.Config{IdleTimeout: e.config.IdleTimeout})
	if err := sess.Start(ctx, func(context.Context) (transport.Conn, error) {
		return conn, nil
	}, func(stream *session.Stream) {
		e.serve(stream)
	}); err != nil {
		_ = conn.Close()
		return err
	}
	registration := protocol.ExitRegistration{
		ID:       e.config.ExitID,
		Name:     e.config.ExitName,
		Capacity: e.config.Capacity,
		Features: []string{"tcp"},
	}
	if err := sess.WriteJSON(protocol.FrameRegister, 0, registration); err != nil {
		_ = sess.Close()
		return err
	}
	e.logger.Info("connected to server", "server", e.config.ServerAddress, "exit_id", registration.ID)
	heartbeatCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go e.heartbeatLoop(heartbeatCtx, sess)
	<-sess.Done()
	if err := sess.Err(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (e *Exit) serve(stream *session.Stream) {
	request := stream.Request()
	destination, err := DialDestination(context.Background(), request.Destination, request.Port)
	if err != nil {
		_ = stream.Reject("destination unavailable: " + err.Error())
		return
	}
	if err := stream.Accept(); err != nil {
		_ = destination.Close()
		return
	}
	e.active.Add(1)
	defer e.active.Add(-1)
	session.Relay(stream, destination)
}

func (e *Exit) heartbeatLoop(ctx context.Context, sess *session.Session) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			heartbeat := protocol.Heartbeat{
				ExitID:      e.config.ExitID,
				Active:      int(e.active.Load()),
				Capacity:    e.config.Capacity,
				TimestampMS: time.Now().UnixMilli(),
			}
			if err := sess.WriteJSON(protocol.FrameHeartbeat, 0, heartbeat); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func addressHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
