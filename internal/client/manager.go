package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/protocol"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"
)

type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
)

type Trust interface {
	Get(host string) string
	Check(host, fingerprint string) error
	Save(host, fingerprint string) error
}

type Manager struct {
	mu         sync.Mutex
	address    string
	passphrase string
	trust      Trust
	forceTCP   bool
	transport  string
	session    *session.Session
	state      State
	lastError  error
	onState    func(State, error)
	onCatalog  func([]protocol.ExitInfo)
	catalog    []protocol.ExitInfo
	reconnect  bool
	closed     bool
}

func NewManager(trust Trust) *Manager {
	return &Manager{
		trust:     trust,
		state:     StateDisconnected,
		reconnect: true,
	}
}

func (m *Manager) SetReconnect(enabled bool) {
	m.mu.Lock()
	m.reconnect = enabled
	m.mu.Unlock()
}

func (m *Manager) SetStateCallback(callback func(State, error)) {
	m.mu.Lock()
	m.onState = callback
	m.mu.Unlock()
}

func (m *Manager) SetCatalogCallback(callback func([]protocol.ExitInfo)) {
	m.mu.Lock()
	m.onCatalog = callback
	catalog := append([]protocol.ExitInfo(nil), m.catalog...)
	m.mu.Unlock()
	if callback != nil && catalog != nil {
		callback(catalog)
	}
}

func (m *Manager) Connect(ctx context.Context, address, passphrase string) error {
	normalized, err := config.NormalizeServerAddress(address)
	if err != nil {
		return err
	}
	if passphrase == "" {
		return errors.New("passphrase cannot be empty")
	}
	m.mu.Lock()
	m.address = normalized
	m.passphrase = passphrase
	m.forceTCP = false
	m.mu.Unlock()
	return m.Reconnect(ctx)
}

// ConnectTCP uses the TLS-over-TCP control transport directly. It is useful
// where UDP is unavailable and for deterministic integration testing.
func (m *Manager) ConnectTCP(ctx context.Context, address, passphrase string) error {
	normalized, err := config.NormalizeServerAddress(address)
	if err != nil {
		return err
	}
	if passphrase == "" {
		return errors.New("passphrase cannot be empty")
	}
	m.mu.Lock()
	m.address = normalized
	m.passphrase = passphrase
	m.forceTCP = true
	m.mu.Unlock()
	return m.Reconnect(ctx)
}

func (m *Manager) Reconnect(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return errors.New("client manager is closed")
	}
	address := m.address
	passphrase := m.passphrase
	trust := m.trust
	oldSession := m.session
	m.session = nil
	forceTCP := m.forceTCP
	callback := m.onState
	m.state = StateConnecting
	m.lastError = nil
	m.mu.Unlock()
	if oldSession != nil {
		_ = oldSession.Close()
	}
	if address == "" || passphrase == "" {
		err := errors.New("not configured")
		m.setError(err)
		return err
	}
	if callback != nil {
		callback(StateConnecting, nil)
	}

	transportName, conn, err := m.connectTransport(ctx, address, trust, forceTCP)
	if err != nil {
		m.setError(err)
		return err
	}
	if err := auth.ClientHandshakePassword(conn, passphrase, auth.RoleClient); err != nil {
		_ = conn.Close()
		m.setError(err)
		return err
	}
	sess, err := m.startSession(ctx, conn)
	if err != nil {
		_ = conn.Close()
		m.setError(err)
		return err
	}
	m.mu.Lock()
	m.session = sess
	m.transport = transportName
	m.state = StateConnected
	m.lastError = nil
	callback = m.onState
	m.mu.Unlock()
	if callback != nil {
		callback(StateConnected, nil)
	}
	go m.sessionLoop(sess)
	return nil
}

func (m *Manager) startSession(ctx context.Context, conn transport.Conn) (*session.Session, error) {
	sess := session.New(session.Config{IdleTimeout: 5 * time.Minute})
	sess.SetControlHandler(func(frame protocol.Frame) {
		if frame.Type != protocol.FrameCatalog {
			return
		}
		catalog, err := protocol.DecodeJSON[protocol.Catalog](frame)
		if err != nil {
			return
		}
		m.mu.Lock()
		m.catalog = append([]protocol.ExitInfo(nil), catalog.Exits...)
		callback := m.onCatalog
		m.mu.Unlock()
		if callback != nil {
			callback(append([]protocol.ExitInfo(nil), catalog.Exits...))
		}
	})
	if err := sess.Start(ctx, func(context.Context) (transport.Conn, error) {
		return conn, nil
	}, nil); err != nil {
		return nil, err
	}
	return sess, nil
}

func (m *Manager) connectTransport(ctx context.Context, address string, trust Trust, forceTCP bool) (string, transport.Conn, error) {
	host := addressHost(address)
	expected := ""
	if trust != nil {
		expected = trust.Get(host)
	}
	var quicErr error
	if !forceTCP {
		quicConfig := transport.ClientTLSConfig(expected, trust, host)
		quicConn, err := transport.DialQUIC(ctx, address, quicConfig)
		if err == nil {
			stream, err := transport.OpenControlStream(ctx, quicConn)
			if err == nil {
				return protocol.ProtocolQUIC, transport.StreamConn(stream), nil
			}
			_ = quicConn.CloseWithError(0, "control stream failed")
			return "", nil, err
		}
		quicErr = err
	}
	tcpConfig := transport.ClientTLSConfig(expected, trust, host)
	tcpConn, tcpErr := transport.DialTLS(ctx, address, tcpConfig)
	if tcpErr == nil {
		return protocol.ProtocolTLS, tcpConn, nil
	}
	return "", nil, fmt.Errorf("QUIC failed: %v; TLS failed: %w", quicErr, tcpErr)
}

func (m *Manager) sessionLoop(sess *session.Session) {
	<-sess.Done()
	m.mu.Lock()
	if m.session != sess {
		m.mu.Unlock()
		return
	}
	m.session = nil
	m.state = StateDisconnected
	m.lastError = sess.Err()
	callback := m.onState
	m.mu.Unlock()
	if callback != nil {
		callback(StateDisconnected, sess.Err())
	}
	m.mu.Lock()
	reconnect := m.reconnect
	closed := m.closed
	m.mu.Unlock()
	if reconnect && !closed {
		go m.reconnectLoop()
	}
}

func (m *Manager) reconnectLoop() {
	delay := time.Second
	for attempt := 0; attempt < 6; attempt++ {
		timer := time.NewTimer(delay)
		<-timer.C
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := m.Reconnect(ctx)
		cancel()
		if err == nil {
			return
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

func (m *Manager) Dial(ctx context.Context, request protocol.OpenRequest) (*session.Stream, error) {
	m.mu.Lock()
	sess := m.session
	m.mu.Unlock()
	if sess == nil {
		return nil, errors.New("not connected to S")
	}
	return sess.Dial(ctx, request)
}

func (m *Manager) Close() error {
	m.mu.Lock()
	sess := m.session
	m.session = nil
	m.closed = true
	m.state = StateDisconnected
	m.mu.Unlock()
	if sess != nil {
		return sess.Close()
	}
	return nil
}

func (m *Manager) State() (State, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.transport, m.lastError
}

func (m *Manager) Catalog() []protocol.ExitInfo {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]protocol.ExitInfo(nil), m.catalog...)
}

func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.state = StateDisconnected
	m.lastError = err
	callback := m.onState
	m.mu.Unlock()
	if callback != nil {
		callback(StateDisconnected, err)
	}
}

func addressHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return host
}
