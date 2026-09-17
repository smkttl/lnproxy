package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/protocol"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"

	"github.com/quic-go/quic-go"
)

type Server struct {
	config   config.Node
	verifier auth.Verifier
	tls      *tls.Config
	logger   *slog.Logger
	registry *Registry

	mu          sync.Mutex
	clientConns map[*session.Session]struct{}
	exitConns   map[string]*exitConn
	directID    string
	limiter     *auth.RateLimiter
	listenReady chan net.Addr
}

type exitConn struct {
	id      string
	session *session.Session
	name    string
}

func NewServer(cfg config.Node, verifier auth.Verifier, tlsConfig *tls.Config, logger *slog.Logger) *Server {
	server := &Server{
		config:      cfg,
		verifier:    verifier,
		tls:         tlsConfig,
		logger:      logger,
		registry:    NewRegistry(45 * time.Second),
		clientConns: make(map[*session.Session]struct{}),
		exitConns:   make(map[string]*exitConn),
		directID:    "direct",
		limiter:     auth.NewRateLimiter(5, time.Minute, 30*time.Second),
		listenReady: make(chan net.Addr, 1),
	}
	if cfg.Role == config.RoleServer || cfg.Role == config.RoleServerExit {
		server.registry.AddPersistent(protocol.ExitInfo{
			ID:        server.directID,
			Name:      "server",
			Type:      "direct",
			LatencyMS: 1,
			Capacity:  cfg.ConnectionLimit,
			Features:  []string{"tcp"},
		}, "healthy")
	}
	return server
}

func (s *Server) Run(ctx context.Context) error {
	if s.config.ListenAddress == "" {
		return errors.New("listen address is required")
	}
	quicListener, udpConn, err := transport.ListenQUIC(s.config.ListenAddress, s.tls)
	if err != nil {
		return fmt.Errorf("listen QUIC: %w", err)
	}
	listenAddress := quicListener.Addr().String()
	tcpListener, err := transport.ListenTLS(listenAddress, s.tls)
	if err != nil {
		_ = quicListener.Close()
		_ = udpConn.Close()
		return fmt.Errorf("listen TLS: %w", err)
	}
	s.logger.Info("server listening", "address", listenAddress)
	select {
	case s.listenReady <- tcpListener.Addr():
	default:
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	go s.acceptQUIC(runCtx, quicListener, errCh)
	go s.acceptTCP(runCtx, tcpListener, errCh)
	go s.catalogLoop(runCtx)

	select {
	case <-ctx.Done():
		_ = tcpListener.Close()
		_ = quicListener.Close()
		_ = udpConn.Close()
		return ctx.Err()
	case err := <-errCh:
		cancel()
		_ = tcpListener.Close()
		_ = quicListener.Close()
		_ = udpConn.Close()
		if errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	}
}

func (s *Server) Ready() <-chan net.Addr {
	return s.listenReady
}

func (s *Server) acceptQUIC(ctx context.Context, listener *quic.Listener, errCh chan<- error) {
	for {
		connection, err := transport.AcceptQUIC(ctx, listener)
		if err != nil {
			errCh <- err
			return
		}
		go func() {
			stream, err := transport.AcceptControlStream(ctx, connection)
			if err != nil {
				_ = connection.CloseWithError(0, "control stream failed")
				return
			}
			remote := connection.RemoteAddr().String()
			if err := s.handleConnection(ctx, transport.StreamConn(stream), remote, func() {
				_ = connection.CloseWithError(0, "closed")
			}); err != nil {
				s.logger.Info("connection closed", "remote", remote, "error", err)
			}
		}()
	}
}

func (s *Server) acceptTCP(ctx context.Context, listener net.Listener, errCh chan<- error) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		go func() {
			if err := s.handleConnection(ctx, connection, connection.RemoteAddr().String(), nil); err != nil {
				s.logger.Info("connection closed", "remote", connection.RemoteAddr(), "error", err)
			}
		}()
	}
}

func (s *Server) handleConnection(ctx context.Context, conn transport.Conn, remote string, closeFallback func()) error {
	key := remoteHost(remote)
	if err := s.limiter.Allowed(key); err != nil {
		_ = conn.Close()
		return err
	}
	response, err := auth.ServerHandshake(conn, s.verifier, "")
	if err != nil {
		s.limiter.Fail(key)
		if closeFallback != nil {
			closeFallback()
		} else {
			_ = conn.Close()
		}
		return err
	}
	s.limiter.Success(key)
	if s.connectionCount() >= s.config.ConnectionLimit {
		if closeFallback != nil {
			closeFallback()
		} else {
			_ = conn.Close()
		}
		return errors.New("connection limit reached")
	}
	switch response.Role {
	case auth.RoleClient:
		return s.handleClient(ctx, conn, remote)
	case auth.RoleExit:
		return s.handleExit(ctx, conn, remote)
	default:
		_ = conn.Close()
		return fmt.Errorf("unsupported authenticated role %q", response.Role)
	}
}

func (s *Server) connectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.clientConns) + len(s.exitConns)
}

func (s *Server) handleClient(ctx context.Context, conn transport.Conn, remote string) error {
	sess := session.New(session.Config{IdleTimeout: s.config.IdleTimeout})
	handler := func(stream *session.Stream) {
		s.forwardOpen(ctx, sess, stream)
	}
	if err := sess.Start(ctx, func(context.Context) (transport.Conn, error) {
		return conn, nil
	}, handler); err != nil {
		_ = conn.Close()
		return err
	}
	s.mu.Lock()
	s.clientConns[sess] = struct{}{}
	s.mu.Unlock()
	s.logger.Info("client connected", "remote", remote)
	s.pushCatalog(sess)
	<-sess.Done()
	s.mu.Lock()
	delete(s.clientConns, sess)
	s.mu.Unlock()
	return sess.Err()
}

func (s *Server) handleExit(ctx context.Context, conn transport.Conn, remote string) error {
	sess := session.New(session.Config{IdleTimeout: s.config.IdleTimeout})
	if err := sess.Start(ctx, func(context.Context) (transport.Conn, error) {
		return conn, nil
	}, func(stream *session.Stream) {
		s.serveExitStream(stream)
	}); err != nil {
		_ = conn.Close()
		return err
	}
	registration, err := waitForRegistration(sess)
	if err != nil {
		_ = sess.Close()
		return err
	}
	if registration.ID == "" {
		registration.ID = s.config.ExitID
	}
	if registration.ID == "" {
		_ = sess.Close()
		return errors.New("exit registration has no ID")
	}
	if registration.Capacity <= 0 {
		registration.Capacity = s.config.ConnectionLimit
	}
	if registration.Name == "" {
		registration.Name = registration.ID
	}
	entry := &exitConn{id: registration.ID, session: sess, name: registration.Name}
	sess.SetControlHandler(func(frame protocol.Frame) {
		if frame.Type != protocol.FrameHeartbeat {
			return
		}
		heartbeat, err := protocol.DecodeJSON[protocol.Heartbeat](frame)
		if err != nil {
			return
		}
		heartbeat.ExitID = registration.ID
		s.registry.Heartbeat(heartbeat)
	})
	s.mu.Lock()
	if old := s.exitConns[registration.ID]; old != nil {
		_ = old.session.Close()
	}
	s.exitConns[registration.ID] = entry
	s.mu.Unlock()
	s.registry.Add(protocol.ExitInfo{
		ID:        registration.ID,
		Name:      registration.Name,
		Type:      "exit",
		LatencyMS: 10,
		Capacity:  registration.Capacity,
		Features:  registration.Features,
	}, "healthy")
	s.logger.Info("exit connected", "id", registration.ID, "remote", remote)
	s.broadcastCatalog()
	<-sess.Done()
	s.mu.Lock()
	if s.exitConns[registration.ID] == entry {
		delete(s.exitConns, registration.ID)
	}
	s.mu.Unlock()
	s.registry.Remove(registration.ID)
	s.broadcastCatalog()
	return sess.Err()
}

func (s *Server) serveExitStream(stream *session.Stream) {
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
	session.Relay(stream, destination)
}

func (s *Server) forwardOpen(ctx context.Context, client *session.Session, stream *session.Stream) {
	request := stream.Request()
	selected, err := s.registry.Select(request.ExitID, false)
	if err != nil {
		_ = stream.Reject(err.Error())
		return
	}
	if selected.ID == s.directID {
		destination, err := DialDestination(ctx, request.Destination, request.Port)
		if err != nil {
			_ = stream.Reject("destination unavailable: " + err.Error())
			return
		}
		if err := stream.Accept(); err != nil {
			_ = destination.Close()
			return
		}
		session.Relay(stream, destination)
		return
	}
	s.mu.Lock()
	exit := s.exitConns[selected.ID]
	s.mu.Unlock()
	if exit == nil {
		_ = stream.Reject(ErrExitUnavailable.Error())
		return
	}
	exitStream, err := exit.session.Dial(ctx, request)
	if err != nil {
		_ = stream.Reject("exit unavailable: " + err.Error())
		return
	}
	if err := stream.Accept(); err != nil {
		_ = exitStream.Close()
		return
	}
	session.Relay(stream, exitStream)
}

func (s *Server) pushCatalog(sess *session.Session) {
	if err := sess.WriteJSON(protocol.FrameCatalog, 0, protocol.Catalog{Exits: s.registry.Snapshot()}); err != nil {
		s.logger.Debug("catalog push failed", "error", err)
	}
}

func (s *Server) broadcastCatalog() {
	catalog := s.registry.Snapshot()
	s.mu.Lock()
	sessions := make([]*session.Session, 0, len(s.clientConns))
	for sess := range s.clientConns {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()
	for _, sess := range sessions {
		if err := sess.WriteJSON(protocol.FrameCatalog, 0, protocol.Catalog{Exits: catalog}); err != nil {
			s.logger.Debug("catalog push failed", "error", err)
		}
	}
}

func (s *Server) catalogLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			before := s.registry.Snapshot()
			after := s.registry.Expire()
			if len(before) != len(after) {
				s.broadcastCatalog()
			}
		case <-ctx.Done():
			return
		}
	}
}

func waitForRegistration(sess *session.Session) (protocol.ExitRegistration, error) {
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	registrationCh := make(chan protocol.ExitRegistration, 1)
	errCh := make(chan error, 1)
	sess.SetControlHandler(func(frame protocol.Frame) {
		switch frame.Type {
		case protocol.FrameRegister:
			registration, err := protocol.DecodeJSON[protocol.ExitRegistration](frame)
			if err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case registrationCh <- registration:
			default:
			}
		}
	})
	select {
	case registration := <-registrationCh:
		return registration, nil
	case err := <-errCh:
		return protocol.ExitRegistration{}, err
	case <-timeout.C:
		return protocol.ExitRegistration{}, errors.New("exit registration timed out")
	case <-sess.Done():
		return protocol.ExitRegistration{}, sess.Err()
	}
}

func remoteHost(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
