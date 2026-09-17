package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lnproxy/internal/protocol"
	"lnproxy/internal/proxy"
	"lnproxy/internal/proxy/httpconnect"
	"lnproxy/internal/proxy/socks5"
	"lnproxy/internal/systemproxy"
)

type RuntimeConfig struct {
	DataDirectory string
	SOCKS5        bool
	IdleTimeout   time.Duration
	Logger        *slog.Logger
}

type Runtime struct {
	config RuntimeConfig
	logger *slog.Logger

	mu          sync.Mutex
	manager     *Manager
	systemProxy systemproxy.SystemProxy
	httpServer  *httpconnect.Server
	socksServer *socks5.Server
	journalPath string
	journal     systemproxy.Journal
	hasJournal  bool
	httpAddr    string
	socksAddr   string
	exitID      string
	fallback    bool
	started     bool
	stopped     bool
	closed      bool
	active      atomic.Int64
}

func NewRuntime(config RuntimeConfig, manager *Manager) *Runtime {
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	return &Runtime{
		config:      config,
		logger:      config.Logger,
		manager:     manager,
		systemProxy: systemproxy.New(),
		exitID:      "auto",
	}
}

func (r *Runtime) Start(ctx context.Context, sAddress string, passphrase string) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("client runtime is shut down")
	}
	if r.started {
		r.mu.Unlock()
		return errors.New("client runtime is already started")
	}
	r.mu.Unlock()

	if err := r.recoverJournal(ctx); err != nil {
		r.markStopped()
		return fmt.Errorf("recover stale proxy journal: %w", err)
	}
	if err := r.manager.Connect(ctx, sAddress, passphrase); err != nil {
		r.markStopped()
		return err
	}
	r.mu.Lock()
	r.started = true
	r.mu.Unlock()
	dialer := &managerDialer{manager: r.manager, runtime: r}
	httpServer := httpconnect.New(dialer, r.logger, r.config.IdleTimeout)
	httpAddress, err := httpServer.Start("127.0.0.1:0")
	if err != nil {
		_ = r.manager.Close()
		r.markStopped()
		return err
	}
	r.httpServer = httpServer
	r.httpAddr = httpAddress.String()

	if r.config.SOCKS5 {
		socksServer := socks5.New(dialer, r.logger, r.config.IdleTimeout)
		socksAddress, err := socksServer.Start("127.0.0.1:0")
		if err != nil {
			_ = httpServer.Close()
			_ = r.manager.Close()
			r.markStopped()
			return err
		}
		r.socksServer = socksServer
		r.socksAddr = socksAddress.String()
	}

	endpoint := systemproxy.Endpoint{HTTP: r.httpAddr, HTTPS: r.httpAddr}
	if r.socksAddr != "" {
		endpoint.SOCKS = r.socksAddr
	}
	snapshot, err := r.systemProxy.Snapshot(ctx)
	if err != nil {
		if errors.Is(err, systemproxy.ErrUnsupported) {
			r.logger.Warn("system proxy settings left unchanged", "reason", err)
		} else {
			r.markStopped()
			return err
		}
	} else {
		journal := systemproxy.Journal{
			Version: 1,
			PID:     os.Getpid(),
			Applied: endpoint,
			Before:  snapshot,
			Time:    time.Now(),
		}
		journalPath := systemproxy.JournalPath(r.config.DataDirectory)
		if err := systemproxy.WriteJournal(journalPath, journal); err != nil {
			r.markStopped()
			return fmt.Errorf("write proxy journal: %w", err)
		}
		if err := r.systemProxy.Apply(ctx, endpoint); err != nil {
			_ = systemproxy.RemoveJournal(journalPath)
			if errors.Is(err, systemproxy.ErrUnsupported) {
				r.logger.Warn("system proxy settings left unchanged", "reason", err)
			} else {
				r.markStopped()
				return fmt.Errorf("apply system proxy: %w", err)
			}
		} else {
			r.journalPath = journalPath
			r.journal = journal
			r.hasJournal = true
		}
	}
	return nil
}

func (r *Runtime) markStopped() {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
}

func (r *Runtime) ProxyAddress() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.httpAddr
}

func (r *Runtime) SOCKSAddress() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.socksAddr
}

func (r *Runtime) SetExit(exitID string, fallback bool) error {
	exitID = strings.TrimSpace(exitID)
	if exitID == "" {
		return errors.New("exit ID is required")
	}
	if exitID != "auto" {
		found := false
		for _, exit := range r.manager.Catalog() {
			if exit.ID == exitID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown exit %q", exitID)
		}
	}
	r.mu.Lock()
	r.exitID = exitID
	r.fallback = fallback
	r.mu.Unlock()
	return nil
}

func (r *Runtime) ExitID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitID
}

func (r *Runtime) Fallback() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fallback
}

func (r *Runtime) Shutdown(ctx context.Context, drain time.Duration) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	httpServer := r.httpServer
	socksServer := r.socksServer
	r.mu.Unlock()

	if httpServer != nil {
		_ = httpServer.Close()
	}
	if socksServer != nil {
		_ = socksServer.Close()
	}
	if drain > 0 {
		deadline := time.NewTimer(drain)
		ticker := time.NewTicker(20 * time.Millisecond)
		waiting := true
		for waiting {
			select {
			case <-deadline.C:
				waiting = false
			case <-ticker.C:
				waiting = r.active.Load() > 0
			case <-ctx.Done():
				waiting = false
			}
		}
		ticker.Stop()
		if !deadline.Stop() {
			select {
			case <-deadline.C:
			default:
			}
		}
	}
	_ = r.manager.Close()
	return r.restoreProxy(ctx)
}

func (r *Runtime) restoreProxy(ctx context.Context) error {
	r.mu.Lock()
	if !r.hasJournal {
		r.mu.Unlock()
		return nil
	}
	journal := r.journal
	path := r.journalPath
	r.mu.Unlock()

	current, err := r.systemProxy.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshot current proxy settings: %w", err)
	}
	applied, err := proxyMatches(ctx, r.systemProxy, current, journal.Applied)
	if err != nil {
		return fmt.Errorf("verify applied proxy settings: %w", err)
	}
	if !applied {
		return errors.New("system proxy settings changed externally; journal preserved")
	}
	if err := r.systemProxy.Restore(ctx, journal.Before); err != nil {
		return fmt.Errorf("restore system proxy settings: %w", err)
	}
	if err := systemproxy.RemoveJournal(path); err != nil {
		return err
	}
	r.mu.Lock()
	r.hasJournal = false
	r.mu.Unlock()
	return nil
}

func (r *Runtime) recoverJournal(ctx context.Context) error {
	path := systemproxy.JournalPath(r.config.DataDirectory)
	journal, err := systemproxy.ReadJournal(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := r.systemProxy.Restore(ctx, journal.Before); err != nil {
		return err
	}
	return systemproxy.RemoveJournal(path)
}

type managerDialer struct {
	manager *Manager
	runtime *Runtime
}

func (d *managerDialer) Dial(ctx context.Context, host string, port uint16) (proxy.Stream, error) {
	request := protocol.OpenRequest{
		Destination: host,
		Port:        port,
		Protocol:    protocol.ProtocolTCP,
		ExitID:      d.runtime.ExitID(),
	}
	stream, err := d.manager.Dial(ctx, request)
	if err == nil {
		d.runtime.active.Add(1)
		return &countedStream{Stream: stream, active: &d.runtime.active}, nil
	}
	if d.runtime.Fallback() && request.ExitID != "auto" {
		request.ExitID = "auto"
		stream, fallbackErr := d.manager.Dial(ctx, request)
		if fallbackErr == nil {
			d.runtime.active.Add(1)
			return &countedStream{Stream: stream, active: &d.runtime.active}, nil
		}
		return nil, fallbackErr
	}
	return nil, err
}

type countedStream struct {
	proxy.Stream
	active *atomic.Int64
	once   sync.Once
}

func (s *countedStream) Close() error {
	var err error
	s.once.Do(func() {
		err = s.Stream.Close()
		s.active.Add(-1)
	})
	return err
}

func (d *managerDialer) Close() error {
	return d.manager.Close()
}

func proxyMatches(ctx context.Context, provider systemproxy.SystemProxy, snapshot systemproxy.Snapshot, endpoint systemproxy.Endpoint) (bool, error) {
	if matcher, ok := provider.(systemproxy.StateMatcher); ok {
		return matcher.Matches(ctx, snapshot, endpoint)
	}
	return false, errors.New("system proxy implementation cannot verify applied settings")
}
