package httpconnect

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"lnproxy/internal/proxy"
)

type Server struct {
	dialer  proxy.Dialer
	logger  *slog.Logger
	timeout time.Duration

	mu       sync.Mutex
	listener net.Listener
	closed   bool
}

func New(dialer proxy.Dialer, logger *slog.Logger, timeout time.Duration) *Server {
	return &Server{dialer: dialer, logger: logger, timeout: timeout}
}

func (s *Server) Start(address string) (net.Addr, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	go s.serve()
	return listener.Addr(), nil
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *Server) serve() {
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if !closed {
				s.logger.Error("HTTP proxy accept failed", "error", err)
			}
			return
		}
		go s.handle(connection)
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	proxy.ApplyIdleDeadline(connection, s.timeout)
	reader := bufio.NewReader(connection)
	request, err := http.ReadRequest(reader)
	if err != nil {
		s.writeError(connection, http.StatusBadRequest, "malformed HTTP proxy request")
		return
	}
	if request.Method == http.MethodConnect {
		s.handleConnect(connection, request)
		return
	}
	s.handleHTTP(connection, reader, request)
}

func (s *Server) handleConnect(connection net.Conn, request *http.Request) {
	host, port, err := splitHostPort(request.Host, 443)
	if err != nil {
		s.writeError(connection, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target, err := s.dialer.Dial(ctx, host, port)
	if err != nil {
		s.writeError(connection, http.StatusBadGateway, "destination unavailable")
		return
	}
	if _, err := io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = target.Close()
		return
	}
	_ = connection.SetDeadline(time.Time{})
	proxy.Relay(connection, target)
}

func (s *Server) handleHTTP(connection net.Conn, reader *bufio.Reader, request *http.Request) {
	if request.URL == nil || request.URL.Host == "" {
		s.writeError(connection, http.StatusBadRequest, "absolute URL required")
		return
	}
	host, port, err := splitHostPort(request.URL.Host, defaultPort(request.URL.Scheme))
	if err != nil {
		s.writeError(connection, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	target, err := s.dialer.Dial(ctx, host, port)
	cancel()
	if err != nil {
		s.writeError(connection, http.StatusBadGateway, "destination unavailable")
		return
	}
	defer target.Close()
	request.RequestURI = ""
	request.URL.Scheme = ""
	request.URL.Host = ""
	request.Header.Del("Proxy-Connection")
	if err := request.Write(target); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	if request.Body != nil {
		_, _ = io.Copy(target, request.Body)
	}
	if closer, ok := target.(proxy.Stream); ok {
		_ = closer.CloseWrite()
	}
	_, _ = io.Copy(connection, target)
}

func (s *Server) writeError(writer io.Writer, status int, message string) {
	_ = writeResponse(writer, status, message)
}

func writeResponse(writer io.Writer, status int, message string) error {
	body := message + "\n"
	_, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		status, http.StatusText(status), len(body), body)
	return err
}

func splitHostPort(value string, fallback int) (string, uint16, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0, errors.New("destination host is required")
	}
	host := value
	portText := strconv.Itoa(fallback)
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
		portText = parsedPort
	} else if strings.Count(value, ":") == 1 {
		return "", 0, errors.New("invalid destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("invalid destination port")
	}
	return strings.Trim(host, "[]"), uint16(port), nil
}

func defaultPort(scheme string) int {
	if strings.EqualFold(scheme, "https") {
		return 443
	}
	return 80
}
