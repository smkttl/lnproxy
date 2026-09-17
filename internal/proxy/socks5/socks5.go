package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"lnproxy/internal/proxy"
)

const (
	version5       = 5
	methodNoAuth   = 0
	methodNone     = 0xff
	commandConnect = 1
	addressIPv4    = 1
	addressDomain  = 3
	addressIPv6    = 4
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
				s.logger.Error("SOCKS5 accept failed", "error", err)
			}
			return
		}
		go s.handle(connection)
	}
}

func (s *Server) handle(connection net.Conn) {
	defer connection.Close()
	proxy.ApplyIdleDeadline(connection, s.timeout)
	if err := negotiate(connection); err != nil {
		return
	}
	host, port, err := readRequest(connection)
	if err != nil {
		_ = writeReply(connection, 7, nil)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	target, err := s.dialer.Dial(ctx, host, port)
	cancel()
	if err != nil {
		_ = writeReply(connection, 5, nil)
		return
	}
	defer target.Close()
	if err := writeReply(connection, 0, nil); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	proxy.Relay(connection, target)
}

func negotiate(connection net.Conn) error {
	var header [2]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return err
	}
	if header[0] != version5 || header[1] == 0 {
		return errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	for _, method := range methods {
		if method == methodNoAuth {
			_, err := connection.Write([]byte{version5, methodNoAuth})
			return err
		}
	}
	_, _ = connection.Write([]byte{version5, methodNone})
	return errors.New("no supported SOCKS5 authentication method")
}

func readRequest(connection net.Conn) (string, uint16, error) {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return "", 0, err
	}
	if header[0] != version5 || header[1] != commandConnect || header[2] != 0 {
		return "", 0, errors.New("unsupported SOCKS5 request")
	}
	var host string
	switch header[3] {
	case addressIPv4:
		value := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(connection, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case addressIPv6:
		value := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(connection, value); err != nil {
			return "", 0, err
		}
		host = net.IP(value).String()
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(connection, length[:]); err != nil {
			return "", 0, err
		}
		if length[0] == 0 {
			return "", 0, errors.New("empty SOCKS5 destination")
		}
		value := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, value); err != nil {
			return "", 0, err
		}
		host = string(value)
	default:
		return "", 0, errors.New("unsupported SOCKS5 address type")
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(connection, portBytes[:]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", 0, errors.New("invalid SOCKS5 destination port")
	}
	return host, port, nil
}

func writeReply(connection net.Conn, status byte, address net.Addr) error {
	response := []byte{version5, status, 0, addressIPv4, 0, 0, 0, 0, 0, 0}
	if tcpAddress, ok := address.(*net.TCPAddr); ok && tcpAddress != nil {
		ip := tcpAddress.IP
		if ipv4 := ip.To4(); ipv4 != nil {
			copy(response[4:8], ipv4)
		} else if ipv6 := ip.To16(); ipv6 != nil {
			response = append([]byte{version5, status, 0, addressIPv6}, ipv6...)
			response = append(response, 0, 0)
		}
		if tcpAddress.Port > 0 {
			port := strconv.Itoa(tcpAddress.Port)
			_ = port
		}
	}
	_, err := connection.Write(response)
	return err
}
