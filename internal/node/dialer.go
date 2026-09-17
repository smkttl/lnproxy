package node

import (
	"context"
	"errors"
	"net"
	"time"
)

func DialDestination(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if host == "" || port == 0 {
		return nil, errors.New("destination and port are required")
	}
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, portString(port)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func portString(port uint16) string {
	var buf [5]byte
	i := len(buf)
	for port > 0 {
		i--
		buf[i] = byte('0' + port%10)
		port /= 10
	}
	if i == len(buf) {
		i--
		buf[i] = '0'
	}
	return string(buf[i:])
}
