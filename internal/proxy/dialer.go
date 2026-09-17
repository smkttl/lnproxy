package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

type Stream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

type Dialer interface {
	Dial(ctx context.Context, host string, port uint16) (Stream, error)
	Close() error
}

type DialerFunc func(context.Context, string, uint16) (Stream, error)

func (f DialerFunc) Dial(ctx context.Context, host string, port uint16) (Stream, error) {
	return f(ctx, host, port)
}

func (f DialerFunc) Close() error {
	return nil
}

type closeWriter interface {
	CloseWrite() error
}

func Relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src io.ReadWriteCloser) {
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(closeWriter); ok {
			_ = closer.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

func ApplyIdleDeadline(conn net.Conn, timeout time.Duration) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}
}

var ErrUnsupported = errors.New("unsupported proxy request")
