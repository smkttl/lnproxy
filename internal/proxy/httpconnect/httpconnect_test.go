package httpconnect

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"lnproxy/internal/protocol"
	"lnproxy/internal/proxy"
	"lnproxy/internal/session"
	"lnproxy/internal/transport"
)

type sessionDialer struct {
	client *session.Session
}

func (d *sessionDialer) Dial(ctx context.Context, host string, port uint16) (proxy.Stream, error) {
	return d.client.Dial(ctx, protocol.OpenRequest{
		Destination: host,
		Port:        port,
		Protocol:    protocol.ProtocolTCP,
	})
}

func (d *sessionDialer) Close() error {
	return nil
}

func TestCONNECT(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	client := session.New(session.Config{})
	server := session.New(session.Config{})
	if err := client.Start(context.Background(), func(context.Context) (transport.Conn, error) {
		return clientRaw, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(context.Background(), func(context.Context) (transport.Conn, error) {
		return serverRaw, nil
	}, func(stream *session.Stream) {
		if err := stream.Accept(); err != nil {
			return
		}
		_, _ = stream.Write([]byte("hello"))
		_ = stream.CloseWrite()
	}); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	defer server.Close()

	serverProxy := New(&sessionDialer{client: client}, nil, time.Minute)
	addr, err := serverProxy.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverProxy.Close()
	conn, err := net.Dial("tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 200 {
		t.Fatalf("status %d", response.StatusCode)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 5)
	if _, err := io.ReadFull(response.Body, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q", data)
	}
}
