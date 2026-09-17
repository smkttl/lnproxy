package client

import (
	"context"
	"net"
	"testing"
	"time"

	"lnproxy/internal/protocol"
)

func TestStartSessionHandlesImmediateCatalog(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- protocol.NewWriter(serverConn).WriteJSON(
			protocol.FrameCatalog,
			0,
			protocol.Catalog{Exits: []protocol.ExitInfo{{ID: "direct", Capacity: 1}}},
		)
	}()

	manager := NewManager(nil)
	catalog := make(chan []protocol.ExitInfo, 1)
	manager.SetCatalogCallback(func(exits []protocol.ExitInfo) {
		catalog <- exits
	})
	sess, err := manager.startSession(context.Background(), clientConn)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	select {
	case exits := <-catalog:
		if len(exits) != 1 || exits[0].ID != "direct" {
			t.Fatalf("catalog = %#v", exits)
		}
	case <-time.After(time.Second):
		t.Fatal("catalog handler was not called")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	default:
	}
	select {
	case <-sess.Done():
		t.Fatalf("session closed: %v", sess.Err())
	default:
	}
}
