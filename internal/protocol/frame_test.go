package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []Frame{
		{Type: FrameData, ID: 42, Payload: []byte("payload")},
		{Type: FrameStreamReady},
	}
	for _, want := range tests {
		var buf bytes.Buffer
		if err := WriteFrame(&buf, want); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != want.Type || got.ID != want.ID || string(got.Payload) != string(want.Payload) {
			t.Fatalf("unexpected frame: %#v", got)
		}
	}
}

func TestOpenValidation(t *testing.T) {
	t.Parallel()
	if _, err := DecodeOpen(Frame{ID: 1, Payload: []byte(`{"destination_host":"","destination_port":80}`)}); err == nil {
		t.Fatal("expected missing destination to fail")
	}
	if _, err := DecodeOpen(Frame{ID: 1, Payload: []byte(`{"destination_host":"example.com","destination_port":80,"protocol":"udp"}`)}); err == nil {
		t.Fatal("expected UDP to fail")
	}
}
