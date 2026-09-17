package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	Version      = 2
	MaxFrameSize = 1 << 20
	MaxDataSize  = 64 << 10
	headerSize   = 13
	ProtocolTCP  = "tcp"
	ProtocolQUIC = "quic"
	ProtocolTLS  = "tls"
	ALPN         = "lnproxy/2"
)

type FrameType uint8

const (
	FrameChallenge FrameType = iota + 1
	FrameAuthResponse
	FrameAuthResult
	FrameRegister
	FrameHeartbeat
	FrameCatalog
	FrameOpen
	FrameOpenAck
	FrameData
	FrameClose
	FrameError
	FrameStreamReady
)

type Frame struct {
	Type    FrameType
	ID      uint64
	Payload []byte
}

type OpenRequest struct {
	RequestID      uint64 `json:"request_id"`
	ExitID         string `json:"exit_id,omitempty"`
	Destination    string `json:"destination_host"`
	Port           uint16 `json:"destination_port"`
	Protocol       string `json:"protocol"`
	ClientSelected bool   `json:"client_selected,omitempty"`
}

type Ack struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	ExitID  string `json:"exit_id,omitempty"`
	Message string `json:"message,omitempty"`
}

type AuthResponse struct {
	Version   int    `json:"version"`
	Role      string `json:"role"`
	Response  []byte `json:"response"`
	SessionID string `json:"session_id,omitempty"`
}

type AuthResult struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Version int    `json:"version"`
}

type ExitRegistration struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Capacity int      `json:"capacity"`
	Features []string `json:"features,omitempty"`
}

type Heartbeat struct {
	ExitID      string `json:"exit_id"`
	Active      int    `json:"active"`
	Capacity    int    `json:"capacity"`
	TimestampMS int64  `json:"timestamp_ms"`
}

type ErrorMessage struct {
	Message string `json:"message"`
}

func ReadFrame(r io.Reader) (Frame, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	size := binary.BigEndian.Uint32(header[9:13])
	if size > MaxFrameSize {
		return Frame{}, fmt.Errorf("frame size %d exceeds limit", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Type:    FrameType(header[0]),
		ID:      binary.BigEndian.Uint64(header[1:9]),
		Payload: payload,
	}, nil
}

func WriteFrame(w io.Writer, frame Frame) error {
	if len(frame.Payload) > MaxFrameSize {
		return fmt.Errorf("frame size %d exceeds limit", len(frame.Payload))
	}
	var header [headerSize]byte
	header[0] = byte(frame.Type)
	binary.BigEndian.PutUint64(header[1:9], frame.ID)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(frame.Payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(frame.Payload) == 0 {
		return nil
	}
	_, err := w.Write(frame.Payload)
	return err
}

type Writer struct {
	mu sync.Mutex
	w  io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

func (w *Writer) Write(frame Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return WriteFrame(w.w, frame)
}

func (w *Writer) WriteJSON(frameType FrameType, id uint64, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return w.Write(Frame{Type: frameType, ID: id, Payload: payload})
}

func DecodeJSON[T any](frame Frame) (T, error) {
	var value T
	if err := json.Unmarshal(frame.Payload, &value); err != nil {
		return value, err
	}
	return value, nil
}

func DecodeOpen(frame Frame) (OpenRequest, error) {
	request, err := DecodeJSON[OpenRequest](frame)
	if err != nil {
		return OpenRequest{}, err
	}
	if request.RequestID == 0 {
		request.RequestID = frame.ID
	}
	if request.Protocol == "" {
		request.Protocol = ProtocolTCP
	}
	if request.Destination == "" || request.Port == 0 {
		return OpenRequest{}, errors.New("destination and port are required")
	}
	if request.Protocol != ProtocolTCP {
		return OpenRequest{}, fmt.Errorf("unsupported protocol %q", request.Protocol)
	}
	return request, nil
}
