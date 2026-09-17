package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"lnproxy/internal/protocol"
	"lnproxy/internal/transport"
)

type Handler func(*Stream)

type DialFunc func(context.Context) (transport.Conn, error)

type CloseWriter interface {
	CloseWrite() error
}

type Config struct {
	IdleTimeout time.Duration
	BufferSize  int
}

type Session struct {
	config  Config
	conn    transport.Conn
	writer  *protocol.Writer
	handler Handler
	control func(protocol.Frame)

	mu       sync.Mutex
	streams  map[uint64]*Stream
	incoming chan *Stream
	closed   bool
	err      error
	done     chan struct{}
	close    sync.Once
	wg       sync.WaitGroup
	nextID   atomic.Uint64
	readDone chan struct{}
}

func New(config Config) *Session {
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 5 * time.Minute
	}
	if config.BufferSize <= 0 {
		config.BufferSize = 32
	}
	return &Session{
		config:   config,
		streams:  make(map[uint64]*Stream),
		incoming: make(chan *Stream, 64),
		done:     make(chan struct{}),
		readDone: make(chan struct{}),
	}
}

func (s *Session) Start(ctx context.Context, dial DialFunc, handler Handler) error {
	if dial == nil {
		return errors.New("dial function is required")
	}
	conn, err := dial(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return net.ErrClosed
	}
	s.conn = conn
	s.writer = protocol.NewWriter(conn)
	s.handler = handler
	s.mu.Unlock()
	s.wg.Add(1)
	go s.readLoop()
	s.wg.Add(1)
	go s.dispatchLoop()
	return nil
}

func (s *Session) Done() <-chan struct{} {
	return s.done
}

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) Incoming() <-chan *Stream {
	return s.incoming
}

func (s *Session) SetControlHandler(handler func(protocol.Frame)) {
	s.mu.Lock()
	s.control = handler
	s.mu.Unlock()
}

func (s *Session) WriteJSON(frameType protocol.FrameType, id uint64, value any) error {
	return s.writeFrameJSON(frameType, id, value)
}

func (s *Session) ReadDone() <-chan struct{} {
	return s.readDone
}

func (s *Session) Open(ctx context.Context, request protocol.OpenRequest) (*Stream, error) {
	if request.Protocol == "" {
		request.Protocol = protocol.ProtocolTCP
	}
	requestID := s.nextID.Add(1)
	if request.RequestID == 0 {
		request.RequestID = requestID
	}
	stream := newStream(s, request.RequestID, s.config)
	s.mu.Lock()
	if s.closed || s.writer == nil {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	s.streams[request.RequestID] = stream
	writer := s.writer
	s.mu.Unlock()

	if err := writer.WriteJSON(protocol.FrameOpen, request.RequestID, request); err != nil {
		s.removeStream(stream, nil)
		stream.forceClose(err)
		return nil, err
	}
	select {
	case ack := <-stream.ack:
		if !ack.OK {
			s.removeStream(stream, nil)
			message := ack.Error
			if message == "" {
				message = "exit rejected connection"
			}
			stream.forceClose(errors.New(message))
			return nil, errors.New(message)
		}
		stream.remoteExit = ack.ExitID
		return stream, nil
	case <-stream.done:
		s.removeStream(stream, nil)
		err := stream.Err()
		if err == nil {
			err = errors.New("stream closed before acknowledgement")
		}
		return nil, err
	case <-ctx.Done():
		s.removeStream(stream, nil)
		stream.forceClose(ctx.Err())
		return nil, ctx.Err()
	case <-s.done:
		err := s.Err()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
}

func (s *Session) Accept(ctx context.Context) (*Stream, error) {
	select {
	case stream := <-s.incoming:
		return stream, nil
	case <-s.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Session) Dial(ctx context.Context, request protocol.OpenRequest) (*Stream, error) {
	return s.Open(ctx, request)
}

func (s *Session) Close() error {
	s.shutdown(net.ErrClosed)
	err := error(nil)
	s.mu.Lock()
	if s.conn != nil {
		err = s.conn.Close()
	}
	s.mu.Unlock()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func (s *Session) Wait() {
	<-s.done
	s.wg.Wait()
}

func (s *Session) readLoop() {
	defer func() {
		s.wg.Done()
		close(s.readDone)
	}()
	for {
		frame, err := protocol.ReadFrame(s.conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				s.shutdown(net.ErrClosed)
			} else {
				s.shutdown(err)
			}
			return
		}
		switch frame.Type {
		case protocol.FrameOpen:
			request, err := protocol.DecodeOpen(frame)
			if err != nil {
				_ = s.writeMessage(frame.ID, "invalid open request: "+err.Error())
				continue
			}
			stream := newStream(s, request.RequestID, s.config)
			stream.request = request
			s.mu.Lock()
			if s.closed {
				s.mu.Unlock()
				stream.forceClose(net.ErrClosed)
				continue
			}
			s.streams[request.RequestID] = stream
			s.mu.Unlock()
			s.dispatch(stream)
		case protocol.FrameOpenAck:
			ack, err := protocol.DecodeJSON[protocol.Ack](frame)
			if err != nil {
				s.shutdown(fmt.Errorf("decode open acknowledgement: %w", err))
				return
			}
			stream := s.lookup(frame.ID)
			if stream != nil {
				select {
				case stream.ack <- ack:
				default:
				}
			}
		case protocol.FrameData:
			stream := s.lookup(frame.ID)
			if stream == nil {
				_ = s.writeFrame(protocol.Frame{Type: protocol.FrameClose, ID: frame.ID})
				continue
			}
			if err := stream.deliver(frame.Payload); err != nil {
				stream.forceClose(err)
			}
		case protocol.FrameClose:
			stream := s.lookup(frame.ID)
			if stream != nil {
				stream.remoteClose()
			}
		case protocol.FrameError:
			message, _ := protocol.DecodeJSON[protocol.ErrorMessage](frame)
			stream := s.lookup(frame.ID)
			if stream != nil {
				stream.forceClose(errors.New(message.Message))
			}
		default:
			s.mu.Lock()
			handler := s.control
			s.mu.Unlock()
			if handler == nil {
				s.shutdown(fmt.Errorf("unexpected control frame %d", frame.Type))
				return
			}
			handler(frame)
		}
	}
}

func (s *Session) dispatch(stream *Stream) {
	select {
	case s.incoming <- stream:
	default:
		go func() {
			select {
			case s.incoming <- stream:
			case <-s.done:
				stream.forceClose(net.ErrClosed)
			}
		}()
	}
}

func (s *Session) dispatchLoop() {
	defer s.wg.Done()
	for {
		select {
		case stream := <-s.incoming:
			if s.handler != nil {
				s.wg.Add(1)
				go func() {
					defer s.wg.Done()
					s.handler(stream)
				}()
			}
		case <-s.done:
			return
		}
	}
}

func (s *Session) writeFrame(frame protocol.Frame) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.mu.Lock()
	writer := s.writer
	closed := s.closed
	s.mu.Unlock()
	if closed || writer == nil {
		return net.ErrClosed
	}
	return writer.Write(frame)
}

func (s *Session) writeMessage(id uint64, message string) error {
	return s.writeFrameJSON(protocol.FrameError, id, protocol.ErrorMessage{Message: message})
}

func (s *Session) writeFrameJSON(frameType protocol.FrameType, id uint64, value any) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	s.mu.Lock()
	writer := s.writer
	closed := s.closed
	s.mu.Unlock()
	if closed || writer == nil {
		return net.ErrClosed
	}
	return writer.WriteJSON(frameType, id, value)
}

func (s *Session) lookup(id uint64) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

func (s *Session) removeStream(stream *Stream, err error) {
	s.mu.Lock()
	if current := s.streams[stream.id]; current == stream {
		delete(s.streams, stream.id)
	}
	s.mu.Unlock()
	if err != nil {
		stream.forceClose(err)
	}
}

func (s *Session) shutdown(err error) {
	s.close.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.err = err
		streams := make([]*Stream, 0, len(s.streams))
		for _, stream := range s.streams {
			streams = append(streams, stream)
		}
		close(s.done)
		s.mu.Unlock()
		for _, stream := range streams {
			stream.forceClose(err)
		}
	})
}

type Stream struct {
	session *Session
	id      uint64
	config  Config
	done    chan struct{}
	ack     chan protocol.Ack
	reads   chan []byte

	mu         sync.Mutex
	readBuf    []byte
	readErr    error
	writeErr   error
	remoteExit string
	request    protocol.OpenRequest
	closed     bool
	remoteEOF  bool
	localEOF   bool
	closeOnce  sync.Once
}

func newStream(s *Session, id uint64, config Config) *Stream {
	return &Stream{
		session: s,
		id:      id,
		config:  config,
		done:    make(chan struct{}),
		ack:     make(chan protocol.Ack, 1),
		reads:   make(chan []byte, config.BufferSize),
	}
}

func (s *Stream) ID() uint64 {
	return s.id
}

func (s *Stream) ExitID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remoteExit
}

func (s *Stream) Request() protocol.OpenRequest {
	return s.request
}

func (s *Stream) Accept() error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	if err := s.session.writeFrameJSON(protocol.FrameOpenAck, s.id, protocol.Ack{OK: true, ExitID: s.remoteExit}); err != nil {
		s.forceClose(err)
		return err
	}
	return nil
}

func (s *Stream) Reject(message string) error {
	err := s.session.writeFrameJSON(protocol.FrameOpenAck, s.id, protocol.Ack{OK: false, Error: message})
	s.forceClose(errors.New(message))
	return err
}

func (s *Stream) Read(p []byte) (int, error) {
	for len(s.readBuf) == 0 {
		s.mu.Lock()
		err := s.readErr
		s.mu.Unlock()
		if err != nil {
			return 0, err
		}
		select {
		case data, ok := <-s.reads:
			if !ok {
				s.mu.Lock()
				err := s.readErr
				if err == nil {
					err = io.EOF
				}
				s.mu.Unlock()
				return 0, err
			}
			s.readBuf = data
		case <-s.done:
			s.mu.Lock()
			err := s.readErr
			s.mu.Unlock()
			if err == nil {
				err = net.ErrClosed
			}
			return 0, err
		}
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	err := s.writeErr
	closed := s.closed
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	if closed {
		return 0, net.ErrClosed
	}
	written := 0
	for written < len(p) {
		end := written + protocol.MaxDataSize
		if end > len(p) {
			end = len(p)
		}
		chunk := append([]byte(nil), p[written:end]...)
		if err := s.session.writeFrame(protocol.Frame{Type: protocol.FrameData, ID: s.id, Payload: chunk}); err != nil {
			s.forceClose(err)
			return written, err
		}
		written = end
	}
	return written, nil
}

func (s *Stream) Close() error {
	err := s.CloseWrite()
	return err
}

func (s *Stream) CloseWrite() error {
	s.mu.Lock()
	if s.closed || s.localEOF {
		s.mu.Unlock()
		return nil
	}
	s.localEOF = true
	s.mu.Unlock()
	return s.session.writeFrame(protocol.Frame{Type: protocol.FrameClose, ID: s.id})
}

func (s *Stream) finishClose() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		s.session.removeStream(s, nil)
		close(s.done)
	})
}

func (s *Stream) LocalAddr() net.Addr {
	return localAddr{}
}

func (s *Stream) RemoteAddr() net.Addr {
	return remoteAddr{exit: s.remoteExit, host: s.request.Destination, port: s.request.Port}
}

func (s *Stream) SetDeadline(time.Time) error {
	return nil
}

func (s *Stream) SetReadDeadline(time.Time) error {
	return nil
}

func (s *Stream) SetWriteDeadline(time.Time) error {
	return nil
}

func (s *Stream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return s.readErr
	}
	return s.writeErr
}

func (s *Stream) deliver(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	copyData := append([]byte(nil), data...)
	select {
	case s.reads <- copyData:
		return nil
	case <-s.done:
		return net.ErrClosed
	}
}

func (s *Stream) remoteClose() {
	s.mu.Lock()
	if s.remoteEOF {
		s.mu.Unlock()
		return
	}
	s.remoteEOF = true
	s.mu.Unlock()
	close(s.reads)
}

func (s *Stream) forceClose(err error) {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.writeErr == nil {
			s.writeErr = err
		}
		if s.readErr == nil {
			s.readErr = err
		}
		if !s.remoteEOF {
			s.remoteEOF = true
			close(s.reads)
		}
		s.mu.Unlock()
		s.session.removeStream(s, nil)
		close(s.done)
	})
}

type localAddr struct{}

func (localAddr) Network() string { return "lnproxy" }
func (localAddr) String() string  { return "local" }

type remoteAddr struct {
	exit string
	host string
	port uint16
}

func (a remoteAddr) Network() string { return "lnproxy" }
func (a remoteAddr) String() string {
	if a.exit == "" {
		return net.JoinHostPort(a.host, fmt.Sprintf("%d", a.port))
	}
	return fmt.Sprintf("%s via %s", net.JoinHostPort(a.host, fmt.Sprintf("%d", a.port)), a.exit)
}
