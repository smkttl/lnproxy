package auth

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"lnproxy/internal/protocol"
)

const (
	RoleClient = "client"
	RoleExit   = "exit"
)

type challengePayload struct {
	Version     int    `json:"version"`
	Nonce       []byte `json:"nonce"`
	Salt        []byte `json:"salt"`
	Iterations  uint32 `json:"iterations"`
	Memory      uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

func makeChallenge(verifier Verifier) ([]byte, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return json.Marshal(challengePayload{
		Version:     protocol.Version,
		Nonce:       nonce,
		Salt:        verifier.Salt,
		Iterations:  verifier.Params.Iterations,
		Memory:      verifier.Params.Memory,
		Parallelism: verifier.Params.Parallelism,
	})
}

func decodeChallenge(payload []byte) (challengePayload, error) {
	var challenge challengePayload
	if err := json.Unmarshal(payload, &challenge); err != nil {
		return challenge, err
	}
	if challenge.Version != protocol.Version || len(challenge.Nonce) < 16 || len(challenge.Salt) < 8 ||
		challenge.Iterations < 1 || challenge.Iterations > 10 ||
		challenge.Memory < 8*1024 || challenge.Memory > 1024*1024 ||
		challenge.Parallelism < 1 || challenge.Parallelism > 16 {
		return challenge, errors.New("invalid authentication challenge")
	}
	return challenge, nil
}

func ServerHandshake(rw io.ReadWriter, verifier Verifier, roleLimit string) (protocol.AuthResponse, error) {
	challenge, err := makeChallenge(verifier)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	writer := protocol.NewWriter(rw)
	if err := writer.Write(protocol.Frame{Type: protocol.FrameChallenge, Payload: challenge}); err != nil {
		return protocol.AuthResponse{}, err
	}
	frame, err := protocol.ReadFrame(rw)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	if frame.Type != protocol.FrameAuthResponse {
		return protocol.AuthResponse{}, fmt.Errorf("expected auth response, got frame %d", frame.Type)
	}
	response, err := protocol.DecodeJSON[protocol.AuthResponse](frame)
	if err != nil {
		return protocol.AuthResponse{}, fmt.Errorf("decode auth response: %w", err)
	}
	decoded, err := decodeChallenge(challenge)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	ok := response.Version == protocol.Version &&
		verifier.VerifyChallenge(decoded.Nonce, response.Response) &&
		(roleLimit == "" || roleLimit == response.Role)
	result := protocol.AuthResult{
		OK:      ok,
		Version: protocol.Version,
	}
	if !ok {
		result.Error = ErrInvalidPassword.Error()
	}
	if err := writer.WriteJSON(protocol.FrameAuthResult, 0, result); err != nil {
		return response, err
	}
	if !ok {
		return response, ErrInvalidPassword
	}
	return response, nil
}

func ClientHandshake(rw io.ReadWriter, verifier Verifier, role string) error {
	frame, err := protocol.ReadFrame(rw)
	if err != nil {
		return err
	}
	if frame.Type != protocol.FrameChallenge {
		return fmt.Errorf("expected challenge, got frame %d", frame.Type)
	}
	challenge, err := decodeChallenge(frame.Payload)
	if err != nil {
		return err
	}
	response := protocol.AuthResponse{
		Version:  protocol.Version,
		Role:     role,
		Response: verifier.ChallengeResponse(challenge.Nonce),
	}
	writer := protocol.NewWriter(rw)
	if err := writer.WriteJSON(protocol.FrameAuthResponse, 0, response); err != nil {
		return err
	}
	resultFrame, err := protocol.ReadFrame(rw)
	if err != nil {
		return err
	}
	if resultFrame.Type != protocol.FrameAuthResult {
		return fmt.Errorf("expected authentication result, got frame %d", resultFrame.Type)
	}
	result, err := protocol.DecodeJSON[protocol.AuthResult](resultFrame)
	if err != nil {
		return err
	}
	if result.Version != protocol.Version {
		return fmt.Errorf("protocol version mismatch: server uses %d", result.Version)
	}
	if !result.OK {
		if result.Error == "" {
			result.Error = ErrInvalidPassword.Error()
		}
		return ErrInvalidPassword
	}
	return nil
}

// ClientHandshakePassword derives the server's verifier from the public salt
// carried in the challenge. The passphrase itself is never transmitted.
func ClientHandshakePassword(rw io.ReadWriter, passphrase, role string) error {
	frame, err := protocol.ReadFrame(rw)
	if err != nil {
		return err
	}
	if frame.Type != protocol.FrameChallenge {
		return fmt.Errorf("expected challenge, got frame %d", frame.Type)
	}
	challenge, err := decodeChallenge(frame.Payload)
	if err != nil {
		return err
	}
	verifier := Verifier{
		Salt: challenge.Salt,
		Params: Parameters{
			Memory:      challenge.Memory,
			Iterations:  challenge.Iterations,
			Parallelism: challenge.Parallelism,
		},
	}
	verifier.Hash = Derive(passphrase, verifier.Salt, verifier.Params)
	response := protocol.AuthResponse{
		Version:  protocol.Version,
		Role:     role,
		Response: verifier.ChallengeResponse(challenge.Nonce),
	}
	writer := protocol.NewWriter(rw)
	if err := writer.WriteJSON(protocol.FrameAuthResponse, 0, response); err != nil {
		return err
	}
	resultFrame, err := protocol.ReadFrame(rw)
	if err != nil {
		return err
	}
	if resultFrame.Type != protocol.FrameAuthResult {
		return fmt.Errorf("expected authentication result, got frame %d", resultFrame.Type)
	}
	result, err := protocol.DecodeJSON[protocol.AuthResult](resultFrame)
	if err != nil {
		return err
	}
	if result.Version != protocol.Version {
		return fmt.Errorf("protocol version mismatch: server uses %d", result.Version)
	}
	if !result.OK {
		if result.Error == "" {
			result.Error = ErrInvalidPassword.Error()
		}
		return ErrInvalidPassword
	}
	return nil
}

// ServerHandshakePassword validates the challenge-derived password proof.
func ServerHandshakePassword(rw io.ReadWriter, verifier Verifier, roleLimit string) (protocol.AuthResponse, error) {
	challenge, err := makeChallenge(verifier)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	writer := protocol.NewWriter(rw)
	if err := writer.Write(protocol.Frame{Type: protocol.FrameChallenge, Payload: challenge}); err != nil {
		return protocol.AuthResponse{}, err
	}
	frame, err := protocol.ReadFrame(rw)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	if frame.Type != protocol.FrameAuthResponse {
		return protocol.AuthResponse{}, fmt.Errorf("expected auth response, got frame %d", frame.Type)
	}
	response, err := protocol.DecodeJSON[protocol.AuthResponse](frame)
	if err != nil {
		return protocol.AuthResponse{}, err
	}
	decoded, err := decodeChallenge(challenge)
	if err != nil {
		return response, err
	}
	ok := response.Version == protocol.Version &&
		(roleLimit == "" || roleLimit == response.Role) &&
		verifier.VerifyChallenge(decoded.Nonce, response.Response)
	result := protocol.AuthResult{OK: ok, Version: protocol.Version}
	if !ok {
		result.Error = ErrInvalidPassword.Error()
	}
	if err := writer.WriteJSON(protocol.FrameAuthResult, 0, result); err != nil {
		return response, err
	}
	if !ok {
		return response, ErrInvalidPassword
	}
	return response, nil
}
