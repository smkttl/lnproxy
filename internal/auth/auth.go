package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const (
	defaultMemory      = 64 * 1024
	defaultIterations  = 3
	defaultParallelism = 2
	keyLength          = 32
	saltLength         = 16
)

var (
	ErrInvalidPassword = errors.New("authentication failed")
	ErrRateLimited     = errors.New("too many authentication failures")
)

type Parameters struct {
	Memory      uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

type VerifierFile struct {
	Version int        `json:"version"`
	Salt    string     `json:"salt"`
	Hash    string     `json:"hash"`
	Params  Parameters `json:"params"`
}

type Verifier struct {
	Salt   []byte
	Hash   []byte
	Params Parameters
}

func DefaultParameters() Parameters {
	return Parameters{
		Memory:      defaultMemory,
		Iterations:  defaultIterations,
		Parallelism: defaultParallelism,
	}
}

func Derive(passphrase string, salt []byte, params Parameters) []byte {
	if params.Memory == 0 {
		params = DefaultParameters()
	}
	return argon2.IDKey([]byte(passphrase), salt, params.Iterations, params.Memory, params.Parallelism, keyLength)
}

func NewVerifier(passphrase string) (Verifier, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return Verifier{}, err
	}
	params := DefaultParameters()
	return Verifier{Salt: salt, Hash: Derive(passphrase, salt, params), Params: params}, nil
}

func (v Verifier) Verify(passphrase string) bool {
	actual := Derive(passphrase, v.Salt, v.Params)
	return subtle.ConstantTimeCompare(actual, v.Hash) == 1
}

func (v Verifier) ChallengeResponse(nonce []byte) []byte {
	mac := hmac.New(sha256.New, v.Hash)
	mac.Write([]byte("lnproxy-auth-v1"))
	mac.Write(nonce)
	return mac.Sum(nil)
}

func (v Verifier) VerifyChallenge(nonce, response []byte) bool {
	expected := v.ChallengeResponse(nonce)
	return subtle.ConstantTimeCompare(expected, response) == 1
}

func (v Verifier) Save(path string) error {
	encoded := VerifierFile{
		Version: 1,
		Salt:    base64.RawStdEncoding.EncodeToString(v.Salt),
		Hash:    base64.RawStdEncoding.EncodeToString(v.Hash),
		Params:  v.Params,
	}
	data, err := json.MarshalIndent(encoded, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writePrivateFile(path, data)
}

func LoadVerifier(path string) (Verifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Verifier{}, err
	}
	var encoded VerifierFile
	if err := json.Unmarshal(data, &encoded); err != nil {
		return Verifier{}, fmt.Errorf("parse verifier: %w", err)
	}
	if encoded.Version != 1 {
		return Verifier{}, fmt.Errorf("unsupported verifier version %d", encoded.Version)
	}
	salt, err := base64.RawStdEncoding.DecodeString(encoded.Salt)
	if err != nil {
		return Verifier{}, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(encoded.Hash)
	if err != nil {
		return Verifier{}, fmt.Errorf("decode hash: %w", err)
	}
	if len(salt) < 8 || len(hash) != keyLength {
		return Verifier{}, errors.New("invalid verifier file")
	}
	return Verifier{Salt: salt, Hash: hash, Params: encoded.Params}, nil
}

func ResolvePassphrase(source string) (string, error) {
	switch {
	case source == "prompt":
		return PromptPassphrase("Please input password: ", false)
	case strings.HasPrefix(source, "env:"):
		name := strings.TrimPrefix(source, "env:")
		if name == "" {
			return "", errors.New("invalid environment passphrase source")
		}
		value, ok := os.LookupEnv(name)
		if !ok || value == "" {
			return "", fmt.Errorf("environment variable %s is not set", name)
		}
		return value, nil
	case strings.HasPrefix(source, "file:"):
		path := strings.TrimPrefix(source, "file:")
		if path == "" {
			return "", errors.New("invalid file passphrase source")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		value := strings.TrimRight(string(data), "\r\n")
		if value == "" {
			return "", errors.New("passphrase file is empty")
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported passphrase source %q", source)
	}
}

func PromptPassphrase(prompt string, confirm bool) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("standard input is not a terminal; use env: or file: passphrase source")
	}
	fmt.Fprint(os.Stderr, prompt)
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(first) == 0 {
		return "", errors.New("passphrase cannot be empty")
	}
	if !confirm {
		return string(first), nil
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(first, second) {
		return "", errors.New("passphrases do not match")
	}
	return string(first), nil
}

type attempt struct {
	count       int
	windowStart time.Time
	blockedTill time.Time
}

type RateLimiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	blockFor time.Duration
	attempts map[string]attempt
}

func NewRateLimiter(limit int, window, blockFor time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:    limit,
		window:   window,
		blockFor: blockFor,
		attempts: make(map[string]attempt),
	}
}

func (l *RateLimiter) Allowed(key string) error {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.attempts[key]
	if now.Before(state.blockedTill) {
		return ErrRateLimited
	}
	if state.windowStart.IsZero() || now.Sub(state.windowStart) > l.window {
		delete(l.attempts, key)
	}
	return nil
}

func (l *RateLimiter) Fail(key string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.attempts[key]
	if state.windowStart.IsZero() || now.Sub(state.windowStart) > l.window {
		state = attempt{count: 0, windowStart: now}
	}
	state.count++
	if state.count >= l.limit {
		state.blockedTill = now.Add(l.blockFor)
	}
	l.attempts[key] = state
}

func (l *RateLimiter) Success(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

type contextKey struct{}

func WithRateLimitKey(ctx context.Context, key string) context.Context {
	return context.WithValue(ctx, contextKey{}, key)
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp := path + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o600); err != nil {
		_ = os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return err
	}
	return nil
}
