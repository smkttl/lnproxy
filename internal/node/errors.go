package node

import "errors"

var (
	ErrNoExit          = errors.New("no healthy exit is available")
	ErrExitUnavailable = errors.New("selected exit is unavailable")
)
