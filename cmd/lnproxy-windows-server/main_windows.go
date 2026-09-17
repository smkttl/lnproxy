//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"lnproxy/internal/config"
	"lnproxy/internal/logging"
	"lnproxy/internal/silentserver"
)

func main() {
	os.Exit(run())
}

func run() int {
	dataDir, err := config.DefaultDataDir()
	if err != nil {
		return 1
	}
	logger, err := logging.New(dataDir, false)
	if err != nil {
		return 1
	}
	defer logger.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := silentserver.Run(ctx, dataDir, logger.Logger); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0
		}
		logger.Error("silent server stopped", "error", err)
		return 1
	}
	return 0
}
