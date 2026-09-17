package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"lnproxy/internal/client"
	"lnproxy/internal/config"
	"lnproxy/internal/logging"
	"lnproxy/internal/transport"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lnproxy-client:", err)
		os.Exit(1)
	}
}

func run() error {
	flags := flag.NewFlagSet("lnproxy-client", flag.ContinueOnError)
	socks5 := flags.Bool("socks5", false, "enable a loopback SOCKS5 listener")
	drainTimeout := flags.Duration("drain-timeout", 10*time.Second, "time to drain active streams on shutdown")
	flags.Usage = func() {
		fmt.Fprintln(flags.Output(), "Usage: lnproxy-client [options]")
		flags.PrintDefaults()
	}
	if len(os.Args) == 2 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
		flags.Usage()
		return nil
	}
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	dataDir, err := config.DefaultDataDir()
	if err != nil {
		return err
	}
	logger, err := logging.New("", true)
	if err != nil {
		return err
	}
	defer logger.Close()
	knownHostsPath := filepath.Join(dataDir, "known-hosts.json")
	knownHosts, err := transport.LoadKnownHosts(knownHostsPath)
	if err != nil {
		return err
	}
	manager := client.NewManager(knownHosts)
	knownHosts.SetConfirmer(func(host, fingerprint string) (bool, error) {
		fmt.Fprintf(os.Stderr, "Server %s fingerprint:\n%s\n", host, fingerprint)
		fmt.Fprint(os.Stderr, "Trust this server? [y/N] ")
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
			return false, err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		return answer == "y" || answer == "yes", nil
	})
	runtime := client.NewRuntime(client.RuntimeConfig{
		DataDirectory: dataDir,
		SOCKS5:        *socks5,
		Logger:        logger.Logger,
	}, manager)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	shell := client.NewShell(runtime, manager, os.Stdin, os.Stdout)
	fmt.Println("> connect <S IP>")
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		if shutdownErr := runtime.Shutdown(shutdownCtx, *drainTimeout); shutdownErr != nil {
			logger.Error("shutdown failed", "error", shutdownErr)
		}
	}()
	err = shell.Run(ctx)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if shutdownErr := runtime.Shutdown(shutdownCtx, *drainTimeout); shutdownErr != nil {
		return errors.Join(err, shutdownErr)
	}
	return err
}
