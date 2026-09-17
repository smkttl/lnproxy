package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"lnproxy/internal/auth"
	"lnproxy/internal/config"
	"lnproxy/internal/initnode"
	"lnproxy/internal/logging"
	"lnproxy/internal/node"
	"lnproxy/internal/transport"
)

type options struct {
	role          string
	initMode      bool
	configPath    string
	dataDir       string
	listen        string
	serverAddress string
	fingerprint   string
	passphraseSrc string
	console       bool
	capacity      int
	idleTimeout   time.Duration
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "lnproxy-node:", err)
		os.Exit(1)
	}
}

func run() error {
	role, args, err := parseInvocation(os.Args[1:])
	if err != nil {
		return err
	}
	opts, err := parseOptions(role, args)
	if err != nil {
		return err
	}
	cfg := config.Node{Role: role}
	if opts.initMode {
		cfg, err = config.DefaultNode(role)
		if err != nil {
			return err
		}
	} else if opts.configPath != "" {
		cfg, err = config.LoadNode(opts.configPath)
		if err != nil {
			return err
		}
		cfg.Role = role
	} else {
		cfg, err = config.DefaultNode(role)
		if err != nil {
			return err
		}
	}
	if opts.dataDir != "" {
		cfg.DataDirectory = opts.dataDir
	}
	cfg = cfg.FillPaths()
	if opts.listen != "" {
		cfg.ListenAddress = opts.listen
	}
	if opts.serverAddress != "" {
		cfg.ServerAddress = opts.serverAddress
	}
	if opts.fingerprint != "" {
		cfg.ServerFingerprint = opts.fingerprint
	}
	if opts.passphraseSrc != "" {
		cfg.PassphraseSource = opts.passphraseSrc
	}
	if opts.console {
		cfg.Console = true
	}
	if opts.capacity > 0 {
		cfg.Capacity = opts.capacity
	}
	if opts.idleTimeout > 0 {
		cfg.IdleTimeout = opts.idleTimeout
	}

	logger, err := logging.New(cfg.DataDirectory, cfg.Console || opts.initMode)
	if err != nil {
		return err
	}
	defer logger.Close()

	if opts.initMode {
		return initnode.Initialize(cfg, opts.configPath)
	}
	if cfg.Role == config.RoleExit {
		passphrase, err := auth.ResolvePassphrase(cfg.PassphraseSource)
		if err != nil {
			return err
		}
		exit := node.NewExit(cfg, passphrase, nil, logger.Logger)
		if cfg.ServerFingerprint == "" {
			knownHosts, err := loadExitKnownHosts(cfg)
			if err != nil {
				return err
			}
			exit.UseTrust(knownHosts)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return exit.Run(ctx)
	}

	verifier, err := auth.LoadVerifier(cfg.VerifierFile)
	if err != nil {
		return fmt.Errorf("load passphrase verifier (run --init first): %w", err)
	}
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	tlsConfig := transport.BaseTLSConfig(&certificate)
	server := node.NewServer(cfg, verifier, tlsConfig, logger.Logger)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return server.Run(ctx)
}

func loadExitKnownHosts(cfg config.Node) (*transport.KnownHosts, error) {
	path := filepath.Join(cfg.DataDirectory, "known-hosts.json")
	knownHosts, err := transport.LoadKnownHosts(path)
	if err != nil {
		return nil, fmt.Errorf("load known hosts: %w", err)
	}
	knownHosts.SetConfirmer(func(host, fingerprint string) (bool, error) {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return false, errors.New("standard input is not a terminal; run E once interactively to trust S or configure --fingerprint")
		}
		fmt.Fprintf(os.Stderr, "Server %s fingerprint:\n%s\n", host, fingerprint)
		fmt.Fprint(os.Stderr, "Trust this server? [y/N] ")
		var answer string
		if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
			return false, err
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		return answer == "y" || answer == "yes", nil
	})
	return knownHosts, nil
}

func parseInvocation(args []string) (string, []string, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return "", nil, errors.New("usage: lnproxy-node <server|exit|server-exit> [options]")
	}
	role := args[0]
	switch role {
	case config.RoleServer, config.RoleExit, config.RoleServerExit:
	default:
		return "", nil, fmt.Errorf("unsupported role %q", role)
	}
	return role, args[1:], nil
}

func parseOptions(role string, args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("lnproxy-node "+role, flag.ContinueOnError)
	flags.BoolVar(&opts.initMode, "init", false, "initialize data directory, certificate, and passphrase verifier")
	flags.StringVar(&opts.configPath, "config", "", "configuration file")
	flags.StringVar(&opts.dataDir, "data-dir", "", "data directory")
	flags.StringVar(&opts.listen, "listen", "", "listen address (default :443)")
	flags.StringVar(&opts.serverAddress, "server", "", "server address for exit mode")
	flags.StringVar(&opts.fingerprint, "fingerprint", "", "expected S certificate SHA-256 fingerprint")
	flags.StringVar(&opts.passphraseSrc, "passphrase", "", "passphrase source: env:NAME, file:PATH, or prompt")
	flags.BoolVar(&opts.console, "console", false, "force console logging")
	flags.IntVar(&opts.capacity, "capacity", 0, "maximum concurrent streams")
	flags.DurationVar(&opts.idleTimeout, "idle-timeout", 0, "idle stream timeout")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	return opts, nil
}
