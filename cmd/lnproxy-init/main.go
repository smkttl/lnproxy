package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"lnproxy/internal/config"
	"lnproxy/internal/initnode"
)

type options struct {
	configPath    string
	dataDir       string
	listen        string
	serverAddress string
	fingerprint   string
	passphraseSrc string
	capacity      int
	idleTimeout   time.Duration
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lnproxy-init:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	role, opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	cfg, err := config.DefaultNode(role)
	if err != nil {
		return err
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
	if opts.capacity > 0 {
		cfg.Capacity = opts.capacity
	}
	if opts.idleTimeout > 0 {
		cfg.IdleTimeout = opts.idleTimeout
	}
	return initnode.Initialize(cfg, opts.configPath)
}

func parseOptions(args []string) (string, options, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		return "", options{}, errors.New("usage: lnproxy-init <server|exit|server-exit> [options]")
	}
	role := args[0]
	switch role {
	case config.RoleServer, config.RoleExit, config.RoleServerExit:
	default:
		return "", options{}, fmt.Errorf("unsupported role %q", role)
	}

	var opts options
	flags := flag.NewFlagSet("lnproxy-init "+role, flag.ContinueOnError)
	flags.StringVar(&opts.configPath, "config", "", "configuration file to create")
	flags.StringVar(&opts.dataDir, "data-dir", "", "data directory")
	flags.StringVar(&opts.listen, "listen", "", "listen address (default :443)")
	flags.StringVar(&opts.serverAddress, "server", "", "server address for exit mode")
	flags.StringVar(&opts.fingerprint, "fingerprint", "", "expected S certificate SHA-256 fingerprint")
	flags.StringVar(&opts.passphraseSrc, "passphrase", "", "runtime passphrase source")
	flags.IntVar(&opts.capacity, "capacity", 0, "maximum concurrent streams")
	flags.DurationVar(&opts.idleTimeout, "idle-timeout", 0, "idle stream timeout")
	if err := flags.Parse(args[1:]); err != nil {
		return "", options{}, err
	}
	return role, opts, nil
}
