package client

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"lnproxy/internal/auth"
)

type Shell struct {
	runtime *Runtime
	manager *Manager
	in      io.Reader
	out     io.Writer
	reader  *bufio.Reader
}

func NewShell(runtime *Runtime, manager *Manager, in io.Reader, out io.Writer) *Shell {
	return &Shell{
		runtime: runtime,
		manager: manager,
		in:      in,
		out:     out,
		reader:  bufio.NewReader(in),
	}
}

func (s *Shell) Run(ctx context.Context) error {
	for {
		fmt.Fprint(s.out, "> ")
		line, err := s.reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			if err == io.EOF {
				return nil
			}
			return err
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			if err != nil {
				return nil
			}
			continue
		}
		quit, err := s.execute(ctx, fields)
		if err != nil {
			fmt.Fprintln(s.out, "error:", err)
		}
		if quit {
			return nil
		}
		if err == io.EOF {
			return nil
		}
	}
}

func (s *Shell) execute(ctx context.Context, fields []string) (bool, error) {
	switch strings.ToLower(fields[0]) {
	case "connect":
		if len(fields) != 2 {
			return false, fmt.Errorf("usage: connect <S IP>")
		}
		passphrase, err := auth.PromptPassphrase("Please input password: ", false)
		if err != nil {
			return false, err
		}
		if err := s.runtime.Start(ctx, fields[1], passphrase); err != nil {
			return false, err
		}
		fmt.Fprintln(s.out, "Authentication success!")
		addr := s.runtime.ProxyAddress()
		fmt.Fprintf(s.out, "HTTP proxy listening on %s\n", addr)
		if socks := s.runtime.SOCKSAddress(); socks != "" {
			fmt.Fprintf(s.out, "SOCKS5 proxy listening on %s\n", socks)
		}
		return false, nil
	case "status":
		state, transport, lastErr := s.manager.State()
		exit := s.runtime.ExitID()
		fmt.Fprintf(s.out, "state: %s\n", state)
		if transport != "" {
			fmt.Fprintf(s.out, "transport: %s\n", transport)
		}
		fmt.Fprintf(s.out, "exit: %s\n", exit)
		fmt.Fprintf(s.out, "http: %s\n", s.runtime.ProxyAddress())
		if socks := s.runtime.SOCKSAddress(); socks != "" {
			fmt.Fprintf(s.out, "socks5: %s\n", socks)
		}
		if lastErr != nil {
			fmt.Fprintf(s.out, "last error: %v\n", lastErr)
		}
		return false, nil
	case "exits":
		catalog := s.manager.Catalog()
		if len(catalog) == 0 {
			fmt.Fprintln(s.out, "no exits available")
			return false, nil
		}
		sort.Slice(catalog, func(i, j int) bool { return catalog[i].ID < catalog[j].ID })
		fmt.Fprintln(s.out, "ID\tNAME\tHEALTH\tLATENCY\tLOAD\tCAPACITY")
		for _, exit := range catalog {
			fmt.Fprintf(s.out, "%s\t%s\t%s\t%dms\t%d\t%d\n",
				exit.ID, exit.Name, exit.Health, exit.LatencyMS, exit.ActiveConnections, exit.Capacity)
		}
		return false, nil
	case "use":
		if len(fields) < 2 || len(fields) > 3 {
			return false, fmt.Errorf("usage: use <exit-id|auto> [fallback]")
		}
		fallback := false
		if len(fields) == 3 {
			var err error
			fallback, err = strconv.ParseBool(fields[2])
			if err != nil {
				return false, fmt.Errorf("fallback must be true or false")
			}
		}
		if err := s.runtime.SetExit(fields[1], fallback); err != nil {
			return false, err
		}
		fmt.Fprintf(s.out, "new streams will use %s\n", fields[1])
		return false, nil
	case "reconnect":
		timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return false, s.manager.Reconnect(timeoutCtx)
	case "disconnect":
		return false, s.manager.Close()
	case "help":
		fmt.Fprintln(s.out, "connect <S IP>")
		fmt.Fprintln(s.out, "status")
		fmt.Fprintln(s.out, "exits")
		fmt.Fprintln(s.out, "use <exit-id|auto> [fallback]")
		fmt.Fprintln(s.out, "reconnect")
		fmt.Fprintln(s.out, "disconnect")
		fmt.Fprintln(s.out, "help")
		fmt.Fprintln(s.out, "quit")
		return false, nil
	case "quit", "exit":
		return true, nil
	default:
		return false, fmt.Errorf("unknown command %q; use help", fields[0])
	}
}
