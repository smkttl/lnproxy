//go:build linux

package systemproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
)

type linuxMode int

const (
	linuxUnsupported linuxMode = iota
	linuxGSettings
	linuxKDE
)

type Linux struct {
	mode linuxMode
}

type gnomeSnapshot struct {
	Mode     string `json:"mode"`
	HTTP     string `json:"http"`
	HTTPS    string `json:"https"`
	SOCKS    string `json:"socks"`
	Ignore   string `json:"ignore"`
	Autoconf string `json:"autoconf"`
}

type kdeSnapshot struct {
	ProxyType string `json:"proxy_type"`
	HTTP      string `json:"http"`
	HTTPS     string `json:"https"`
	SOCKS     string `json:"socks"`
	NoProxy   string `json:"no_proxy"`
	PAC       string `json:"pac"`
}

func New() SystemProxy {
	desktop := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP"))
	sessionType := strings.ToLower(os.Getenv("XDG_SESSION_TYPE"))
	if (strings.Contains(desktop, "GNOME") || strings.Contains(desktop, "UNITY")) && os.Getenv("DISPLAY") != "" {
		if sessionType != "x11" && sessionType != "wayland" && sessionType != "" {
			return Unsupported{Reason: ErrUnsupported.Error()}
		}
		if _, err := exec.LookPath("gsettings"); err == nil {
			return &Linux{mode: linuxGSettings}
		}
	}
	if strings.Contains(desktop, "KDE") && os.Getenv("DISPLAY") != "" {
		if sessionType != "x11" && sessionType != "wayland" && sessionType != "" {
			return Unsupported{Reason: ErrUnsupported.Error()}
		}
		if kdeCommand() != nil {
			return &Linux{mode: linuxKDE}
		}
	}
	return Unsupported{Reason: ErrUnsupported.Error()}
}

func (l *Linux) Snapshot(ctx context.Context) (Snapshot, error) {
	switch l.mode {
	case linuxGSettings:
		values := gnomeSnapshot{}
		var err error
		values.Mode, err = gsettingsGet(ctx, "org.gnome.system.proxy", "mode")
		if err != nil {
			return Snapshot{}, err
		}
		values.HTTP, err = gsettingsGet(ctx, "org.gnome.system.proxy.http", "host")
		if err != nil {
			return Snapshot{}, err
		}
		values.HTTPS, err = gsettingsGet(ctx, "org.gnome.system.proxy.https", "host")
		if err != nil {
			return Snapshot{}, err
		}
		values.SOCKS, err = gsettingsGet(ctx, "org.gnome.system.proxy.socks", "host")
		if err != nil {
			return Snapshot{}, err
		}
		values.Ignore, err = gsettingsGet(ctx, "org.gnome.system.proxy", "ignore-hosts")
		if err != nil {
			return Snapshot{}, err
		}
		values.Autoconf, err = gsettingsGet(ctx, "org.gnome.system.proxy", "autoconfig-url")
		if err != nil {
			return Snapshot{}, err
		}
		return marshalSnapshot(values)
	case linuxKDE:
		values := kdeSnapshot{}
		var err error
		values.ProxyType, err = kread(ctx, "ProxyType")
		if err != nil {
			return Snapshot{}, err
		}
		values.HTTP, err = kread(ctx, "httpProxy")
		if err != nil {
			return Snapshot{}, err
		}
		values.HTTPS, err = kread(ctx, "httpsProxy")
		if err != nil {
			return Snapshot{}, err
		}
		values.SOCKS, err = kread(ctx, "socksProxy")
		if err != nil {
			return Snapshot{}, err
		}
		values.NoProxy, err = kread(ctx, "NoProxyFor")
		if err != nil {
			return Snapshot{}, err
		}
		values.PAC, err = kread(ctx, "Proxy Config Script")
		if err != nil {
			return Snapshot{}, err
		}
		return marshalSnapshot(values)
	default:
		return Snapshot{}, ErrUnsupported
	}
}

func (l *Linux) Apply(ctx context.Context, endpoint Endpoint) error {
	switch l.mode {
	case linuxGSettings:
		if err := gsettingsSet(ctx, "org.gnome.system.proxy", "mode", "manual"); err != nil {
			return err
		}
		host, port, err := splitEndpoint(endpoint.HTTP)
		if err != nil {
			return err
		}
		if err := gsettingsSet(ctx, "org.gnome.system.proxy.http", "host", host); err != nil {
			return err
		}
		if err := gsettingsSet(ctx, "org.gnome.system.proxy.http", "port", port); err != nil {
			return err
		}
		httpsHost, httpsPort, err := splitEndpoint(endpoint.HTTPS)
		if err != nil {
			httpsHost, httpsPort = host, port
		}
		if err := gsettingsSet(ctx, "org.gnome.system.proxy.https", "host", httpsHost); err != nil {
			return err
		}
		if err := gsettingsSet(ctx, "org.gnome.system.proxy.https", "port", httpsPort); err != nil {
			return err
		}
		return nil
	case linuxKDE:
		host, port, err := splitEndpoint(endpoint.HTTP)
		if err != nil {
			return err
		}
		_ = host
		if err := kwrite(ctx, "ProxyType", "1"); err != nil {
			return err
		}
		if err := kwrite(ctx, "httpProxy", endpoint.HTTP); err != nil {
			return err
		}
		if err := kwrite(ctx, "httpsProxy", endpoint.HTTPSOrDefault()); err != nil {
			return err
		}
		if endpoint.SOCKS != "" {
			if err := kwrite(ctx, "socksProxy", endpoint.SOCKS); err != nil {
				return err
			}
		}
		_ = port
		return nil
	default:
		return ErrUnsupported
	}
}

func (l *Linux) Matches(ctx context.Context, snapshot Snapshot, endpoint Endpoint) (bool, error) {
	switch l.mode {
	case linuxGSettings:
		var values gnomeSnapshot
		if err := json.Unmarshal(snapshot.Values, &values); err != nil {
			return false, err
		}
		httpHost, httpPort, err := splitEndpoint(endpoint.HTTP)
		if err != nil {
			return false, err
		}
		httpsHost, httpsPort, err := splitEndpoint(endpoint.HTTPSOrDefault())
		if err != nil {
			return false, err
		}
		return values.Mode == "manual" && values.HTTP == httpHost &&
			values.HTTPS == httpsHost && values.Autoconf == "" && httpPort == httpsPort, nil
	case linuxKDE:
		var values kdeSnapshot
		if err := json.Unmarshal(snapshot.Values, &values); err != nil {
			return false, err
		}
		return values.ProxyType == "1" && values.HTTP == endpoint.HTTP &&
			values.HTTPS == endpoint.HTTPSOrDefault(), nil
	default:
		return false, ErrUnsupported
	}
}

func (l *Linux) Restore(ctx context.Context, snapshot Snapshot) error {
	switch l.mode {
	case linuxGSettings:
		var values gnomeSnapshot
		if err := json.Unmarshal(snapshot.Values, &values); err != nil {
			return err
		}
		if err := gsettingsSet(ctx, "org.gnome.system.proxy", "mode", values.Mode); err != nil {
			return err
		}
		host, port, _ := splitEndpoint(values.HTTP)
		_ = gsettingsSet(ctx, "org.gnome.system.proxy.http", "host", host)
		_ = gsettingsSet(ctx, "org.gnome.system.proxy.http", "port", port)
		httpsHost, httpsPort, _ := splitEndpoint(values.HTTPS)
		_ = gsettingsSet(ctx, "org.gnome.system.proxy.https", "host", httpsHost)
		_ = gsettingsSet(ctx, "org.gnome.system.proxy.https", "port", httpsPort)
		return gsettingsSet(ctx, "org.gnome.system.proxy", "autoconfig-url", values.Autoconf)
	case linuxKDE:
		var values kdeSnapshot
		if err := json.Unmarshal(snapshot.Values, &values); err != nil {
			return err
		}
		if err := kwrite(ctx, "ProxyType", values.ProxyType); err != nil {
			return err
		}
		_ = kwrite(ctx, "httpProxy", values.HTTP)
		_ = kwrite(ctx, "httpsProxy", values.HTTPS)
		_ = kwrite(ctx, "socksProxy", values.SOCKS)
		_ = kwrite(ctx, "NoProxyFor", values.NoProxy)
		_ = kwrite(ctx, "Proxy Config Script", values.PAC)
		return nil
	default:
		return ErrUnsupported
	}
}

func (e Endpoint) HTTPSOrDefault() string {
	if e.HTTPS != "" {
		return e.HTTPS
	}
	return e.HTTP
}

func marshalSnapshot(value any) (Snapshot, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: 1, Values: data}, nil
}

func gsettingsGet(ctx context.Context, schema, key string) (string, error) {
	output, err := exec.CommandContext(ctx, "gsettings", "get", schema, key).Output()
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(output))
	value = strings.Trim(value, "'")
	return value, nil
}

func gsettingsSet(ctx context.Context, schema, key, value string) error {
	return exec.CommandContext(ctx, "gsettings", "set", schema, key, value).Run()
}

func kread(ctx context.Context, key string) (string, error) {
	command := kdeCommand("--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
	if command == nil {
		return "", ErrUnsupported
	}
	command = append(command, "--read")
	command[0] = strings.Replace(command[0], "kwriteconfig", "kreadconfig", 1)
	output, err := exec.CommandContext(ctx, command[0], command[1:]...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func kwrite(ctx context.Context, key, value string) error {
	command := kdeCommand("--file", "kioslaverc", "--group", "Proxy Settings", "--key", key)
	if command == nil {
		return ErrUnsupported
	}
	command = append(command, value)
	return exec.CommandContext(ctx, command[0], command[1:]...).Run()
}

func kdeCommand(args ...string) []string {
	for _, binary := range []string{"kwriteconfig6", "kwriteconfig5"} {
		if path, err := exec.LookPath(binary); err == nil {
			return append([]string{path}, args...)
		}
	}
	return nil
}

func splitEndpoint(endpoint string) (string, string, error) {
	if endpoint == "" {
		return "", "0", nil
	}
	host, port, err := netSplitHostPort(endpoint)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func netSplitHostPort(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", "", errors.New("invalid proxy endpoint")
	}
	return host, port, nil
}
