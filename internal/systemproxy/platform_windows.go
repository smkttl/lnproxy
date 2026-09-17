//go:build windows

package systemproxy

import (
	"context"
	"encoding/json"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const internetSettings = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type Windows struct{}

type windowsSnapshot struct {
	ProxyEnable   uint32 `json:"proxy_enable"`
	ProxyServer   string `json:"proxy_server"`
	ProxyOverride string `json:"proxy_override"`
	AutoConfigURL string `json:"auto_config_url"`
}

func New() SystemProxy {
	return Windows{}
}

func (Windows) Snapshot(context.Context) (Snapshot, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettings, registry.QUERY_VALUE)
	if err != nil {
		return Snapshot{}, err
	}
	defer key.Close()
	value := windowsSnapshot{}
	proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
	if err == nil {
		value.ProxyEnable = uint32(proxyEnable)
	}
	value.ProxyServer, _, _ = key.GetStringValue("ProxyServer")
	value.ProxyOverride, _, _ = key.GetStringValue("ProxyOverride")
	value.AutoConfigURL, _, _ = key.GetStringValue("AutoConfigURL")
	data, err := json.Marshal(value)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Version: 1, Values: data}, nil
}

func (Windows) Apply(_ context.Context, endpoint Endpoint) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	server := "http=" + endpoint.HTTP
	if endpoint.HTTPS != "" {
		server += ";https=" + endpoint.HTTPS
	}
	if endpoint.SOCKS != "" {
		server += ";socks=" + endpoint.SOCKS
	}
	if err := key.SetStringValue("ProxyServer", server); err != nil {
		return err
	}
	if err := key.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	_ = key.DeleteValue("AutoConfigURL")
	notifyProxyChange()
	return nil
}

func (Windows) Matches(_ context.Context, snapshot Snapshot, endpoint Endpoint) (bool, error) {
	var original windowsSnapshot
	if err := json.Unmarshal(snapshot.Values, &original); err != nil {
		return false, err
	}
	current, err := (Windows{}).Snapshot(context.Background())
	if err != nil {
		return false, err
	}
	var value windowsSnapshot
	if err := json.Unmarshal(current.Values, &value); err != nil {
		return false, err
	}
	expected := "http=" + endpoint.HTTP
	if endpoint.HTTPS != "" {
		expected += ";https=" + endpoint.HTTPS
	}
	if endpoint.SOCKS != "" {
		expected += ";socks=" + endpoint.SOCKS
	}
	return value.ProxyEnable == 1 && value.ProxyServer == expected && value.AutoConfigURL == "", nil
}

func (Windows) Restore(_ context.Context, snapshot Snapshot) error {
	var value windowsSnapshot
	if err := json.Unmarshal(snapshot.Values, &value); err != nil {
		return err
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, internetSettings, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if value.ProxyEnable == 0 {
		if err := key.SetDWordValue("ProxyEnable", 0); err != nil {
			return err
		}
	} else {
		if err := key.SetDWordValue("ProxyEnable", value.ProxyEnable); err != nil {
			return err
		}
	}
	if err := key.SetStringValue("ProxyServer", value.ProxyServer); err != nil {
		return err
	}
	if err := key.SetStringValue("ProxyOverride", value.ProxyOverride); err != nil {
		return err
	}
	if value.AutoConfigURL == "" {
		_ = key.DeleteValue("AutoConfigURL")
	} else if err := key.SetStringValue("AutoConfigURL", value.AutoConfigURL); err != nil {
		return err
	}
	notifyProxyChange()
	return nil
}

var (
	wininet           = syscall.NewLazyDLL("wininet.dll")
	internetSetOption = wininet.NewProc("InternetSetOptionW")
)

func notifyProxyChange() {
	const (
		internetOptionSettingsChanged = 39
		internetOptionRefresh         = 37
	)
	_, _, _ = internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = internetSetOption.Call(0, internetOptionRefresh, 0, 0)
}
