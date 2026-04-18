package config

import (
	"bytes"
	"flag"
	"strings"
	"testing"
	"time"
)

func TestRegisterFlags_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	cfg := RegisterFlags(fs, "1.2.3.4:1111", "5.6.7.8:2222")
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"ListenAddr", cfg.ListenAddr, "1.2.3.4:1111"},
		{"BackendAddr", cfg.BackendAddr, "5.6.7.8:2222"},
		{"ClientTLSEnabled", cfg.ClientTLSEnabled, false},
		{"BackendTLSEnabled", cfg.BackendTLSEnabled, false},
		{"MaxConns", cfg.MaxConns, 1024},
		{"HandshakeTimeout", cfg.HandshakeTimeout, 15 * time.Second},
		{"IdleTimeout", cfg.IdleTimeout, 5 * time.Minute},
		{"BackendDialTimeout", cfg.BackendDialTimeout, 5 * time.Second},
		{"ShutdownGracePeriod", cfg.ShutdownGracePeriod, 30 * time.Second},
		{"MetricsAddr", cfg.MetricsAddr, "127.0.0.1:9091"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestRegisterFlags_Override(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	cfg := RegisterFlags(fs, "x", "y")
	err := fs.Parse([]string{
		"-listen", ":1",
		"-backend", ":2",
		"-max-conns", "0",
		"-idle-timeout", "0",
		"-metrics-addr", "",
		"-client-tls-required",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":1" || cfg.BackendAddr != ":2" {
		t.Errorf("addrs: %+v", cfg)
	}
	if cfg.MaxConns != 0 {
		t.Errorf("max-conns not overridden: %d", cfg.MaxConns)
	}
	if cfg.IdleTimeout != 0 {
		t.Errorf("idle-timeout not overridden: %s", cfg.IdleTimeout)
	}
	if cfg.MetricsAddr != "" {
		t.Errorf("metrics-addr not cleared: %q", cfg.MetricsAddr)
	}
	if !cfg.ClientTLSRequired {
		t.Error("client-tls-required not set")
	}
}

func TestRegisterFlags_Help(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	_ = RegisterFlags(fs, "a", "b")
	fs.Usage()
	help := buf.String()
	// Spot-check a few known flags.
	for _, want := range []string{"-listen", "-backend", "-max-conns", "-metrics-addr", "-handshake-timeout"} {
		if !strings.Contains(help, want) {
			t.Errorf("help missing %q", want)
		}
	}
}
