package config

import (
	"bytes"
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func encodedKey(fill byte, size int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, size))
}

func validConfig() Config {
	return Config{
		Device:            "eth0",
		FirewallBackend:   "nftables",
		NFTablesTableName: "go-fwknop-filter",
		NFTablesChainName: "go-fwknop-chain",
		MaxPacketLength:   1600,
		Users: []User{
			{
				Name:   "alice",
				AESKey: encodedKey(0x11, 32),
			},
			{
				Name:   "bob",
				AESKey: encodedKey(0x33, 32),
			},
		},
		Rules: []Rule{
			{
				Name:         "ssh",
				KnockPort:    62201,
				OpenProto:    "tcp",
				OpenPort:     22,
				OpenTime:     30,
				AllowedUsers: []string{"alice"},
				AllowedIPs:   []string{"203.0.113.10"},
			},
		},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name            string
		mutate          func(*Config)
		wantErrContains string
	}{
		{
			name: "valid config",
		},
		{
			name: "duplicate username",
			mutate: func(cfg *Config) {
				cfg.Users[1].Name = cfg.Users[0].Name
			},
			wantErrContains: "duplicated username",
		},
		{
			name: "duplicate knock port",
			mutate: func(cfg *Config) {
				cfg.Rules = append(cfg.Rules, Rule{
					Name:         "web",
					KnockPort:    cfg.Rules[0].KnockPort,
					OpenProto:    "tcp",
					OpenPort:     443,
					OpenTime:     30,
					AllowedUsers: []string{"alice"},
				})
			},
			wantErrContains: "duplicated knock port",
		},
		{
			name: "unknown user in rule",
			mutate: func(cfg *Config) {
				cfg.Rules[0].AllowedUsers = []string{"charlie"}
			},
			wantErrContains: "unknown username",
		},
		{
			name: "zero open time",
			mutate: func(cfg *Config) {
				cfg.Rules[0].OpenTime = 0
			},
			wantErrContains: "open_time must be non-zero",
		},
		{
			name: "invalid aes key length",
			mutate: func(cfg *Config) {
				cfg.Users[0].AESKey = encodedKey(0x11, 16)
			},
			wantErrContains: "aes key in wrong format",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			if tc.mutate != nil {
				tc.mutate(&cfg)
			}

			err := cfg.Validate()
			if tc.wantErrContains == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("Validate() expected error containing %q, got nil", tc.wantErrContains)
			}
			if !strings.Contains(err.Error(), tc.wantErrContains) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tc.wantErrContains)
			}
		})
	}
}

func TestValidateDecodesUserKeys(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	wantAES, _ := base64.StdEncoding.DecodeString(cfg.Users[0].AESKey)

	if !bytes.Equal(cfg.Users[0].AESKeyBytes, wantAES) {
		t.Fatalf("decoded AES key mismatch")
	}
}

func TestValidateAllowedIPNets(t *testing.T) {
	tests := []struct {
		name      string
		allowedIP string
		match     []string
		noMatch   []string
	}{
		{
			name:      "bare ipv6 becomes a single host",
			allowedIP: "2001:db8::1",
			match:     []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1"},
			noMatch:   []string{"2001:db8::2", "203.0.113.10"},
		},
		{
			name:      "ipv6 cidr",
			allowedIP: "2001:db8:1::/48",
			match:     []string{"2001:db8:1::1", "2001:db8:1:ffff::ff"},
			noMatch:   []string{"2001:db8:2::1", "203.0.113.10"},
		},
		{
			name:      "bare ipv4 becomes a single host",
			allowedIP: "203.0.113.10",
			match:     []string{"203.0.113.10"},
			noMatch:   []string{"203.0.113.11", "2001:db8::1"},
		},
		{
			name:      "wildcard covers both families",
			allowedIP: "*",
			match:     []string{"203.0.113.10", "2001:db8::1", "::1", "0.0.0.0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Rules[0].AllowedIPs = []string{tc.allowedIP}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate() unexpected error: %v", err)
			}

			contains := func(ip string) bool {
				for _, ipnet := range cfg.Rules[0].AllowedIPNets {
					if ipnet.Contains(net.ParseIP(ip)) {
						return true
					}
				}
				return false
			}

			for _, ip := range tc.match {
				if !contains(ip) {
					t.Errorf("allowed_ips %q should match %s", tc.allowedIP, ip)
				}
			}
			for _, ip := range tc.noMatch {
				if contains(ip) {
					t.Errorf("allowed_ips %q should not match %s", tc.allowedIP, ip)
				}
			}
		})
	}
}

func TestValidateRejectsInvalidIPv6(t *testing.T) {
	cfg := validConfig()
	cfg.Rules[0].AllowedIPs = []string{"2001:db8::zz"}

	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid allowed_ip") {
		t.Fatalf("Validate() expected invalid allowed_ip error, got: %v", err)
	}
}
