package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func encodedKey(fill byte, size int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, size))
}

func validConfig() Config {
	return Config{
		Device:          "eth0",
		FirewallBackend: "nftables",
		Users: []User{
			{
				Name:    "alice",
				AESKey:  encodedKey(0x11, 32),
				HMACKey: encodedKey(0x22, 32),
			},
			{
				Name:    "bob",
				AESKey:  encodedKey(0x33, 32),
				HMACKey: encodedKey(0x44, 32),
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
		{
			name: "invalid hmac key base64",
			mutate: func(cfg *Config) {
				cfg.Users[0].HMACKey = "not-base64***"
			},
			wantErrContains: "illegal base64 data",
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
	wantHMAC, _ := base64.StdEncoding.DecodeString(cfg.Users[0].HMACKey)

	if !bytes.Equal(cfg.Users[0].AESKeyBytes, wantAES) {
		t.Fatalf("decoded AES key mismatch")
	}
	if !bytes.Equal(cfg.Users[0].HMACKeyBytes, wantHMAC) {
		t.Fatalf("decoded HMAC key mismatch")
	}
}
