package main

import (
	"bytes"
	"encoding/base64"
	"github.com/Luiggi33/go-fwknop/config"
	"github.com/Luiggi33/go-fwknop/spa"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The client and the daemon have to agree on the wire format, so exercise the
// payload against the real processor rather than asserting on bytes.
func TestBuildPayloadRoundTripsThroughProcessor(t *testing.T) {
	for _, addr := range []string{"203.0.113.10", "2001:db8::10"} {
		t.Run(addr, func(t *testing.T) {
			srcIP := net.ParseIP(addr)
			bits := 128
			if srcIP.To4() != nil {
				bits = 32
			}
			_, ipnet, err := net.ParseCIDR(addr + "/" + strconv.Itoa(bits))
			if err != nil {
				t.Fatalf("ParseCIDR() unexpected error: %v", err)
			}

			key := bytes.Repeat([]byte{0x10}, 32)
			user := config.User{Name: "alice", AESKeyBytes: key}
			rule := config.Rule{
				Name:          "ssh",
				KnockPort:     62201,
				OpenProto:     "tcp",
				OpenPort:      22,
				OpenTime:      15,
				AllowedUsers:  []string{"alice"},
				AllowedIPNets: []net.IPNet{*ipnet},
			}
			processor := spa.NewProcessor([]config.User{user}, []config.Rule{rule})

			plaintext := buildPayload(user.Name, time.Now(), rule.OpenProto, rule.OpenPort, srcIP)
			ciphertext, err := spa.Encrypt(key, plaintext)
			if err != nil {
				t.Fatalf("Encrypt() unexpected error: %v", err)
			}
			wire := []byte(base64.StdEncoding.EncodeToString(ciphertext))

			matchedRule, matchedUser, err := processor.Process(wire, rule.KnockPort, srcIP)
			if err != nil {
				t.Fatalf("Process() rejected client payload: %v", err)
			}
			if matchedRule == nil || matchedRule.Name != rule.Name {
				t.Fatalf("Process() returned wrong rule")
			}
			if matchedUser == nil || matchedUser.Name != user.Name {
				t.Fatalf("Process() returned wrong user")
			}
		})
	}
}

func TestLoadKey(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x10}, 32))

	t.Run("from env", func(t *testing.T) {
		t.Setenv("KNOCK_KEY", valid)
		key, err := loadKey("")
		if err != nil {
			t.Fatalf("loadKey() unexpected error: %v", err)
		}
		if len(key) != 32 {
			t.Fatalf("loadKey() returned %d bytes, want 32", len(key))
		}
	})

	t.Run("file wins over env", func(t *testing.T) {
		t.Setenv("KNOCK_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x99}, 32)))
		path := filepath.Join(t.TempDir(), "key")
		// trailing newline is what an editor or `echo` will leave behind
		if err := os.WriteFile(path, []byte(valid+"\n"), 0o600); err != nil {
			t.Fatalf("WriteFile() unexpected error: %v", err)
		}

		key, err := loadKey(path)
		if err != nil {
			t.Fatalf("loadKey() unexpected error: %v", err)
		}
		if !bytes.Equal(key, bytes.Repeat([]byte{0x10}, 32)) {
			t.Fatalf("loadKey() returned the env key, want the file key")
		}
	})

	t.Run("rejects wrong length", func(t *testing.T) {
		t.Setenv("KNOCK_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x10}, 16)))
		if _, err := loadKey(""); err == nil {
			t.Fatalf("loadKey() expected error for 16 byte key")
		}
	})

	t.Run("rejects missing key", func(t *testing.T) {
		t.Setenv("KNOCK_KEY", "")
		if _, err := loadKey(""); err == nil {
			t.Fatalf("loadKey() expected error when no key is configured")
		}
	})
}
