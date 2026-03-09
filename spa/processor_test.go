package spa

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"fwknock/config"
	"net"
	"testing"
	"time"
)

func testProcessorFixture() (*Processor, config.User, config.Rule) {
	user := config.User{
		Name:         "alice",
		AESKeyBytes:  bytes.Repeat([]byte{0x10}, 32),
		HMACKeyBytes: bytes.Repeat([]byte{0x20}, 32),
	}
	rule := config.Rule{
		Name:         "ssh",
		KnockPort:    62201,
		OpenProto:    "tcp",
		OpenPort:     22,
		OpenTime:     15,
		AllowedUsers: []string{"alice"},
	}
	processor := NewProcessor([]config.User{user}, []config.Rule{rule})
	return processor, user, rule
}

func makePayloadFromPlaintext(t *testing.T, user config.User, plaintext []byte) []byte {
	t.Helper()

	ciphertext, err := Encrypt(user.AESKeyBytes, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}
	hmac := ComputeHMAC(user.HMACKeyBytes, ciphertext)

	return []byte(base64.StdEncoding.EncodeToString(ciphertext) + ":" + base64.StdEncoding.EncodeToString(hmac))
}

func makePayload(t *testing.T, user config.User, username string, timestamp time.Time, openProto string, openPort uint16) []byte {
	t.Helper()

	plaintext := []byte(fmt.Sprintf("%s\n%d\n%s\n%d\n", username, timestamp.Unix(), openProto, openPort))
	return makePayloadFromPlaintext(t, user, plaintext)
}

func TestProcessorProcessAcceptsValidPayload(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	payload := makePayload(t, user, user.Name, time.Now(), rule.OpenProto, rule.OpenPort)

	matchedRule, matchedUser, err := processor.Process(payload, rule.KnockPort, net.ParseIP("203.0.113.10"))
	if err != nil {
		t.Fatalf("Process() unexpected error: %v", err)
	}
	if matchedRule == nil || matchedRule.Name != rule.Name {
		t.Fatalf("Process() returned wrong rule")
	}
	if matchedUser == nil || matchedUser.Name != user.Name {
		t.Fatalf("Process() returned wrong user")
	}
}

func TestProcessorProcessRejectsInvalidHMAC(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	payload := makePayload(t, user, user.Name, time.Now(), rule.OpenProto, rule.OpenPort)

	parts := bytes.SplitN(payload, []byte{':'}, 2)
	hmacPart, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatalf("DecodeString() unexpected error: %v", err)
	}
	hmacPart[0] ^= 0xFF

	tamperedPayload := []byte(string(parts[0]) + ":" + base64.StdEncoding.EncodeToString(hmacPart))
	_, _, err = processor.Process(tamperedPayload, rule.KnockPort, net.ParseIP("203.0.113.10"))
	if !errors.Is(err, ErrSPARejected) {
		t.Fatalf("Process() expected ErrSPARejected, got: %v", err)
	}
}

func TestProcessorProcessRejectsReplay(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	payload := makePayload(t, user, user.Name, time.Now(), rule.OpenProto, rule.OpenPort)
	srcIP := net.ParseIP("203.0.113.10")

	if _, _, err := processor.Process(payload, rule.KnockPort, srcIP); err != nil {
		t.Fatalf("first Process() unexpected error: %v", err)
	}

	_, _, err := processor.Process(payload, rule.KnockPort, srcIP)
	if !errors.Is(err, ErrSPARejected) {
		t.Fatalf("second Process() expected ErrSPARejected, got: %v", err)
	}
}

func TestProcessorProcessRejectsExpiredTimestamp(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	payload := makePayload(t, user, user.Name, time.Now().Add(-2*time.Minute), rule.OpenProto, rule.OpenPort)

	_, _, err := processor.Process(payload, rule.KnockPort, net.ParseIP("203.0.113.10"))
	if !errors.Is(err, ErrSPARejected) {
		t.Fatalf("Process() expected ErrSPARejected for expired timestamp, got: %v", err)
	}
}

func TestProcessorProcessRejectsProtoPortMismatch(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	payload := makePayload(t, user, user.Name, time.Now(), "udp", 53)

	_, _, err := processor.Process(payload, rule.KnockPort, net.ParseIP("203.0.113.10"))
	if !errors.Is(err, ErrSPARejected) {
		t.Fatalf("Process() expected ErrSPARejected for proto/port mismatch, got: %v", err)
	}
}

func TestProcessorProcessMalformedDecryptedPayloadDoesNotPanic(t *testing.T) {
	processor, user, rule := testProcessorFixture()
	plaintext := []byte(fmt.Sprintf("%s\n%d\n", user.Name, time.Now().Unix()))
	payload := makePayloadFromPlaintext(t, user, plaintext)

	didPanic := false
	var err error

	func() {
		defer func() {
			if recover() != nil {
				didPanic = true
			}
		}()
		_, _, err = processor.Process(payload, rule.KnockPort, net.ParseIP("203.0.113.10"))
	}()

	if didPanic {
		t.Fatalf("Process() panicked on malformed decrypted payload")
	}
	if !errors.Is(err, ErrSPARejected) {
		t.Fatalf("Process() expected ErrSPARejected for malformed decrypted payload, got: %v", err)
	}
}
