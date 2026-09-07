package spa

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("alice\n1700000000\ntcp\n22\n")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}
	if len(ciphertext) <= 16 {
		t.Fatalf("Encrypt() returned too-short ciphertext")
	}

	decrypted, err := Decrypt(key, append([]byte(nil), ciphertext...))
	if err != nil {
		t.Fatalf("Decrypt() unexpected error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt() plaintext mismatch")
	}
}

func TestDecryptRejectsTruncatedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, 32)
	plaintext := []byte("payload")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}

	truncated := append([]byte(nil), ciphertext[:len(ciphertext)-1]...)
	if _, err := Decrypt(key, truncated); err == nil {
		t.Fatalf("Decrypt() expected error for truncated ciphertext")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x29}, 32)
	plaintext := []byte("single packet authorization")

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt() unexpected error: %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatalf("Decrypt() expected error for tampered ciphertext")
	}
}
