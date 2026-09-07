// Command client sends a single SPA packet to a go-fw-knop daemon.
package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"fwknock/spa"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	log.SetFlags(0)
	if err := run(); err != nil {
		log.Fatalf("client: %v", err)
	}
}

func run() error {
	server := flag.String("server", "", "host running the knock daemon (required)")
	knockPort := flag.Uint("knock-port", 0, "UDP port the daemon listens on (required)")
	username := flag.String("user", "", "username configured on the daemon (required)")
	openProto := flag.String("proto", "tcp", "protocol to open")
	openPort := flag.Uint("port", 22, "port to open")
	sourceIP := flag.String("source-ip", "", "source IP as the daemon sees it; only needed behind NAT")
	keyFile := flag.String("key-file", "", "file holding the base64 AES key (default: $KNOCK_KEY)")
	flag.Parse()

	switch {
	case *server == "":
		return errors.New("-server is required")
	case *knockPort == 0 || *knockPort > 65535:
		return errors.New("-knock-port must be between 1 and 65535")
	case *username == "":
		return errors.New("-user is required")
	case *openPort == 0 || *openPort > 65535:
		return errors.New("-port must be between 1 and 65535")
	case *openProto != "tcp" && *openProto != "udp":
		return errors.New("-proto must be tcp or udp")
	}

	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}

	// Dial performs the route lookup and binds a local address without sending
	// anything, so LocalAddr is exactly the source IP this datagram will carry.
	conn, err := net.Dial("udp", net.JoinHostPort(*server, strconv.FormatUint(uint64(*knockPort), 10)))
	if err != nil {
		return fmt.Errorf("dialing %s: %w", *server, err)
	}
	defer conn.Close()

	srcIP := conn.LocalAddr().(*net.UDPAddr).IP
	if *sourceIP != "" {
		if srcIP = net.ParseIP(*sourceIP); srcIP == nil {
			return fmt.Errorf("invalid -source-ip %q", *sourceIP)
		}
	}

	plaintext := buildPayload(*username, time.Now(), *openProto, uint16(*openPort), srcIP)
	ciphertext, err := spa.Encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypting payload: %w", err)
	}

	if _, err := conn.Write([]byte(base64.StdEncoding.EncodeToString(ciphertext))); err != nil {
		return fmt.Errorf("sending knock: %w", err)
	}

	log.Printf("knock sent to %s for %s/%d from %s", conn.RemoteAddr(), *openProto, *openPort, srcIP)
	return nil
}

// buildPayload lays out the plaintext the daemon's processor expects:
// [username\n][unix_timestamp\n][open_proto\n][open_port\n][src_ip\n]
func buildPayload(username string, timestamp time.Time, openProto string, openPort uint16, srcIP net.IP) []byte {
	return fmt.Appendf(nil, "%s\n%d\n%s\n%d\n%s\n", username, timestamp.Unix(), openProto, openPort, srcIP)
}

// loadKey reads the base64 AES key from a file, or from $KNOCK_KEY. It is
// deliberately not a flag: flag values leak into shell history and ps output.
func loadKey(path string) ([]byte, error) {
	encoded := os.Getenv("KNOCK_KEY")
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file: %w", err)
		}
		encoded = string(data)
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("no AES key: set $KNOCK_KEY or pass -key-file")
	}

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding AES key: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}
