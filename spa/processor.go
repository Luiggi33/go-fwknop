package spa

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	main "fwknock"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

type Processor struct {
	users       []main.User
	rules       []main.Rule
	replayCache map[string]time.Time
	mu          sync.Mutex
}

func NewProcessor(users []main.User, rules []main.Rule) *Processor {
	p := &Processor{
		users:       users,
		rules:       rules,
		replayCache: make(map[string]time.Time),
	}
	return p
}

func (p *Processor) FindRuleByKnockPort(port uint16) *main.Rule {
	for i := range p.rules {
		if p.rules[i].KnockPort == port {
			return &p.rules[i]
		}
	}
	return nil
}

var ErrSPARejected = errors.New("SPA packet rejected")

func (p *Processor) Process(rawPayload []byte, knockPort uint16, srcIP net.IP) (*main.Rule, *main.User, error) {
	// base64(iv + ciphertext) + ":" + base64(HMAC-SHA256(iv + ciphertext))
	payloadParts := bytes.Split(rawPayload, []byte{':'})
	if len(payloadParts) != 2 {
		slog.Debug("payload has too many/too little parts")
		return nil, nil, ErrSPARejected
	}

	rule := p.FindRuleByKnockPort(knockPort)
	if rule == nil {
		slog.Debug("no matching rule found while processing")
		return nil, nil, ErrSPARejected
	}

	ciphertextPart, err := base64.StdEncoding.DecodeString(string(payloadParts[0]))
	if err != nil {
		slog.Debug("%w", err)
		return nil, nil, ErrSPARejected
	}
	hmacPart, err := base64.StdEncoding.DecodeString(string(payloadParts[1]))
	if err != nil {
		slog.Debug("%w", err)
		return nil, nil, ErrSPARejected
	}

	var matchedUser *main.User
	for _, user := range p.users {
		if !slices.Contains(rule.AllowedUsers, user.Name) {
			continue
		}
		if VerifyHMAC(user.HMACKeyBytes, ciphertextPart, hmacPart) {
			matchedUser = &user
			break
		}
	}
	if matchedUser == nil {
		slog.Debug("no matching user found")
		return nil, nil, ErrSPARejected
	}

	payloadDigest := PayloadDigest(ciphertextPart)

	p.mu.Lock()
	_, inCache := p.replayCache[payloadDigest]
	if inCache {
		slog.Debug("potential replay attack!")
		return nil, nil, ErrSPARejected
	}
	p.mu.Unlock()

	// [username\n][unix_timestamp\n][open_proto\n][open_port\n]
	decryptedCiphertext, err := Decrypt(matchedUser.AESKeyBytes, ciphertextPart)
	if err != nil {
		return nil, nil, err
	}

	ciphertextParts := bytes.Split(decryptedCiphertext, []byte{'\n'})
	username := string(ciphertextParts[0])
	unixTimestampInt, err := strconv.Atoi(string(ciphertextParts[1]))
	if err != nil {
		return nil, nil, err
	}
	unixTimestamp := time.Unix(int64(unixTimestampInt), 0)
	openProto := string(ciphertextParts[2])
	openPort, err := strconv.ParseUint(string(ciphertextParts[3]), 0, 16)

	if unixTimestamp.After(time.Now().Add(5*time.Second)) || unixTimestamp.Before(time.Now().Add(-60*time.Second)) {
		slog.Debug("timestamp seems unusual... replay attack?")
		return nil, nil, ErrSPARejected
	}

	if username != matchedUser.Name {
		slog.Debug("usernames don't match, somebody tampered!")
		return nil, nil, ErrSPARejected
	}

	if openProto != rule.OpenProto || uint16(openPort) != rule.OpenPort {
		slog.Debug("found rule and send rule dont match up, somebody tampered!")
		return nil, nil, ErrSPARejected
	}

	p.mu.Lock()
	p.replayCache[payloadDigest] = time.Now()
	p.mu.Unlock()

	return rule, matchedUser, nil
}

func (p *Processor) StartEviction(ctx context.Context, window time.Duration) {
	ticker := time.NewTicker(window / 4)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-window)
				p.mu.Lock()
				for digest, seen := range p.replayCache {
					if seen.Before(cutoff) {
						delete(p.replayCache, digest)
					}
				}
				p.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}
