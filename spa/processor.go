package spa

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fwknock/config"
	"log"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"
)

type Processor struct {
	users       []config.User
	rules       []config.Rule
	replayCache map[string]time.Time
	mu          sync.Mutex
}

func NewProcessor(users []config.User, rules []config.Rule) *Processor {
	p := &Processor{
		users:       users,
		rules:       rules,
		replayCache: make(map[string]time.Time),
	}
	return p
}

func (p *Processor) FindRuleByKnockPort(port uint16) *config.Rule {
	for i := range p.rules {
		if p.rules[i].KnockPort == port {
			return &p.rules[i]
		}
	}
	return nil
}

var ErrSPARejected = errors.New("SPA packet rejected")

func (p *Processor) Process(rawPayload []byte, knockPort uint16, srcIP net.IP) (*config.Rule, *config.User, error) {
	// base64(iv + ciphertext) + ":" + base64(HMAC-SHA256(iv + ciphertext))
	payloadParts := bytes.Split(rawPayload, []byte{':'})
	if len(payloadParts) != 2 {
		log.Printf("processor: payload has too many/too little parts")
		return nil, nil, ErrSPARejected
	}

	rule := p.FindRuleByKnockPort(knockPort)
	if rule == nil {
		log.Printf("processor: no matching rule found")
		return nil, nil, ErrSPARejected
	}

	ciphertextPayloadPart := make([]byte, len(payloadParts[0]))
	copy(ciphertextPayloadPart, payloadParts[0])

	ciphertextPart, err := base64.StdEncoding.DecodeString(string(ciphertextPayloadPart))
	if err != nil {
		log.Printf("processor: %s", err.Error())
		return nil, nil, ErrSPARejected
	}

	ciphertextPayloadTwo := make([]byte, len(payloadParts[1]))
	copy(ciphertextPayloadTwo, payloadParts[1])

	hmacPart, err := base64.StdEncoding.DecodeString(string(ciphertextPayloadTwo))
	if err != nil {
		log.Printf("processor: %s", err.Error())
		return nil, nil, ErrSPARejected
	}

	var matchedUser *config.User
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
		log.Printf("processor: no matching user found")
		return nil, nil, ErrSPARejected
	}

	payloadDigest := PayloadDigest(ciphertextPart)

	p.mu.Lock()
	defer p.mu.Unlock()

	_, inCache := p.replayCache[payloadDigest]
	if inCache {
		log.Printf("processor: potential replay attack!")
		return nil, nil, ErrSPARejected
	}

	// [username\n][unix_timestamp\n][open_proto\n][open_port\n]
	decryptedCiphertext, err := Decrypt(matchedUser.AESKeyBytes, ciphertextPart)
	if err != nil {
		return nil, nil, err
	}

	ciphertextParts := bytes.Split(decryptedCiphertext, []byte{'\n'})
	if len(ciphertextParts) != 4 {
		log.Printf("processor: decrypted ciphertext has too many/too little parts")
		return nil, nil, ErrSPARejected
	}
	username := string(ciphertextParts[0])
	unixTimestampInt, err := strconv.Atoi(string(ciphertextParts[1]))
	if err != nil {
		return nil, nil, err
	}
	unixTimestamp := time.Unix(int64(unixTimestampInt), 0)
	openProto := string(ciphertextParts[2])
	openPort, err := strconv.ParseUint(string(ciphertextParts[3]), 0, 16)
	if err != nil {
		return nil, nil, err
	}

	if unixTimestamp.After(time.Now().Add(5*time.Second)) || unixTimestamp.Before(time.Now().Add(-60*time.Second)) {
		log.Printf("processor: timestamp seems unusual... replay attack?")
		return nil, nil, ErrSPARejected
	}

	if username != matchedUser.Name {
		log.Printf("processor: usernames don't match, somebody tampered!")
		return nil, nil, ErrSPARejected
	}

	if openProto != rule.OpenProto || uint16(openPort) != rule.OpenPort {
		log.Printf("processor: found rule and send rule dont match up, somebody tampered!")
		return nil, nil, ErrSPARejected
	}

	p.replayCache[payloadDigest] = time.Now()

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
