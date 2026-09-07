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

const (
	// how far ahead of / behind our clock a payload timestamp may be
	maxClockSkew  = 5 * time.Second
	maxPayloadAge = 60 * time.Second
	// past this, a digest can never pass the timestamp check again
	replayWindow = maxPayloadAge + maxClockSkew
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
	// base64(Nonce[12] + AES-GCM-ciphertext + GCM-tag[16])
	rule := p.FindRuleByKnockPort(knockPort)
	if rule == nil {
		log.Printf("processor: no matching rule found")
		return nil, nil, ErrSPARejected
	}

	ciphertextPart, err := base64.StdEncoding.DecodeString(string(rawPayload))
	if err != nil {
		log.Printf("processor: %s", err.Error())
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

	var matchedUser *config.User
	var decryptedCiphertext []byte
	for i, user := range p.users {
		if !slices.Contains(rule.AllowedUsers, user.Name) {
			continue
		}
		decryptedCiphertxt, err := Decrypt(user.AESKeyBytes, ciphertextPart)
		if err == nil {
			matchedUser = &p.users[i]
			decryptedCiphertext = decryptedCiphertxt
			break
		}
	}
	if matchedUser == nil {
		log.Printf("processor: no matching user found")
		return nil, nil, ErrSPARejected
	}

	// decryptedCiphertext = [username\n][unix_timestamp\n][open_proto\n][open_port\n][src_ip\n]
	ciphertextParts := bytes.Split(decryptedCiphertext, []byte{'\n'})
	if len(ciphertextParts) == 6 && len(ciphertextParts[5]) == 0 {
		ciphertextParts = ciphertextParts[:5]
	}
	if len(ciphertextParts) != 5 {
		log.Printf("processor: decrypted ciphertext has too many/too little parts")
		return nil, nil, ErrSPARejected
	}
	username := string(ciphertextParts[0])
	unixTimestampInt, err := strconv.Atoi(string(ciphertextParts[1]))
	if err != nil {
		return nil, nil, ErrSPARejected
	}
	unixTimestamp := time.Unix(int64(unixTimestampInt), 0)
	openProto := string(ciphertextParts[2])
	openPort, err := strconv.ParseUint(string(ciphertextParts[3]), 10, 16)
	if err != nil {
		return nil, nil, ErrSPARejected
	}
	srcIPStr := string(ciphertextParts[4])
	if !net.ParseIP(srcIPStr).Equal(srcIP) {
		log.Printf("processor: source IP in decrypted payload doesn't match actual source IP, somebody tampered!")
		return nil, nil, ErrSPARejected
	}

	allowed := false
	for _, ipnet := range rule.AllowedIPNets {
		if ipnet.Contains(srcIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		log.Printf("processor: source IP %s is not allowed to knock for this rule", srcIP.String())
		return nil, nil, ErrSPARejected
	}

	now := time.Now()
	if unixTimestamp.After(now.Add(maxClockSkew)) || unixTimestamp.Before(now.Add(-maxPayloadAge)) {
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

func (p *Processor) StartEviction(ctx context.Context) {
	ticker := time.NewTicker(replayWindow / 4)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cutoff := time.Now().Add(-replayWindow)
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
