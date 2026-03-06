package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

type User struct {
	Name    string `yaml:"name"`
	AESKey  string `yaml:"aes_key"`
	HMACKey string `yaml:"hmac_key"`

	AESKeyBytes  []byte
	HMACKeyBytes []byte
}

type Rule struct {
	Name         string   `yaml:"name"`
	KnockPort    uint16   `yaml:"knock_port"`
	OpenProto    string   `yaml:"open_proto"`
	OpenPort     uint16   `yaml:"open_port"`
	OpenTime     uint16   `yaml:"open_time"`
	AllowedUsers []string `yaml:"allowed_users"`
}

func (r *Rule) String() string {
	return fmt.Sprintf("%s: udp %d -> %s %d (%d seconds)", r.Name, r.KnockPort, r.OpenProto, r.OpenPort, r.OpenTime)
}

type Config struct {
	Device            string `yaml:"listen_on_interface"`
	NFTablesTableName string `yaml:"nftables_table_name"`
	NFTablesChainName string `yaml:"nftables_chain_name"`
	Users             []User `yaml:"users"`
	Rules             []Rule `yaml:"rules"`
}

func (c *Config) Validate() error {
	if c.Device == "" {
		return errors.New("listen_on_interface is required")
	}
	if len(c.Rules) == 0 {
		return errors.New("at least one access rule is required")
	}
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}
	seenUsername := make(map[string]bool)
	for i, user := range c.Users {
		aesBytes, err := base64.StdEncoding.DecodeString(user.AESKey)
		if err != nil {
			return fmt.Errorf("user %d: %s", i, err)
		}
		if len(aesBytes) != 32 {
			return fmt.Errorf("user %d: aes key in wrong format!", i)
		}
		user.AESKeyBytes = aesBytes

		hmacBytes, err := base64.StdEncoding.DecodeString(user.HMACKey)
		if err != nil {
			return fmt.Errorf("user %d: %s", i, err)
		}
		if len(hmacBytes) != 32 {
			return fmt.Errorf("user %d: hmac key in wrong format!", i)
		}
		user.HMACKeyBytes = hmacBytes

		if seenUsername[user.Name] {
			return fmt.Errorf("user %d: duplicated username %s", i, user.Name)
		}
		seenUsername[user.Name] = true
	}
	seenKnockPorts := make(map[uint16]bool)
	for i, rule := range c.Rules {
		if rule.KnockPort == 0 || rule.OpenPort == 0 {
			return fmt.Errorf("rule %d: ports must be non-zero", i)
		}
		if rule.OpenTime == 0 {
			return fmt.Errorf("rule %d: open_time must be non-zero", i)
		}

		if seenKnockPorts[rule.KnockPort] {
			return fmt.Errorf("rule %d: duplicated knock port %d", i, rule.KnockPort)
		}
		seenKnockPorts[rule.KnockPort] = true

		for _, username := range rule.AllowedUsers {
			if !seenUsername[username] {
				return fmt.Errorf("rule %d: unknown username %s", i, username)
			}
		}
	}
	return nil
}

func (c *Config) FindMatchingRule(port uint16) (Rule, bool) {
	for _, rule := range c.Rules {
		if rule.KnockPort == port {
			return rule, true
		}
	}
	return Rule{}, false
}

func (c *Config) AccessRulesToBpfFilter() string {
	parts := make([]string, 0, len(c.Rules))
	for _, rule := range c.Rules {
		parts = append(parts, fmt.Sprintf("(udp dst port %d)", rule.KnockPort))
	}
	return strings.Join(parts, " or ")
}
