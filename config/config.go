package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
)

type User struct {
	Name   string `yaml:"name"`
	AESKey string `yaml:"aes_key"`

	AESKeyBytes []byte
}

type Rule struct {
	Name          string   `yaml:"name"`
	KnockPort     uint16   `yaml:"knock_port"`
	OpenProto     string   `yaml:"open_proto"`
	OpenPort      uint16   `yaml:"open_port"`
	OpenTime      uint16   `yaml:"open_time"`
	AllowedUsers  []string `yaml:"allowed_users"`
	AllowedIPs    []string `yaml:"allowed_ips"`
	AllowedIPNets []net.IPNet
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
	FirewallBackend   string `yaml:"firewall_backend"`
	MaxPacketLength   int32  `yaml:"max_packet_length"`
}

func (c *Config) Validate() error {
	if c.Device == "" {
		return errors.New("listen_on_interface is required")
	}
	if c.NFTablesTableName == "" {
		return errors.New("nftables_table_name is required")
	}
	if c.NFTablesChainName == "" {
		return errors.New("nftables_chain_name is required")
	}
	if len(c.Rules) == 0 {
		return errors.New("at least one access rule is required")
	}
	if len(c.Users) == 0 {
		return errors.New("at least one user is required")
	}
	if c.FirewallBackend == "" {
		return errors.New("firewall_backend is required")
	}
	if c.MaxPacketLength <= 0 {
		return errors.New("max_packet_length must be positive")
	}
	if c.MaxPacketLength > 65535 {
		return errors.New("max_packet_length must be at most 65535")
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
		c.Users[i].AESKeyBytes = aesBytes

		if seenUsername[user.Name] {
			return fmt.Errorf("user %d: duplicated username %s", i, user.Name)
		}
		seenUsername[user.Name] = true
	}
	seenKnockPorts := make(map[uint16]bool)
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d: name is required", i)
		}
		if rule.KnockPort == 0 || rule.OpenPort == 0 {
			return fmt.Errorf("rule %d: ports must be non-zero", i)
		}
		if rule.OpenTime == 0 {
			return fmt.Errorf("rule %d: open_time must be non-zero", i)
		}
		if rule.OpenProto != "tcp" && rule.OpenProto != "udp" {
			return fmt.Errorf("rule %d: open_proto must be tcp or udp", i)
		}

		if seenKnockPorts[rule.KnockPort] {
			return fmt.Errorf("rule %d: duplicated knock port %d", i, rule.KnockPort)
		}
		seenKnockPorts[rule.KnockPort] = true

		if len(rule.AllowedUsers) == 0 {
			return fmt.Errorf("rule %d: at least one allowed user is required", i)
		}
		for _, username := range rule.AllowedUsers {
			if !seenUsername[username] {
				return fmt.Errorf("rule %d: unknown username %s", i, username)
			}
		}

		if len(rule.AllowedIPs) == 0 {
			return fmt.Errorf("rule %d: at least one allowed IP is required", i)
		}
		for j, ip := range rule.AllowedIPs {
			if ip == "" {
				return fmt.Errorf("rule %d: allowed_ips contains empty string at index %d", i, j)
			}
			if ip == "*" {
				// special case: allow all IPs
				c.Rules[i].AllowedIPNets = []net.IPNet{
					{
						IP:   net.IPv4zero,
						Mask: net.CIDRMask(0, 32),
					},
				}
				continue
			}
			if !strings.Contains(ip, "/") {
				ip += "/32"
			}
			_, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				return fmt.Errorf("rule %d: invalid allowed_ip %s: %s", i, ip, err)
			}
			c.Rules[i].AllowedIPNets = append(c.Rules[i].AllowedIPNets, *ipnet)
		}
	}
	return nil
}

func (c *Config) AccessRulesToBpfFilter() string {
	parts := make([]string, 0, len(c.Rules))
	for _, rule := range c.Rules {
		parts = append(parts, fmt.Sprintf("(udp dst port %d)", rule.KnockPort))
	}
	return strings.Join(parts, " or ")
}
