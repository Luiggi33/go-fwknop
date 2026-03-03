package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/rule"

	"go.yaml.in/yaml/v3"
)

type AccessRule struct {
	KnockProto string `yaml:"knock_proto"`
	KnockPort  uint16 `yaml:"knock_port"`
	OpenProto  string `yaml:"open_proto"`
	OpenPort   uint16 `yaml:"open_port"`
	OpenTime   uint16 `yaml:"open_time"`
}

func (accessRule *AccessRule) String() string {
	return fmt.Sprintf("Knock on %s port %d to open %s port %d for %d seconds", accessRule.KnockProto, accessRule.KnockPort, accessRule.OpenProto, accessRule.OpenPort, accessRule.OpenTime)
}

type Config struct {
	Device            string       `yaml:"listen_on_interface"`
	AccessRules       []AccessRule `yaml:"access_rules"`
	NFTablesTableName string       `yaml:"nftables_table_name"`
	NFTablesChainName string       `yaml:"nftables_chain_name"`
}

func (c *Config) Validate() error {
	if c.Device == "" {
		return errors.New("listen_on_interface is required")
	}
	for i, r := range c.AccessRules {
		proto := strings.ToLower(r.KnockProto)
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("rule %d: invalid knock_proto %q", i, r.KnockProto)
		}
		if r.KnockPort == 0 || r.OpenPort == 0 {
			return fmt.Errorf("rule %d: ports must be non-zero", i)
		}
		if r.OpenTime == 0 {
			return fmt.Errorf("rule %d: open_time must be non-zero", i)
		}
	}
	return nil
}

type RuleKey struct {
	SrcIP     string
	OpenPort  uint16
	OpenProto string
}

func (r RuleKey) String() string {
	return fmt.Sprintf("%s:%s:%d", r.SrcIP, r.OpenProto, r.OpenPort)
}

type FirewallManager struct {
	conn        *nftables.Conn
	table       *nftables.Table
	chain       *nftables.Chain
	activeRules map[RuleKey]uint64
	mu          sync.Mutex
}

func (f *FirewallManager) HasRule(srcIP net.IP, openPort uint16, openProto string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.activeRules[RuleKey{SrcIP: srcIP.String(), OpenPort: openPort, OpenProto: openProto}]
	return ok
}

func (f *FirewallManager) AddRule(srcIP net.IP, openPort uint16, openProto string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	parsedIP, err := netip.ParseAddr(srcIP.String())
	if err != nil {
		return err
	}

	var addressFamilyExpression expressions.AddrFamily
	if parsedIP.Is4() {
		addressFamilyExpression = expressions.IPv4
	} else {
		addressFamilyExpression = expressions.IPv6
	}

	var protoExpression expressions.TransportProto
	if strings.EqualFold(openProto, "tcp") {
		protoExpression = expressions.TCP
	} else {
		protoExpression = expressions.UDP
	}

	exprs, err := rule.Build(expr.VerdictAccept, rule.AddressFamily(addressFamilyExpression), rule.SourceAddress(parsedIP), rule.TransportProtocol(protoExpression), rule.DestinationPort(openPort))
	if err != nil {
		return err
	}

	ruleKey := RuleKey{
		SrcIP:     srcIP.String(),
		OpenPort:  openPort,
		OpenProto: openProto,
	}

	userData := []byte(ruleKey.String())

	ruleTarget := rule.NewRuleTarget(f.table, f.chain)
	ruleData := rule.NewRuleData(userData, exprs)
	_, err = ruleTarget.Add(f.conn, ruleData)
	if err != nil {
		return fmt.Errorf("adding rule to target: %w", err)
	}

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("flush rules: %w", err)
	}

	chainRules, err := f.conn.GetRules(f.table, f.chain)
	if err != nil {
		return fmt.Errorf("failed to get rules after insert: %w", err)
	}

	for _, r := range chainRules {
		if bytes.Equal(r.UserData, userData) {
			f.activeRules[ruleKey] = r.Handle
			break
		}
	}

	return nil
}

func (f *FirewallManager) RevokeRule(srcIP net.IP, openPort uint16, openProto string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := RuleKey{SrcIP: srcIP.String(), OpenPort: openPort, OpenProto: openProto}
	handle, ok := f.activeRules[key]
	if !ok {
		return nil
	}

	err := f.conn.DelRule(&nftables.Rule{
		Table:  f.table,
		Chain:  f.chain,
		Handle: handle,
	})
	if err != nil {
		return fmt.Errorf("failed to remove rule: %w", err)
	}

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("failed to remove rule: %w", err)
	}

	delete(f.activeRules, key)
	return nil
}

func (f *FirewallManager) CleanupRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, handle := range f.activeRules {
		err := f.conn.DelRule(&nftables.Rule{
			Table:  f.table,
			Chain:  f.chain,
			Handle: handle,
		})
		if err != nil {
			return fmt.Errorf("failed to cleanup rule: %w", err)
		}

		if err := f.conn.Flush(); err != nil {
			return fmt.Errorf("failed to cleanup rule: %w", err)
		}
	}

	clear(f.activeRules)

	return nil
}

func NewFirewallManager(tableName, chainName string) (*FirewallManager, error) {
	conn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to nftables: %w", err)
	}

	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet, // covers both IPv4 and IPv6
		Name:   tableName,
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     chainName,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})

	if err := conn.Flush(); err != nil {
		return nil, fmt.Errorf("failed to set up table/chain: %w", err)
	}

	return &FirewallManager{
		conn:        conn,
		table:       table,
		chain:       chain,
		activeRules: make(map[RuleKey]uint64),
	}, nil
}

func bpfFilterFromString(config *Config) string {
	if len(config.AccessRules) == 0 {
		log.Fatal("no access rules configured")
	}
	parts := make([]string, 0, len(config.AccessRules))
	for _, r := range config.AccessRules {
		parts = append(parts, fmt.Sprintf("(%s dst port %d)", r.KnockProto, r.KnockPort))
	}
	return strings.Join(parts, " or ")
}

func findMatchingRule(rules []AccessRule, proto string, port uint16) *AccessRule {
	for _, rule := range rules {
		if strings.EqualFold(rule.KnockProto, proto) && rule.KnockPort == port {
			return &rule
		}
	}
	return nil
}

func main() {
	configFile := flag.String("config-file", "config.yaml", "config file that should be used")
	flag.Parse()

	var config Config
	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file: %v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Error reading in config: %v", err)
	}
	if err := config.Validate(); err != nil {
		log.Fatalf("config couldnt be validated: %s", err)
	}

	firewallManager, err := NewFirewallManager(config.NFTablesTableName, config.NFTablesChainName)
	if err != nil {
		log.Fatalf("Error creating nftables manager: %v", err)
	}
	defer firewallManager.conn.CloseLasting()

	handle, err := pcap.OpenLive(config.Device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error starting listener: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(bpfFilterFromString(&config)); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf("Successfully started knock listener on device \"%s\"\n", config.Device)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			if err := firewallManager.CleanupRules(); err != nil {
				log.Printf("Your about to have a bad time, firewall couldnt be cleaned up: %v\n", err)
			}
			log.Printf("%s\n", sig.String())
			os.Exit(0)
		}
	}()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		var srcIP net.IP

		if nl := packet.NetworkLayer(); nl != nil {
			switch v := nl.(type) {
			case *layers.IPv4:
				srcIP = v.SrcIP
			case *layers.IPv6:
				srcIP = v.SrcIP
			}
		}

		var destProto string
		var destPort uint16

		if tl := packet.TransportLayer(); tl != nil {
			switch v := tl.(type) {
			case *layers.UDP:
				destPort = uint16(v.DstPort)
				destProto = "udp"
			case *layers.TCP:
				destPort = uint16(v.DstPort)
				destProto = "tcp"
			}
		}

		rule := findMatchingRule(config.AccessRules, destProto, destPort)
		if rule == nil {
			continue
		}

		if firewallManager.HasRule(srcIP, rule.OpenPort, rule.OpenProto) {
			log.Printf("knock was discarded, due to port being open for this IP already")
			continue
		}

		if err := firewallManager.AddRule(srcIP, rule.OpenPort, rule.OpenProto); err != nil {
			log.Printf("Firewall Manager coduln't add rule: %s! See %v\n", rule, err)
			continue
		}

		capturedIP := make(net.IP, len(srcIP))
		copy(capturedIP, srcIP)
		capturedRule := rule

		time.AfterFunc(time.Duration(rule.OpenTime)*time.Second, func() {
			if err := firewallManager.RevokeRule(capturedIP, capturedRule.OpenPort, capturedRule.OpenProto); err != nil {
				log.Printf("Firewall Manager couldn't remove rule: %s. this aint good: %v\n", capturedRule, err)
			}
		})
	}
}
