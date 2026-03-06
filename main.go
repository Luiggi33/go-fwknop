package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"fwknock/config"
	"fwknock/spa"
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

// TODO: Move out into own package!
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

var ErrRuleExists = errors.New("rule already active")

func (f *FirewallManager) AddRule(srcIP net.IP, openPort uint16, openProto string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	ruleKey := RuleKey{
		SrcIP:     srcIP.String(),
		OpenPort:  openPort,
		OpenProto: openProto,
	}

	if _, exists := f.activeRules[ruleKey]; exists {
		return ErrRuleExists
	}

	parsedIP, err := netip.ParseAddr(srcIP.String())
	if err != nil {
		return err
	}
	parsedIP = parsedIP.Unmap()

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

	log.Printf("added firewall rule: %s -> %s port %d\n", srcIP, openProto, openPort)

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

	log.Printf("revoked firewall rule: %s -> %s port %d\n", srcIP, openProto, openPort)

	return nil
}

func (f *FirewallManager) CleanupRules() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, handle := range f.activeRules {
		f.conn.DelRule(&nftables.Rule{
			Table:  f.table,
			Chain:  f.chain,
			Handle: handle,
		})
	}

	if err := f.conn.Flush(); err != nil {
		return fmt.Errorf("failed to cleanup rule: %w", err)
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

	conn.FlushTable(table)

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

func main() {
	configFile := flag.String("config-file", "config.yaml", "config file that should be used")
	flag.Parse()

	var config config.Config
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

	if err := handle.SetBPFFilter(config.AccessRulesToBpfFilter()); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf("Successfully started knock listener on device \"%s\"\n", config.Device)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	processor := spa.NewProcessor(config.Users, config.Rules)
	processor.StartEviction(ctx, 60*time.Second)

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

		if srcIP == nil || destProto == "" {
			continue
		}

		rule, ok := config.FindMatchingRule(destPort)
		if !ok {
			continue
		}

		if err := firewallManager.AddRule(srcIP, rule.OpenPort, rule.OpenProto); err != nil {
			if !errors.Is(err, ErrRuleExists) {
				log.Printf("Firewall Manager couldn't add rule: %s! See %v\n", rule.String(), err)
			}
			continue
		}

		capturedIP := make(net.IP, len(srcIP))
		copy(capturedIP, srcIP)

		time.AfterFunc(time.Duration(rule.OpenTime)*time.Second, func() {
			if err := firewallManager.RevokeRule(capturedIP, rule.OpenPort, rule.OpenProto); err != nil {
				log.Printf("Firewall Manager couldn't remove rule %s, error: %v\n", rule.String(), err)
			}
		})
	}
}
