package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/ngrok/firewall_toolkit/pkg/expressions"
	"github.com/ngrok/firewall_toolkit/pkg/rule"
)

type RuleKey struct {
	SrcIP     string
	OpenPort  uint16
	OpenProto string
}

func (r RuleKey) String() string {
	return fmt.Sprintf("%s:%s:%d", r.SrcIP, r.OpenProto, r.OpenPort)
}

type NFTablesManager struct {
	conn        *nftables.Conn
	table       *nftables.Table
	chain       *nftables.Chain
	activeRules map[RuleKey]uint64
	mu          sync.Mutex
}

var ErrRuleExists = errors.New("rule already active")

func (f *NFTablesManager) AddRule(srcIP net.IP, openPort uint16, openProto string) error {
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

func (f *NFTablesManager) RevokeRule(srcIP net.IP, openPort uint16, openProto string) error {
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

func (f *NFTablesManager) CleanupRules() error {
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

func (f *NFTablesManager) Close() error {
	if err := f.conn.CloseLasting(); err != nil {
		return err
	}
	return nil
}

func NewNFTablesManager(tableName, chainName string) (*NFTablesManager, error) {
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

	return &NFTablesManager{
		conn:        conn,
		table:       table,
		chain:       chain,
		activeRules: make(map[RuleKey]uint64),
	}, nil
}
