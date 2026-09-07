package firewall

import "net"

type Manager interface {
	AddRule(srcIP net.IP, openPort uint16, openProto string) error
	RevokeRule(srcIP net.IP, openPort uint16, openProto string) error
	CleanupRules() error
	Close() error
}
