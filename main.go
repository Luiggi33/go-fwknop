package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"fwknock/config"
	"fwknock/firewall"
	"fwknock/spa"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"go.yaml.in/yaml/v3"
)

func newFirewallManager(cfg config.Config) (firewall.Manager, error) {
	switch cfg.FirewallBackend {
	case "nftables":
		return firewall.NewNFTablesManager(cfg.NFTablesTableName, cfg.NFTablesChainName)
	default:
		return nil, fmt.Errorf("unknown backend: %s", cfg.FirewallBackend)
	}
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

	firewallManager, err := newFirewallManager(config)
	if err != nil {
		log.Fatalf("Error creating firewall manager: %v", err)
	}
	defer firewallManager.Close()

	handle, err := pcap.OpenLive(config.Device, config.MaxPacketLength, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error starting listener: %v", err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(config.AccessRulesToBpfFilter()); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf("Successfully started knock listener on device \"%s\"\n", config.Device)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	processor := spa.NewProcessor(config.Users, config.Rules)
	processor.StartEviction(ctx)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			if err := firewallManager.CleanupRules(); err != nil {
				log.Printf("cleanup failed: %v", err)
			}
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				log.Println("packet sources isn't ok")
				if err := firewallManager.CleanupRules(); err != nil {
					log.Printf("cleanup failed: %v", err)
				}
				return
			}

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
				}
			}

			if srcIP == nil || destProto == "" {
				continue
			}

			rule := processor.FindRuleByKnockPort(destPort)
			if rule == nil {
				continue
			}

			var payload []byte
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload = appLayer.Payload()
			}
			if payload == nil {
				continue
			}

			matchedRule, user, err := processor.Process(payload, destPort, srcIP)
			if err != nil {
				log.Println(err.Error())
				continue
			}

			log.Printf("SPA accepted from %s for user %s, opening %s/%d for %ds",
				srcIP, user.Name, matchedRule.OpenProto, matchedRule.OpenPort, matchedRule.OpenTime)

			if err := firewallManager.AddRule(srcIP, matchedRule.OpenPort, matchedRule.OpenProto); err != nil {
				if !errors.Is(err, firewall.ErrRuleExists) {
					log.Printf("Firewall Manager couldn't add rule: %s! See %v\n", rule.String(), err)
				}
				continue
			}

			capturedIP := make(net.IP, len(srcIP))
			copy(capturedIP, srcIP)
			capturedRule := matchedRule

			time.AfterFunc(time.Duration(capturedRule.OpenTime)*time.Second, func() {
				if err := firewallManager.RevokeRule(capturedIP, capturedRule.OpenPort, capturedRule.OpenProto); err != nil {
					log.Printf("failed to revoke rule: %v", err)
				}
			})
		}
	}
}
