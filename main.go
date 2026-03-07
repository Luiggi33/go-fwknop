package main

import (
	"context"
	"errors"
	"flag"
	"fwknock/config"
	"fwknock/firewall"
	"fwknock/spa"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"go.yaml.in/yaml/v3"
)

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

	firewallManager, err := firewall.NewFirewallManager(config.NFTablesTableName, config.NFTablesChainName)
	if err != nil {
		log.Fatalf("Error creating nftables manager: %v", err)
	}
	defer firewallManager.Conn.CloseLasting()

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
			if !errors.Is(err, firewall.ErrRuleExists) {
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
