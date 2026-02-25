package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.yaml.in/yaml/v3"
)

type AccessRule struct {
	KnockProto string `yaml:"knock_proto"`
	KnockPort  uint16 `yaml:"knock_port"`
	OpenProto  string `yaml:"open_proto"`
	OpenPort   uint16 `yaml:"open_port"`
}

type Config struct {
	Device      string       `yaml:"listen_on_interface"`
	AccessRules []AccessRule `yaml:"access_rules"`
}

func bpfFilterFromString(config *Config) string {
	returnString := ""
	for _, accessRule := range config.AccessRules {
		returnString += fmt.Sprintf("(%s dst port %d) or ", accessRule.KnockProto, accessRule.KnockPort)
	}
	return strings.TrimSuffix(returnString, " or ")
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

	var config Config
	yamlFile, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("Error reading config file: %v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Error reading in config: %v", err)
	}

	handle, err := pcap.OpenLive(config.Device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error starting listener: %v", err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(bpfFilterFromString(&config))
	if err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	log.Printf("Successfully started knock listener on device \"%s\"\n", config.Device)

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

		log.Printf("Valid knock from %s\n", srcIP)
	}
}
