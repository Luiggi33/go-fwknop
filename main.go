package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	DEVICE         = "lo"
	KNOCKING_PORT  = 8000
	KNOCKING_PROTO = "udp"
)

func main() {
	handle, err := pcap.OpenLive(DEVICE, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	handle.SetBPFFilter(fmt.Sprintf("%s dst port %d", KNOCKING_PROTO, KNOCKING_PORT))

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

		var destPort uint16

		if tl := packet.TransportLayer(); tl != nil {
			switch v := tl.(type) {
			case *layers.UDP:
				destPort = uint16(v.DstPort)
			case *layers.TCP:
				destPort = uint16(v.DstPort)
			}
		}

		fmt.Println(srcIP, " ", destPort)
	}
}
