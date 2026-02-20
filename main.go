package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	DEVICE = "lo"
)

func main() {
	handle, err := pcap.OpenLive(DEVICE, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

	}
}
