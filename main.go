package main

import (
	"flag"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	port := flag.Int("port", 8080, "Cloudflare tunnel port to monitor")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cloudflare-inspector %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		return
	}

	fmt.Printf("Starting HTTP monitor on port %d\n", *port)
	handle, _ := pcap.OpenLive("lo0", 65536, true, pcap.BlockForever)
	defer handle.Close()
	_ = handle.SetBPFFilter(fmt.Sprintf("tcp port %d", *port))

	streamFactory := &httpStreamFactory{}
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

	fmt.Println("Starting capture loop")

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			assembler.AssembleWithTimestamp(
				packet.NetworkLayer().NetworkFlow(),
				tcp.(*layers.TCP),
				packet.Metadata().Timestamp,
			)
		}
	}

	fmt.Println("Bye bye!")
}
