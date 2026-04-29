package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

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
	dashboardPort := flag.Int("dashboard", 4040, "Web dashboard port")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cloudflare-inspector %s\n", version)
		fmt.Printf("  commit: %s\n", commit)
		fmt.Printf("  built:  %s\n", date)
		return
	}

	// Start web dashboard in background
	go func() {
		if err := StartDashboardServer(*dashboardPort, *port); err != nil {
			log.Printf("Dashboard server error: %v\n", err)
		}
	}()

	// Determine the loopback interface name based on OS
	iface := "lo0"
	if runtime.GOOS == "linux" {
		iface = "lo"
	}

	fmt.Printf("Starting HTTP monitor on port %d (interface: %s)\n", *port, iface)

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening interface %s: %v\n", iface, err)
		log.Println("Available interfaces:")
		devices, listErr := pcap.FindAllDevs()
		if listErr != nil {
			log.Printf("  Could not list interfaces: %v\n", listErr)
		} else {
			for _, dev := range devices {
				log.Printf("  - %s: %s\n", dev.Name, dev.Description)
			}
		}
		os.Exit(1)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp port %d", *port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Error setting BPF filter '%s': %v\n", filter, err)
		os.Exit(1)
	}

	streamFactory := &httpStreamFactory{capturePort: *port}
	pool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(pool)

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
