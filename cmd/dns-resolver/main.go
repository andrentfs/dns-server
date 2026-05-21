package main

import (
	"fmt"
	"net"

	"github.com/andrentfs/dns-server/pkg/dns"
)

func main() {
	fmt.Printf("Starting DNS Server...\n")
	packetConection, err := net.ListenPacket("udp", ":53")
	if err != nil {
		panic(err)
	}
	defer packetConection.Close()
	for {
		buf := make([]byte, 512)
		bytesRead, addr, err := packetConection.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Read error from %s: %s", addr.String(), err)
			continue
		}
		go dns.HandlePacket(packetConection, addr, buf[:bytesRead])
	}
}
