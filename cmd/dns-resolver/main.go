package main

import (
	"fmt"
	"net"

	"github.com/andrentfs/dns-server/pkg/dns"
)

func main() {
	fmt.Printf("Starting DNS Server...\n")

	// Um servidor DNS tradicional recebe consultas via UDP na porta 53.
	// ListenPacket cria um socket UDP que consegue receber pacotes de varios
	// clientes sem precisar manter uma conexao dedicada para cada um.
	packetConection, err := net.ListenPacket("udp", ":53")
	if err != nil {
		panic(err)
	}
	defer packetConection.Close()

	for {
		// Pacotes DNS UDP normalmente cabem em 512 bytes no formato classico.
		// Este buffer recebe os bytes crus enviados pelo cliente, ainda sem
		// interpretar header, pergunta ou respostas.
		buf := make([]byte, 512)
		bytesRead, addr, err := packetConection.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Read error from %s: %s", addr.String(), err)
			continue
		}

		// Cada consulta e tratada em uma goroutine para o servidor poder receber
		// outras perguntas enquanto uma resolucao recursiva ainda esta em andamento.
		go dns.HandlePacket(packetConection, addr, buf[:bytesRead])
	}
}
