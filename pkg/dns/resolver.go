package dns

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12, 199.7.91.13, 192.203.230.10, 192.5.5.241, 192.112.36.4,198.97.190.53"

var debugLogger = log.New(os.Stdout, "[dns-debug] ", log.LstdFlags|log.Lmicroseconds)

func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("handlePacket error [%s]: %s\n", addr.String(), err)
	}
}

func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	p := dnsmessage.Parser{}
	header, err := p.Start(buf)
	if err != nil {
		return err
	}
	question, err := p.Question()
	if err != nil {
		return err
	}
	debugf("Cliente %s perguntou por %s (%s). Vamos resolver passo a passo, como um DNS recursivo.", addr.String(), question.Name.String(), question.Type.String())
	response, err := dnsQuery(gerRootServers(), question)
	if err != nil {
		return err
	}
	response.Header.ID = header.ID
	responseBuffer, err := response.Pack()
	if err != nil {
		return err
	}
	_, err = pc.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}
	return nil
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	return dnsQueryWithExchanger(servers, question, outgoingDnsQuery)
}

type dnsExchanger func([]net.IP, dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error)

func dnsQueryWithExchanger(servers []net.IP, question dnsmessage.Question, exchange dnsExchanger) (*dnsmessage.Message, error) {
	debugf("Iniciando resolução iterativa para %s. Primeiro passo: perguntar aos servidores raiz.", question.Name.String())
	currentServers := servers
	for i := 0; i < 3; i++ {
		debugf("Rodada %d: consultando %d servidor(es): %s", i+1, len(currentServers), formatServers(currentServers))
		dnsAnswer, header, err := exchange(currentServers, question)
		if err != nil {
			return nil, err
		}
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}
		if header.Authoritative {
			debugf("Resposta autoritativa recebida. O servidor consultado conhece a resposta final para %s.", question.Name.String())
			debugf("Total de respostas finais: %d", len(parsedAnswers))
			return &dnsmessage.Message{
				Header:  dnsmessage.Header{Response: true},
				Answers: parsedAnswers,
			}, nil
		}
		debugf("Ainda nao e a resposta final. O servidor devolveu %d resposta(s) e vai indicar proximos servidores DNS.", len(parsedAnswers))
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}

		if len(authorities) == 0 {
			debugf("Nenhuma autoridade foi retornada. Isso equivale a nome nao encontrado para esta consulta.")
			return &dnsmessage.Message{
				Header: dnsmessage.Header{RCode: dnsmessage.RCodeNameError},
			}, nil
		}

		// A secao Authority normalmente traz registros NS: nomes dos servidores
		// responsaveis pelo proximo pedaco da arvore DNS.
		nameservers := []string{}
		for _, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				ns := authority.Body.(*dnsmessage.NSResource).NS.String()
				nameservers = append(nameservers, ns)
				debugf("Authority: %s aponta para o nameserver %s", authority.Header.Name.String(), ns)
			}
		}

		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}
		newResolverServersFound := false
		nextServers := []net.IP{}
		// A secao Additional pode trazer glue records: IPs dos nameservers
		// listados em Authority. Com esses IPs podemos perguntar diretamente
		// ao proximo nivel, sem precisar resolver o nome do nameserver antes.
		for _, additional := range additionals {
			if additional.Header.Type == dnsmessage.TypeA {
				for _, nameserver := range nameservers {
					if additional.Header.Name.String() == nameserver {
						newResolverServersFound = true
						ip := net.IP(additional.Body.(*dnsmessage.AResource).A[:])
						nextServers = append(nextServers, ip)
						debugf("Additional/glue: %s tem IP %s. Esse sera um dos proximos DNS consultados.", nameserver, ip.String())
					}
				}
			}
		}
		if !newResolverServersFound {
			debugf("Recebemos NS, mas nenhum IP em Additional. Este exemplo ainda nao resolve o nome do nameserver separadamente.")
			break
		}
		currentServers = nextServers
	}

	debugf("Nao foi possivel concluir a resolucao iterativa para %s dentro do limite de rodadas.", question.Name.String())
	return &dnsmessage.Message{
		Header: dnsmessage.Header{RCode: dnsmessage.RCodeServerFailure},
	}, nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	debugf("Montando pacote DNS UDP para %s e enviando para %s.", question.Name.String(), formatServers(servers))
	max := ^uint16(0)
	randonNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:       uint16(randonNumber.Int64()),
			Response: false,
			OpCode:   dnsmessage.OpCode(0),
		},
		Questions: []dnsmessage.Question{question},
	}
	buf, err := message.Pack()
	if err != nil {
		return nil, nil, err
	}
	var conn net.Conn
	for _, server := range servers {
		debugf("Tentando abrir conexao UDP com DNS %s:53.", server.String())
		conn, err = net.Dial("udp", server.String()+":53")
		if err == nil {
			debugf("Conexao UDP pronta com %s:53.", server.String())
			break
		}
		debugf("Falha ao conectar em %s:53: %s", server.String(), err)
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("Failed to make connection to servers %s", err)
	}
	_, err = conn.Write(buf)
	if err != nil {
		return nil, nil, err
	}
	debugf("Consulta enviada. Aguardando resposta do DNS remoto.")

	answer := make([]byte, 512)
	n, err := bufio.NewReader(conn).Read(answer)
	if err != nil {
		return nil, nil, err
	}
	conn.Close()
	debugf("Resposta recebida com %d byte(s). Agora vamos parsear o pacote DNS.", n)
	var p dnsmessage.Parser
	header, err := p.Start(answer[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("parser start error: %s", err)
	}
	debugf("Header da resposta: RCode=%s Authoritative=%t Truncated=%t.", header.RCode.String(), header.Authoritative, header.Truncated)

	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}
	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesn't have the same amount of questions")
	}

	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

func gerRootServers() []net.IP {
	rootServers := []net.IP{}
	for _, rootServer := range strings.Split(ROOT_SERVERS, ",") {
		rootServers = append(rootServers, net.ParseIP(strings.TrimSpace(rootServer)))
	}
	return rootServers
}

func debugf(format string, args ...any) {
	debugLogger.Printf(format, args...)
}

func formatServers(servers []net.IP) string {
	formatted := make([]string, 0, len(servers))
	for _, server := range servers {
		if server == nil {
			continue
		}
		formatted = append(formatted, server.String())
	}
	return strings.Join(formatted, ", ")
}
