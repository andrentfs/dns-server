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

// ROOT_SERVERS lista alguns servidores raiz da Internet.
// A resolucao recursiva comeca neles porque a raiz sabe indicar quem cuida
// dos TLDs, como .br, .com, .org etc.
const ROOT_SERVERS = "198.41.0.4,199.9.14.201,192.33.4.12, 199.7.91.13, 192.203.230.10, 192.5.5.241, 192.112.36.4,198.97.190.53"

// maxIterativeSteps evita loop infinito caso algum servidor responda de forma
// inesperada ou a cadeia de delegacoes nao leve a uma resposta final.
const maxIterativeSteps = 8

var debugLogger = log.New(os.Stdout, "[dns-debug] ", log.LstdFlags|log.Lmicroseconds)

// HandlePacket e a borda publica do pacote: recebe os bytes crus do cliente e
// delega o trabalho real para handlePacket, apenas registrando erros.
func HandlePacket(pc net.PacketConn, addr net.Addr, buf []byte) {
	if err := handlePacket(pc, addr, buf); err != nil {
		fmt.Printf("handlePacket error [%s]: %s\n", addr.String(), err)
	}
}

func handlePacket(pc net.PacketConn, addr net.Addr, buf []byte) error {
	// Parser le um pacote DNS sem precisar desmontar manualmente byte a byte.
	// Start interpreta o header DNS, onde ficam campos como ID, flags e RCode.
	p := dnsmessage.Parser{}
	header, err := p.Start(buf)
	if err != nil {
		return err
	}

	// Este servidor didatico considera uma consulta com uma pergunta.
	// A pergunta tem o nome consultado, o tipo de registro e a classe.
	question, err := p.Question()
	if err != nil {
		return err
	}
	debugf("Cliente %s perguntou por %s (%s). Vamos resolver passo a passo, como um DNS recursivo.", addr.String(), question.Name.String(), question.Type.String())

	// A partir daqui o codigo se comporta como um resolvedor recursivo:
	// comeca nos servidores raiz e vai seguindo delegacoes ate o autoritativo.
	response, err := dnsQuery(gerRootServers(), question)
	if err != nil {
		return err
	}

	// O cliente espera receber de volta o mesmo ID da consulta original.
	// Esse ID permite que ele relacione a resposta com a pergunta que fez.
	response.Header.ID = header.ID
	responseBuffer, err := response.Pack()
	if err != nil {
		return err
	}

	// Escreve a resposta DNS ja empacotada para o endereco UDP que perguntou.
	_, err = pc.WriteTo(responseBuffer, addr)
	if err != nil {
		return err
	}
	return nil
}

func dnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Message, error) {
	return dnsQueryWithExchanger(servers, question, outgoingDnsQuery)
}

// dnsExchanger e uma abstracao pequena para permitir testes.
// Em producao ela aponta para outgoingDnsQuery, que faz UDP real.
// Nos testes ela pode ser substituida por uma funcao fake.
type dnsExchanger func([]net.IP, dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error)

func dnsQueryWithExchanger(servers []net.IP, question dnsmessage.Question, exchange dnsExchanger) (*dnsmessage.Message, error) {
	return dnsQueryWithExchangerDepth(servers, question, exchange, 0)
}

func dnsQueryWithExchangerDepth(servers []net.IP, question dnsmessage.Question, exchange dnsExchanger, depth int) (*dnsmessage.Message, error) {
	debugf("=== INÍCIO DA RESOLUÇÃO RECURSIVA ===")
	debugf("Pergunta original do cliente: nome=%s tipo=%s classe=%s", question.Name.String(), question.Type.String(), question.Class.String())
	debugf("Ideia do DNS: se eu não sei a resposta, pergunto para quem está mais acima na árvore. Primeiro passo: servidores raiz.")

	// currentServers representa "quem vamos perguntar agora".
	// No primeiro passo sao servidores raiz; depois viram servidores de TLD,
	// servidores autoritativos da zona, e assim por diante.
	currentServers := servers
	for i := 0; i < maxIterativeSteps; i++ {
		debugf("--- PASSO %d ---", i+1)
		debugf("Servidores que podem ajudar neste passo: %s", formatServers(currentServers))
		if i == 0 {
			debugf("Estes são servidores RAIZ: eles conhecem a raiz da árvore DNS e indicam quem cuida de TLDs como .com, .br, .org.")
		} else {
			debugf("Estes servidores vieram da resposta anterior. Agora o resolver desce mais um nível na árvore DNS.")
		}

		// Envia a mesma pergunta para um dos servidores conhecidos neste nivel.
		// A resposta pode ser final ou apenas uma delegacao para outro servidor.
		dnsAnswer, header, err := exchange(currentServers, question)
		if err != nil {
			return nil, err
		}

		// ANSWER contem respostas diretas para a pergunta.
		// Exemplo: "www.exemplo.com. A 203.0.113.10".
		parsedAnswers, err := dnsAnswer.AllAnswers()
		if err != nil {
			return nil, err
		}
		debugResources("ANSWER", "respostas diretas para a pergunta. Se o servidor for autoritativo, normalmente é aqui que está o resultado final.", parsedAnswers)

		// AUTHORITY e ADDITIONAL tambem precisam ser lidas antes de decidir.
		// Mesmo uma resposta autoritativa sem ANSWER pode trazer SOA em AUTHORITY,
		// que indica NODATA: o nome existe, mas nao tem aquele tipo de registro.
		authorities, err := dnsAnswer.AllAuthorities()
		if err != nil {
			return nil, err
		}
		additionals, err := dnsAnswer.AllAdditionals()
		if err != nil {
			return nil, err
		}

		// Se Authoritative=true, o servidor consultado e dono da zona.
		// Nesse ponto paramos a recursao e devolvemos exatamente as secoes
		// relevantes ao cliente.
		if header.Authoritative {
			debugf("Decisão: o bit Authoritative=true veio ligado. Isso significa que o servidor consultado tem autoridade sobre este nome.")
			debugf("Fim: vou devolver ao cliente as %d resposta(s) da seção ANSWER.", len(parsedAnswers))
			return &dnsmessage.Message{
				Header:      dnsmessage.Header{Response: true},
				Questions:   []dnsmessage.Question{question},
				Answers:     parsedAnswers,
				Authorities: authorities,
				Additionals: additionals,
			}, nil
		}

		// Se ainda nao e autoritativo, a resposta deve trazer uma delegacao:
		// registros NS na secao AUTHORITY apontando o proximo conjunto de DNS.
		debugf("Decisão: Authoritative=false. Ainda não é a resposta final; precisamos olhar AUTHORITY e ADDITIONAL para descobrir o próximo DNS.")
		debugResources("AUTHORITY", "delegações. Aqui aparecem registros NS dizendo quais nameservers cuidam da próxima zona.", authorities)

		// Sem AUTHORITY nao ha para onde continuar. Este resolvedor simples
		// transforma essa situacao em NameError para o cliente.
		if len(authorities) == 0 {
			debugf("Decisão: não veio nenhuma autoridade. Sem NS para continuar, retorno NameError para o cliente.")
			return &dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError},
				Questions: []dnsmessage.Question{question},
			}, nil
		}

		// A secao AUTHORITY normalmente traz registros NS: nomes dos servidores
		// responsaveis pelo proximo pedaco da arvore DNS.
		nameservers := []string{}
		for _, authority := range authorities {
			if authority.Header.Type == dnsmessage.TypeNS {
				ns := authority.Body.(*dnsmessage.NSResource).NS.String()
				nameservers = append(nameservers, ns)
				debugf("Authority: %s aponta para o nameserver %s", authority.Header.Name.String(), ns)
			}
		}

		debugResources("ADDITIONAL", "dados extras. Frequentemente traz glue records: IPs dos NS citados em AUTHORITY.", additionals)
		// A secao ADDITIONAL pode trazer glue records: IPs dos nameservers
		// listados em Authority. Com esses IPs podemos perguntar diretamente
		// ao proximo nivel, sem precisar resolver o nome do nameserver antes.
		nextServers := glueServers(nameservers, additionals)
		if len(nextServers) == 0 {
			// Em muitas delegacoes, principalmente quando o NS esta fora da zona,
			// nao vem glue record. Nesse caso primeiro resolvemos o A do NS.
			debugf("Decisão: recebi nomes de NS em AUTHORITY, mas nenhum IP correspondente em ADDITIONAL.")
			debugf("Agora vou resolver o endereço A de cada nameserver, começando novamente pelos servidores raiz.")
			nextServers, err = resolveNameserverIPs(nameservers, exchange, depth+1)
			if err != nil {
				return nil, err
			}
			if len(nextServers) == 0 {
				debugf("Não consegui descobrir nenhum IP para os nameservers recebidos.")
				break
			}
			debugf("Decisão: resolvi %d nameserver(s). Próximo passo: perguntar diretamente para %s.", len(nextServers), formatServers(nextServers))
		} else {
			debugf("Decisão: encontrei %d glue record(s). Próximo passo: perguntar diretamente para %s.", len(nextServers), formatServers(nextServers))
		}

		// O proximo loop pergunta para os servidores descobertos nesta resposta.
		currentServers = nextServers
	}

	// Se o limite de passos acabou, devolvemos SERVFAIL.
	// Isso sinaliza que o servidor nao conseguiu completar a resolucao.
	debugf("Fim com falha: não foi possível concluir a resolução iterativa para %s dentro do limite de rodadas.", question.Name.String())
	return &dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeServerFailure},
		Questions: []dnsmessage.Question{question},
	}, nil
}

func glueServers(nameservers []string, additionals []dnsmessage.Resource) []net.IP {
	nextServers := []net.IP{}

	// Glue record e um A/AAAA em ADDITIONAL para um nameserver citado em NS.
	// Aqui usamos apenas A porque o resolvedor didatico consulta IPv4.
	for _, additional := range additionals {
		if additional.Header.Type != dnsmessage.TypeA {
			continue
		}
		for _, nameserver := range nameservers {
			if additional.Header.Name.String() == nameserver {
				ip := net.IP(additional.Body.(*dnsmessage.AResource).A[:])
				nextServers = append(nextServers, ip)
				debugf("Additional/glue: %s tem IP %s. Esse sera um dos proximos DNS consultados.", nameserver, ip.String())
			}
		}
	}
	return nextServers
}

func resolveNameserverIPs(nameservers []string, exchange dnsExchanger, depth int) ([]net.IP, error) {
	// Esta funcao e uma resolucao auxiliar: antes de continuar a pergunta
	// original, precisamos descobrir o IP do nameserver que recebemos por nome.
	if depth > maxIterativeSteps {
		debugf("Limite de resolução auxiliar atingido ao tentar descobrir IP de nameserver.")
		return nil, nil
	}

	servers := []net.IP{}
	for _, nameserver := range nameservers {
		nsName, err := dnsmessage.NewName(nameserver)
		if err != nil {
			return nil, err
		}
		debugf("Resolvendo IP do nameserver %s com uma consulta A auxiliar.", nameserver)

		// Resolver o nameserver tambem segue a hierarquia DNS normal.
		// Por isso a consulta auxiliar recomeca nos servidores raiz.
		response, err := dnsQueryWithExchangerDepth(gerRootServers(), dnsmessage.Question{
			Name:  nsName,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}, exchange, depth)
		if err != nil {
			return nil, err
		}
		for _, answer := range response.Answers {
			if answer.Header.Type != dnsmessage.TypeA {
				continue
			}
			ip := net.IP(answer.Body.(*dnsmessage.AResource).A[:])
			servers = append(servers, ip)
			debugf("Nameserver %s resolvido para %s.", nameserver, ip.String())
		}

		// Um IP ja e suficiente para continuar a resolucao original.
		// O codigo tenta o proximo nameserver apenas se este nao tiver A.
		if len(servers) > 0 {
			return servers, nil
		}
	}
	return servers, nil
}

func outgoingDnsQuery(servers []net.IP, question dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	debugf("Montando pacote DNS UDP.")
	debugf("QUESTION que será enviada ao DNS remoto: nome=%s tipo=%s classe=%s", question.Name.String(), question.Type.String(), question.Class.String())

	// Cada consulta DNS tem um ID de 16 bits. Em um resolvedor real, esse ID
	// ajuda a conferir se a resposta recebida corresponde a consulta enviada.
	max := ^uint16(0)
	randonNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return nil, nil, err
	}

	// Monta uma mensagem DNS de consulta:
	// - Response=false significa que isto e pergunta, nao resposta.
	// - Questions carrega a pergunta que queremos fazer ao servidor remoto.
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
	debugf("Pacote montado: ID=%d QR=false Opcode=%d Questions=%d. Enviando por UDP/53.", message.Header.ID, message.Header.OpCode, len(message.Questions))

	// Tenta consultar os servidores em ordem. Se um nao conseguir abrir conexao,
	// tenta o proximo IP da lista recebida.
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

	// Le a resposta crua em bytes e depois entrega esses bytes ao Parser.
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

	// Servidores DNS normalmente ecoam a pergunta original na secao QUESTION.
	// Validar a quantidade ajuda a detectar resposta malformada.
	questions, err := p.AllQuestions()
	if err != nil {
		return nil, nil, err
	}
	if len(questions) != len(message.Questions) {
		return nil, nil, fmt.Errorf("answer packet doesn't have the same amount of questions")
	}
	debugf("SEÇÃO QUESTION ecoada pelo servidor remoto:")
	for _, answeredQuestion := range questions {
		debugf("  QUESTION nome=%s tipo=%s classe=%s", answeredQuestion.Name.String(), answeredQuestion.Type.String(), answeredQuestion.Class.String())
	}

	// Depois de registrar as perguntas, posicionamos o parser na proxima secao
	// para que quem chamou consiga ler ANSWER, AUTHORITY e ADDITIONAL.
	err = p.SkipAllQuestions()
	if err != nil {
		return nil, nil, err
	}

	return &p, &header, nil
}

func gerRootServers() []net.IP {
	rootServers := []net.IP{}

	// A constante e uma string para facilitar leitura/configuracao.
	// Aqui ela vira uma lista de net.IP pronta para as consultas UDP.
	for _, rootServer := range strings.Split(ROOT_SERVERS, ",") {
		rootServers = append(rootServers, net.ParseIP(strings.TrimSpace(rootServer)))
	}
	return rootServers
}

func debugf(format string, args ...any) {
	// Centraliza os logs didaticos para manter o prefixo e o formato iguais.
	debugLogger.Printf(format, args...)
}

func formatServers(servers []net.IP) string {
	formatted := make([]string, 0, len(servers))

	// Converte uma lista de IPs para texto legivel nos logs.
	for _, server := range servers {
		if server == nil {
			continue
		}
		formatted = append(formatted, server.String())
	}
	return strings.Join(formatted, ", ")
}

func debugResources(sectionName, explanation string, resources []dnsmessage.Resource) {
	// Imprime uma secao DNS de forma pedagogica, explicando o papel dela e
	// detalhando cada registro encontrado.
	debugf("SEÇÃO %s: %s", sectionName, explanation)
	if len(resources) == 0 {
		debugf("  %s vazia.", sectionName)
		return
	}
	for i, resource := range resources {
		debugf("  %s[%d] %s", sectionName, i+1, formatResource(resource))
	}
}

func formatResource(resource dnsmessage.Resource) string {
	// Cada tipo de registro DNS tem um corpo diferente.
	// O type switch extrai os campos mais importantes de cada um para o log.
	header := resource.Header
	prefix := fmt.Sprintf("nome=%s tipo=%s classe=%s ttl=%d", header.Name.String(), header.Type.String(), header.Class.String(), header.TTL)
	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		return fmt.Sprintf("%s valor=%s", prefix, net.IP(body.A[:]).String())
	case *dnsmessage.AAAAResource:
		return fmt.Sprintf("%s valor=%s", prefix, net.IP(body.AAAA[:]).String())
	case *dnsmessage.NSResource:
		return fmt.Sprintf("%s nameserver=%s", prefix, body.NS.String())
	case *dnsmessage.CNAMEResource:
		return fmt.Sprintf("%s canonical=%s", prefix, body.CNAME.String())
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%s preference=%d host=%s", prefix, body.Pref, body.MX.String())
	case *dnsmessage.TXTResource:
		return fmt.Sprintf("%s texto=%q", prefix, strings.Join(body.TXT, " "))
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s ns=%s mbox=%s serial=%d", prefix, body.NS.String(), body.MBox.String(), body.Serial)
	case *dnsmessage.PTRResource:
		return fmt.Sprintf("%s ptr=%s", prefix, body.PTR.String())
	default:
		return fmt.Sprintf("%s valor=%T", prefix, body)
	}
}
