package dns

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type MockPacketConn struct{}

func (m *MockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

func (m *MockPacketConn) Close() error {
	return nil
}

func (m *MockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, nil, nil
}
func (m *MockPacketConn) LocalAddr() net.Addr {
	return nil
}
func (m *MockPacketConn) SetDeadline(t time.Time) error {
	return nil
}
func (m *MockPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (m *MockPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandlePacket(t *testing.T) {
	names := []string{"www.google.com.", "www.amazon.com."}
	for _, name := range names {
		max := ^uint16(0)
		randomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
		if err != nil {
			t.Fatalf("rand error: %s", err)
		}
		message := dnsmessage.Message{
			Header: dnsmessage.Header{
				RCode:            dnsmessage.RCode(0),
				ID:               uint16(randomNumber.Int64()),
				OpCode:           dnsmessage.OpCode(0),
				Response:         false,
				AuthenticData:    false,
				RecursionDesired: false,
			},
			Questions: []dnsmessage.Question{
				{
					Name:  dnsmessage.MustNewName(name),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				},
			},
		}
		buf, err := message.Pack()
		if err != nil {
			t.Fatalf("Pack error: %s", err)
		}

		err = handlePacket(&MockPacketConn{}, &net.IPAddr{IP: net.ParseIP("127.0.0.1")}, buf)
		if err != nil {
			t.Fatalf("serve error: %s", err)
		}
	}
}

func TestOutgoingDnsQuery(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("com."),
		Type:  dnsmessage.TypeNS,
		Class: dnsmessage.ClassINET,
	}

	if len(ROOT_SERVERS) == 0 {
		t.Fatalf("No root servers found")
	}

	rootServers := strings.Split(ROOT_SERVERS, ",")

	servers := []net.IP{net.ParseIP(rootServers[0])}
	dnsAnswer, header, err := outgoingDnsQuery(servers, question)
	if err != nil {
		t.Fatalf("outgoingDnsQuery error: %s", err)
	}
	if header == nil {
		t.Fatalf("No header found")
	}
	if dnsAnswer == nil {
		t.Fatalf("no answer found")
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("response was not succesful (maybe the DNS server has changed?)")
	}
	err = dnsAnswer.SkipAllAnswers()
	if err != nil {
		t.Fatalf("SkipAllAnswers error: %s", err)
	}
	parsedAuthorities, err := dnsAnswer.AllAuthorities()
	fmt.Printf("parse authoraties: %+v\n", parsedAuthorities)
	if err != nil {
		t.Fatalf("Error getting answers")
	}
	if len(parsedAuthorities) == 0 {
		t.Fatalf("No answers received")
	}
}

func TestDnsQueryUsesGlueRecordsAsNextServers(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.exemplo.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	rootServer := net.ParseIP("198.41.0.4")
	authoritativeServer := net.ParseIP("203.0.113.53")
	finalAnswer := [4]byte{203, 0, 113, 10}
	queries := [][]net.IP{}

	response, err := dnsQueryWithExchanger([]net.IP{rootServer}, question, func(servers []net.IP, q dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
		queries = append(queries, append([]net.IP(nil), servers...))
		if len(queries) == 1 {
			return parserForMessage(t, dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true},
				Questions: []dnsmessage.Question{q},
				Authorities: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("com."),
							Type:  dnsmessage.TypeNS,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.gtld-servers.net.")},
					},
				},
				Additionals: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("a.gtld-servers.net."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 53}},
					},
				},
			})
		}

		return parserForMessage(t, dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, Authoritative: true},
			Questions: []dnsmessage.Question{q},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  q.Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.AResource{A: finalAnswer},
				},
			},
		})
	})
	if err != nil {
		t.Fatalf("dnsQueryWithExchanger error: %s", err)
	}
	if len(queries) != 2 {
		t.Fatalf("expected 2 iterative queries, got %d", len(queries))
	}
	if !queries[0][0].Equal(rootServer) {
		t.Fatalf("first query should go to root server, got %v", queries[0])
	}
	if !queries[1][0].Equal(authoritativeServer) {
		t.Fatalf("second query should go to glue server %s, got %v", authoritativeServer, queries[1])
	}
	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected successful response, got %s", response.Header.RCode.String())
	}
	if len(response.Answers) != 1 {
		t.Fatalf("expected one final answer, got %d", len(response.Answers))
	}
	gotAnswer := response.Answers[0].Body.(*dnsmessage.AResource).A
	if gotAnswer != finalAnswer {
		t.Fatalf("expected final A answer %v, got %v", finalAnswer, gotAnswer)
	}
}

func TestDnsQueryResolvesNameserverAddressWhenGlueIsMissing(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.awtecnologia.com.br."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	rootServer := net.ParseIP("198.41.0.4")
	brServer := net.ParseIP("200.219.159.10")
	secServer := net.ParseIP("200.160.0.11")
	finalAnswer := [4]byte{198, 51, 100, 10}
	queries := []dnsmessage.Question{}
	queryServers := [][]net.IP{}

	response, err := dnsQueryWithExchanger([]net.IP{rootServer}, question, func(servers []net.IP, q dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
		queries = append(queries, q)
		queryServers = append(queryServers, append([]net.IP(nil), servers...))

		switch q.Name.String() {
		case "www.awtecnologia.com.br.":
			if servers[0].Equal(rootServer) {
				return parserForMessage(t, dnsmessage.Message{
					Header:    dnsmessage.Header{Response: true},
					Questions: []dnsmessage.Question{q},
					Authorities: []dnsmessage.Resource{
						{
							Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("br."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET},
							Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("f.dns.br.")},
						},
					},
					Additionals: []dnsmessage.Resource{
						{
							Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("f.dns.br."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
							Body:   &dnsmessage.AResource{A: [4]byte{200, 219, 159, 10}},
						},
					},
				})
			}
			if servers[0].Equal(brServer) {
				return parserForMessage(t, dnsmessage.Message{
					Header:    dnsmessage.Header{Response: true},
					Questions: []dnsmessage.Question{q},
					Authorities: []dnsmessage.Resource{
						{
							Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("awtecnologia.com.br."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET},
							Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.sec.dns.br.")},
						},
					},
				})
			}
			return parserForMessage(t, dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true, Authoritative: true},
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
						Body:   &dnsmessage.AResource{A: finalAnswer},
					},
				},
			})
		case "a.sec.dns.br.":
			return parserForMessage(t, dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true, Authoritative: true},
				Questions: []dnsmessage.Question{q},
				Answers: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
						Body:   &dnsmessage.AResource{A: [4]byte{200, 160, 0, 11}},
					},
				},
			})
		default:
			t.Fatalf("unexpected query for %s", q.Name.String())
		}
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("dnsQueryWithExchanger error: %s", err)
	}
	if len(queryServers) != 4 {
		t.Fatalf("expected 4 queries including nameserver address lookup, got %d", len(queryServers))
	}
	if queries[2].Name.String() != "a.sec.dns.br." || queries[2].Type != dnsmessage.TypeA {
		t.Fatalf("expected third query to resolve nameserver A record, got %s %s", queries[2].Name.String(), queries[2].Type.String())
	}
	if !queryServers[3][0].Equal(secServer) {
		t.Fatalf("expected final query to use resolved nameserver server %s, got %v", secServer, queryServers[3])
	}
	if response.Header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("expected successful response, got %s", response.Header.RCode.String())
	}
	if gotAnswer := response.Answers[0].Body.(*dnsmessage.AResource).A; gotAnswer != finalAnswer {
		t.Fatalf("expected final A answer %v, got %v", finalAnswer, gotAnswer)
	}
}

func TestDnsQueryDebugExplainsDnsPacketSections(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.exemplo.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	var logs bytes.Buffer
	previousOutput := debugLogger.Writer()
	debugLogger.SetOutput(&logs)
	defer debugLogger.SetOutput(previousOutput)

	_, err := dnsQueryWithExchanger([]net.IP{net.ParseIP("198.41.0.4")}, question, func(servers []net.IP, q dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
		return parserForMessage(t, dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, Authoritative: true},
			Questions: []dnsmessage.Question{q},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
					Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}},
				},
			},
		})
	})
	if err != nil {
		t.Fatalf("dnsQueryWithExchanger error: %s", err)
	}

	output := logs.String()
	expectedParts := []string{
		"Pergunta original do cliente",
		"servidores RAIZ",
		"SEÇÃO ANSWER",
		"ANSWER[1]",
		"valor=203.0.113.10",
		"Decisão: o bit Authoritative=true",
	}
	for _, expectedPart := range expectedParts {
		if !strings.Contains(output, expectedPart) {
			t.Fatalf("expected debug log to contain %q, got:\n%s", expectedPart, output)
		}
	}
}

func TestDnsQueryDebugExplainsDelegationAndGlueRecords(t *testing.T) {
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("www.exemplo.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	var logs bytes.Buffer
	previousOutput := debugLogger.Writer()
	debugLogger.SetOutput(&logs)
	defer debugLogger.SetOutput(previousOutput)

	_, err := dnsQueryWithExchanger([]net.IP{net.ParseIP("198.41.0.4")}, question, func(servers []net.IP, q dnsmessage.Question) (*dnsmessage.Parser, *dnsmessage.Header, error) {
		if servers[0].Equal(net.ParseIP("198.41.0.4")) {
			return parserForMessage(t, dnsmessage.Message{
				Header:    dnsmessage.Header{Response: true},
				Questions: []dnsmessage.Question{q},
				Authorities: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("com."), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET, TTL: 172800},
						Body:   &dnsmessage.NSResource{NS: dnsmessage.MustNewName("a.gtld-servers.net.")},
					},
				},
				Additionals: []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("a.gtld-servers.net."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 172800},
						Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 53}},
					},
				},
			})
		}
		return parserForMessage(t, dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, Authoritative: true},
			Questions: []dnsmessage.Question{q},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
					Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}},
				},
			},
		})
	})
	if err != nil {
		t.Fatalf("dnsQueryWithExchanger error: %s", err)
	}

	output := logs.String()
	expectedParts := []string{
		"SEÇÃO AUTHORITY",
		"delegações",
		"nameserver=a.gtld-servers.net.",
		"SEÇÃO ADDITIONAL",
		"glue records",
		"valor=203.0.113.53",
		"Próximo passo: perguntar diretamente",
	}
	for _, expectedPart := range expectedParts {
		if !strings.Contains(output, expectedPart) {
			t.Fatalf("expected debug log to contain %q, got:\n%s", expectedPart, output)
		}
	}
}

func TestGerRootServersTrimsConfiguredAddresses(t *testing.T) {
	for _, server := range gerRootServers() {
		if server == nil {
			t.Fatalf("expected all root server addresses to parse")
		}
	}
}

func parserForMessage(t *testing.T, message dnsmessage.Message) (*dnsmessage.Parser, *dnsmessage.Header, error) {
	t.Helper()
	packed, err := message.Pack()
	if err != nil {
		t.Fatalf("Pack error: %s", err)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(packed)
	if err != nil {
		return nil, nil, err
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, nil, err
	}
	return &parser, &header, nil
}
