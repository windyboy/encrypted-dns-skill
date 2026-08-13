package edns

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestBuildAndParseResponse(t *testing.T) {
	queryWire, query, transactionID, err := BuildQuery("Example.COM.", "A")
	if err != nil {
		t.Fatalf("build query: %v", err)
	}
	if query.Name != "example.com" || query.Type != "A" {
		t.Fatalf("canonical query = %#v", query)
	}

	var request dnsmessage.Message
	if err := request.Unpack(queryWire); err != nil {
		t.Fatalf("unpack query: %v", err)
	}
	response := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 transactionID,
			Response:           true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			AuthenticData:      true,
		},
		Questions: request.Questions,
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
		}},
	}
	responseWire, err := response.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}

	dnsResult, err := ParseResponse(responseWire, transactionID, query)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if dnsResult.RCode != "NOERROR" || !dnsResult.ResolverReportsDNSSECAuthenticated {
		t.Fatalf("unexpected DNS result: %#v", dnsResult)
	}
	if got := dnsResult.Answers[0]["address"]; got != "192.0.2.1" {
		t.Fatalf("address = %v, want 192.0.2.1", got)
	}
}

func TestBuildQueryIDNAAndBlockedNames(t *testing.T) {
	_, query, _, err := BuildQuery("bücher.example", "AAAA")
	if err != nil {
		t.Fatalf("build IDNA query: %v", err)
	}
	if query.Name != "xn--bcher-kva.example" {
		t.Fatalf("IDNA name = %q", query.Name)
	}

	blocked := []string{"localhost", "router.local", "service.internal", "host.lan", "1.0.0.127.in-addr.arpa", "127.0.0.1"}
	for _, name := range blocked {
		if _, _, _, err := BuildQuery(name, "A"); err == nil {
			t.Errorf("BuildQuery(%q) succeeded, want policy error", name)
		}
	}
}

func TestNormalizeCAA(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	data := append([]byte{0, 5}, []byte("issueletsencrypt.org")...)
	record := normalizeAnswer(dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.Type(257), Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.UnknownResource{Type: dnsmessage.Type(257), Data: data},
	})
	if record["tag"] != "issue" || record["value"] != "letsencrypt.org" {
		t.Fatalf("unexpected CAA normalization: %#v", record)
	}
}

func TestParseResponseRejectsTransactionMismatch(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	message := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 2, Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	wire, err := message.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}
	if _, err := ParseResponse(wire, 1, QueryInfo{Name: "example.com", Type: "A"}); err == nil {
		t.Fatal("transaction mismatch was accepted")
	}

	if binary.BigEndian.Uint16(wire[:2]) != 2 {
		t.Fatal("test response ID was not encoded")
	}
}
