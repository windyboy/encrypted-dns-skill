package edns

import (
	"encoding/binary"
	"reflect"
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

func TestBuildPTRQueryFromIPAddress(t *testing.T) {
	_, ipv4, _, err := BuildQuery("192.0.2.1", "PTR")
	if err != nil {
		t.Fatalf("build IPv4 PTR query: %v", err)
	}
	if ipv4.Name != "1.2.0.192.in-addr.arpa" || ipv4.Type != "PTR" {
		t.Fatalf("unexpected IPv4 PTR query: %#v", ipv4)
	}
	_, ipv6, _, err := BuildQuery("2001:db8::1", "PTR")
	if err != nil {
		t.Fatalf("build IPv6 PTR query: %v", err)
	}
	if ipv6.Name != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa" {
		t.Fatalf("unexpected IPv6 PTR name: %q", ipv6.Name)
	}
	if _, _, _, err := BuildQuery("example.com", "PTR"); err == nil {
		t.Fatal("PTR query accepted a non-IP input")
	}
}

func TestNormalizeSupportedAnswerTypes(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	target := dnsmessage.MustNewName("target.example.")
	resources := []dnsmessage.Resource{
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeCNAME, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeMX, TTL: 60}, Body: &dnsmessage.MXResource{Pref: 10, MX: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, TTL: 60}, Body: &dnsmessage.TXTResource{TXT: []string{"one", "two"}}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeNS, TTL: 60}, Body: &dnsmessage.NSResource{NS: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeSOA, TTL: 60}, Body: &dnsmessage.SOAResource{NS: target, MBox: target, Serial: 1}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeSRV, TTL: 60}, Body: &dnsmessage.SRVResource{Priority: 1, Weight: 2, Port: 443, Target: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypePTR, TTL: 60}, Body: &dnsmessage.PTRResource{PTR: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeSVCB, TTL: 60}, Body: &dnsmessage.SVCBResource{Priority: 1, Target: target}},
		{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeHTTPS, TTL: 60}, Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 1, Target: target}}},
	}
	wantTypes := []string{"AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "SRV", "PTR", "SVCB", "HTTPS"}
	wantFields := []map[string]any{
		{"address": "2001:db8::1"},
		{"target": "target.example"},
		{"priority": uint16(10), "exchange": "target.example"},
		{"strings": []string{"one", "two"}},
		{"host": "target.example"},
		{"primary_ns": "target.example", "responsible_mailbox": "target.example", "serial": uint32(1)},
		{"priority": uint16(1), "weight": uint16(2), "port": uint16(443), "target": "target.example"},
		{"target": "target.example"},
		{"priority": uint16(1), "target": "target.example", "params": []map[string]any{}},
		{"priority": uint16(1), "target": "target.example", "params": []map[string]any{}},
	}
	for index, resource := range resources {
		record := normalizeAnswer(resource)
		if record["type"] != wantTypes[index] || record["name"] != "example.com" || record["ttl"] != uint32(60) {
			t.Fatalf("unexpected %s normalization: %#v", wantTypes[index], record)
		}
		for field, want := range wantFields[index] {
			if got := record[field]; !reflect.DeepEqual(got, want) {
				t.Fatalf("%s field %s = %#v, want %#v", wantTypes[index], field, got, want)
			}
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
