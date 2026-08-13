package edns

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

var recordTypes = map[string]dnsmessage.Type{
	"A":     dnsmessage.TypeA,
	"AAAA":  dnsmessage.TypeAAAA,
	"CNAME": dnsmessage.TypeCNAME,
	"MX":    dnsmessage.TypeMX,
	"TXT":   dnsmessage.TypeTXT,
	"NS":    dnsmessage.TypeNS,
	"SOA":   dnsmessage.TypeSOA,
	"CAA":   dnsmessage.Type(257),
	"SRV":   dnsmessage.TypeSRV,
	"SVCB":  dnsmessage.TypeSVCB,
	"HTTPS": dnsmessage.TypeHTTPS,
	"PTR":   dnsmessage.TypePTR,
}

func BuildQuery(name, recordType string) ([]byte, QueryInfo, uint16, error) {
	typeName := strings.ToUpper(recordType)
	qtype, ok := recordTypes[typeName]
	if !ok {
		return nil, QueryInfo{}, 0, fmt.Errorf("unsupported record type %q", recordType)
	}

	var canonical string
	var err error
	if typeName == "PTR" {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(name))
		if parseErr != nil {
			return nil, QueryInfo{}, 0, fmt.Errorf("PTR queries require an IPv4 or IPv6 address")
		}
		canonical = reverseName(address.Unmap())
	} else {
		canonical, err = canonicalName(name)
	}
	if err != nil {
		return nil, QueryInfo{}, 0, err
	}

	dnsName, err := dnsmessage.NewName(canonical + ".")
	if err != nil {
		return nil, QueryInfo{}, 0, fmt.Errorf("encode domain name: %w", err)
	}

	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, QueryInfo{}, 0, fmt.Errorf("generate DNS transaction ID: %w", err)
	}
	id := binary.BigEndian.Uint16(randomID[:])
	message := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	wire, err := message.Pack()
	if err != nil {
		return nil, QueryInfo{}, 0, fmt.Errorf("pack DNS query: %w", err)
	}
	return wire, QueryInfo{Name: canonical, Type: typeName}, id, nil
}

func reverseName(address netip.Addr) string {
	if address.Is4() {
		bytes := address.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa", bytes[3], bytes[2], bytes[1], bytes[0])
	}

	bytes := address.As16()
	var builder strings.Builder
	// Each IPv6 nibble is emitted from least to most significant per RFC 3596.
	for index := len(bytes) - 1; index >= 0; index-- {
		fmt.Fprintf(&builder, "%x.%x.", bytes[index]&0x0f, bytes[index]>>4)
	}
	builder.WriteString("ip6.arpa")
	return builder.String()
}

func ParseResponse(wire []byte, expectedID uint16, query QueryInfo) (DNSInfo, error) {
	var message dnsmessage.Message
	if err := message.Unpack(wire); err != nil {
		return DNSInfo{}, fmt.Errorf("unpack DNS response: %w", err)
	}
	if !message.Header.Response {
		return DNSInfo{}, fmt.Errorf("received a DNS query instead of a response")
	}
	if message.Header.OpCode != 0 {
		return DNSInfo{}, fmt.Errorf("DNS response uses unexpected opcode %d", message.Header.OpCode)
	}
	if message.Header.Truncated {
		return DNSInfo{}, fmt.Errorf("DNS response is truncated")
	}
	if message.Header.ID != expectedID {
		return DNSInfo{}, fmt.Errorf("DNS transaction ID mismatch")
	}
	if len(message.Questions) != 1 {
		return DNSInfo{}, fmt.Errorf("DNS response contains %d questions, want 1", len(message.Questions))
	}
	wantType := recordTypes[query.Type]
	question := message.Questions[0]
	if trimRoot(question.Name.String()) != query.Name || question.Type != wantType || question.Class != dnsmessage.ClassINET {
		return DNSInfo{}, fmt.Errorf("DNS response question does not match request")
	}

	answers := make([]AnswerRecord, 0, len(message.Answers))
	for _, resource := range message.Answers {
		if resource.Header.Class != dnsmessage.ClassINET {
			return DNSInfo{}, fmt.Errorf("DNS answer %q uses unsupported class %d", trimRoot(resource.Header.Name.String()), resource.Header.Class)
		}
		answer, err := normalizeAnswer(resource)
		if err != nil {
			return DNSInfo{}, err
		}
		answers = append(answers, answer)
	}

	return DNSInfo{
		RCode:                              rcodeName(message.Header.RCode),
		RCodeValue:                         int(message.Header.RCode),
		ResolverReportsDNSSECAuthenticated: message.Header.AuthenticData,
		ClientValidatedDNSSEC:              false,
		Answers:                            answers,
	}, nil
}

func canonicalName(input string) (string, error) {
	name := strings.TrimSuffix(strings.TrimSpace(input), ".")
	if name == "" {
		return "", fmt.Errorf("domain name is empty")
	}
	if net.ParseIP(name) != nil {
		return "", fmt.Errorf("IP literals are not accepted as domain names")
	}

	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("convert domain name to IDNA ASCII: %w", err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", fmt.Errorf("domain name exceeds 253 bytes")
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("domain name contains an invalid label")
		}
	}

	blocked := []string{"localhost", ".local", ".internal", ".lan", ".arpa"}
	for _, suffix := range blocked {
		if ascii == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(ascii, suffix) {
			return "", fmt.Errorf("domain name is blocked by the local-name policy")
		}
	}
	return ascii, nil
}

func normalizeAnswer(resource dnsmessage.Resource) (AnswerRecord, error) {
	record := AnswerRecord{
		"name": trimRoot(resource.Header.Name.String()),
		"type": typeName(resource.Header.Type),
		"ttl":  resource.Header.TTL,
	}

	switch body := resource.Body.(type) {
	case *dnsmessage.AResource:
		record["address"] = net.IP(body.A[:]).String()
	case *dnsmessage.AAAAResource:
		record["address"] = net.IP(body.AAAA[:]).String()
	case *dnsmessage.CNAMEResource:
		record["target"] = trimRoot(body.CNAME.String())
	case *dnsmessage.MXResource:
		record["priority"] = body.Pref
		record["exchange"] = trimRoot(body.MX.String())
	case *dnsmessage.TXTResource:
		record["strings"] = body.TXT
	case *dnsmessage.NSResource:
		record["host"] = trimRoot(body.NS.String())
	case *dnsmessage.PTRResource:
		record["target"] = trimRoot(body.PTR.String())
	case *dnsmessage.SOAResource:
		record["primary_ns"] = trimRoot(body.NS.String())
		record["responsible_mailbox"] = trimRoot(body.MBox.String())
		record["serial"] = body.Serial
		record["refresh"] = body.Refresh
		record["retry"] = body.Retry
		record["expire"] = body.Expire
		record["minimum_ttl"] = body.MinTTL
	case *dnsmessage.SRVResource:
		record["priority"] = body.Priority
		record["weight"] = body.Weight
		record["port"] = body.Port
		record["target"] = trimRoot(body.Target.String())
	case *dnsmessage.SVCBResource:
		addSVCBFields(record, body.Priority, body.Target, body.Params)
	case *dnsmessage.HTTPSResource:
		addSVCBFields(record, body.Priority, body.Target, body.Params)
	case *dnsmessage.UnknownResource:
		if resource.Header.Type == dnsmessage.Type(257) && len(body.Data) >= 2 {
			record["flags"] = body.Data[0]
			tagLength := int(body.Data[1])
			if 2+tagLength <= len(body.Data) {
				record["tag"] = string(body.Data[2 : 2+tagLength])
				record["value"] = string(body.Data[2+tagLength:])
			} else {
				return nil, fmt.Errorf("CAA answer contains a truncated tag")
			}
		} else {
			return nil, fmt.Errorf("DNS answer type %s cannot be represented by result-v1", typeName(resource.Header.Type))
		}
	default:
		return nil, fmt.Errorf("DNS answer type %s has an unexpected wire representation", typeName(resource.Header.Type))
	}
	return record, nil
}

func applyHTTPAge(info *DNSInfo, ageSeconds int64) {
	if ageSeconds <= 0 {
		return
	}
	for _, answer := range info.Answers {
		ttl, ok := answer["ttl"].(uint32)
		if !ok {
			continue
		}
		if ageSeconds >= int64(ttl) {
			answer["ttl"] = uint32(0)
		} else {
			answer["ttl"] = ttl - uint32(ageSeconds)
		}
	}
}

func addSVCBFields(record AnswerRecord, priority uint16, target dnsmessage.Name, params []dnsmessage.SVCParam) {
	record["priority"] = priority
	record["target"] = trimRoot(target.String())
	values := make([]map[string]any, 0, len(params))
	for _, param := range params {
		values = append(values, map[string]any{
			"key":          param.Key.String(),
			"key_value":    uint16(param.Key),
			"value_base64": base64.StdEncoding.EncodeToString(param.Value),
		})
	}
	record["params"] = values
}

func trimRoot(name string) string {
	return strings.TrimSuffix(strings.ToLower(name), ".")
}

func typeName(recordType dnsmessage.Type) string {
	for name, value := range recordTypes {
		if value == recordType {
			return name
		}
	}
	return fmt.Sprintf("TYPE%d", recordType)
}

func rcodeName(rcode dnsmessage.RCode) string {
	names := map[dnsmessage.RCode]string{
		dnsmessage.RCodeSuccess:        "NOERROR",
		dnsmessage.RCodeFormatError:    "FORMERR",
		dnsmessage.RCodeServerFailure:  "SERVFAIL",
		dnsmessage.RCodeNameError:      "NXDOMAIN",
		dnsmessage.RCodeNotImplemented: "NOTIMP",
		dnsmessage.RCodeRefused:        "REFUSED",
	}
	if name, ok := names[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
