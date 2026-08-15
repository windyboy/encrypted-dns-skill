package edns

import "fmt"

type Capability struct {
	Protocol string `json:"protocol"`
	Status   string `json:"status"`
	Standard string `json:"standard,omitempty"`
	Note     string `json:"note,omitempty"`
}

func Capabilities() []Capability {
	return []Capability{
		{Protocol: "doh", Status: "available", Standard: "RFC 8484", Note: "RFC wire format over HTTP GET or POST"},
		{Protocol: "dot", Status: "available", Standard: "RFC 7858 and RFC 8310", Note: "strict PKIX and authentication-domain validation"},
		{Protocol: "doq", Status: "available", Standard: "RFC 9250", Note: "RFC wire format over dedicated QUIC streams"},
		{Protocol: "doh3", Status: "available", Standard: "RFC 8484 over HTTP/3", Note: "RFC wire format over HTTP/3 GET or POST"},
		{Protocol: "dnscrypt", Status: "available", Standard: "DNSCrypt protocol specification", Note: "DNSCrypt v2 with authenticated resolver certificates"},
		{Protocol: "odoh", Status: "research", Standard: "RFC 9230", Note: "No maintained Go dependency has been selected."},
		{Protocol: "anonymized-dnscrypt", Status: "research", Standard: "Anonymized DNSCrypt specification"},
	}
}

func KnownProtocol(protocol string) bool {
	for _, item := range Capabilities() {
		if item.Protocol == protocol {
			return true
		}
	}
	return false
}

func ValidateHTTPMethod(protocol, method string) error {
	if method != "get" && method != "post" {
		return fmt.Errorf("http method must be get or post")
	}
	if protocol != "doh" && protocol != "doh3" && method != "post" {
		return fmt.Errorf("http method applies only to DoH and DoH3")
	}
	return nil
}

func ProxySupportedForProtocol(protocol string) bool {
	return protocol == "doh" || protocol == "dot"
}
