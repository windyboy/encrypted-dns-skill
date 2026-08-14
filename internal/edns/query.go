package edns

import (
	"context"
	"encoding/binary"
	"fmt"
)

type queryExchange func(context.Context, Provider, []byte, QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error)

func Query(ctx context.Context, options QueryOptions) Result {
	return queryWithExchange(ctx, options, exchangeProtocol)
}

func queryWithExchange(ctx context.Context, options QueryOptions, exchange queryExchange) Result {
	wire, query, transactionID, err := BuildQuery(options.Name, options.RecordType)
	result := Result{
		SchemaVersion: 1,
		Operation:     "query",
		Query:         query,
		Transport: TransportInfo{
			Protocol:  options.Protocol,
			Encrypted: true,
			Bootstrap: "system_resolver",
		},
		DNS: DNSInfo{Answers: []AnswerRecord{}},
	}
	if err != nil {
		result.Query = QueryInfo{Name: options.Name, Type: options.RecordType}
		result.Error = &ErrorInfo{Class: "input", Message: err.Error()}
		return result
	}

	provider, err := FindProvider(options.Provider)
	if err != nil {
		result.Error = &ErrorInfo{Class: "input", Message: err.Error()}
		return result
	}
	if err := ValidateProxyURL(options.Proxy); err != nil {
		result.Error = &ErrorInfo{Class: "input", Message: err.Error()}
		return result
	}
	if options.Proxy != "" && options.Protocol != "doh" && options.Protocol != "dot" {
		result.Error = &ErrorInfo{Class: "unsupported", Message: fmt.Sprintf("proxying is not available for protocol %q", options.Protocol)}
		return result
	}
	result.Resolver = ResolverInfo{Provider: provider.ID, Profile: provider.Profile}
	endpoint, err := provider.Endpoint(options.Protocol)
	if err != nil {
		class := "input"
		if IsUnsupported(err) {
			class = "unsupported"
		}
		result.Error = &ErrorInfo{Class: class, Message: err.Error()}
		return result
	}
	result.Resolver.Endpoint = endpoint
	if options.Protocol == "doh" || options.Protocol == "doh3" || options.Protocol == "doq" {
		binary.BigEndian.PutUint16(wire[:2], 0)
		transactionID = 0
	}

	response, transport, peer, err := exchange(ctx, provider, wire, options)
	result.Transport = transport
	if err != nil {
		result.Error = &ErrorInfo{Class: "transport", Message: err.Error()}
		return result
	}
	if options.Protocol == "dnscrypt" {
		result.Resolver.Endpoint = peer.ServerAddress
		result.Resolver.AuthenticationName = peer.ProviderName
		result.Resolver.CertificateSerial = peer.CertificateSerial
	}

	result.DNS, err = ParseResponse(response, transactionID, query)
	if err != nil {
		result.Error = &ErrorInfo{Class: "protocol", Message: err.Error()}
		return result
	}
	applyHTTPAge(&result.DNS, result.Transport.HTTPAgeSeconds)
	result.Completed = true
	return result
}

func exchangeProtocol(ctx context.Context, provider Provider, wire []byte, options QueryOptions) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
	var response []byte
	var transport TransportInfo
	var peer dnsCryptPeerInfo
	var err error
	switch options.Protocol {
	case "doh":
		response, transport, err = exchangeDoH(ctx, provider, wire, options.Method, options.Proxy)
	case "dot":
		response, transport, err = exchangeDoT(ctx, provider, wire, options.Proxy)
	case "doq":
		response, transport, err = exchangeDoQ(ctx, provider, wire)
	case "doh3":
		response, transport, err = exchangeDoH3(ctx, provider, wire, options.Method)
	case "dnscrypt":
		var stamp string
		stamp, err = provider.Endpoint("dnscrypt")
		if err == nil {
			response, transport, peer, err = exchangeDNSCrypt(ctx, stamp, wire)
		}
	default:
		err = fmt.Errorf("protocol %q is not available; run ednsdiag capabilities", options.Protocol)
	}
	return response, transport, peer, err
}

func Probe(ctx context.Context, options QueryOptions) Result {
	result := Query(ctx, options)
	result.Operation = "probe"
	return result
}
