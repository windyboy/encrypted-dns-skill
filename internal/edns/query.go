package edns

import (
	"context"
	"fmt"
)

func Query(ctx context.Context, options QueryOptions) Result {
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
	result.Resolver = ResolverInfo{Provider: provider.ID, Profile: provider.Profile}

	var response []byte
	switch options.Protocol {
	case "doh":
		result.Resolver.Endpoint = provider.DoHURL
		response, result.Transport, err = exchangeDoH(ctx, provider, wire, options.Method)
	case "dot":
		result.Resolver.Endpoint = provider.DoTAddr
		response, result.Transport, err = exchangeDoT(ctx, provider, wire)
	default:
		err = fmt.Errorf("protocol %q is not available; run ednsdiag capabilities", options.Protocol)
	}
	if err != nil {
		result.Error = &ErrorInfo{Class: "transport", Message: err.Error()}
		return result
	}

	result.DNS, err = ParseResponse(response, transactionID, query)
	if err != nil {
		result.Error = &ErrorInfo{Class: "protocol", Message: err.Error()}
		return result
	}
	result.Completed = true
	return result
}
