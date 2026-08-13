package edns

import (
	"context"
	"fmt"
	"time"

	"github.com/ameshkov/dnscrypt/v2"
	"github.com/miekg/dns"
)

const (
	dnsCryptDefaultTimeout = 5 * time.Second
	dnsCryptUDPSize        = 1252
)

type dnsCryptPeerInfo struct {
	ServerAddress     string
	ProviderName      string
	CertificateSerial uint32
}

func exchangeDNSCrypt(ctx context.Context, stamp string, wire []byte) ([]byte, TransportInfo, dnsCryptPeerInfo, error) {
	started := time.Now()
	info := TransportInfo{
		Protocol:  "dnscrypt",
		Encrypted: true,
		Bootstrap: "stamp_ip",
	}
	peer := dnsCryptPeerInfo{}

	var query dns.Msg
	if err := query.Unpack(wire); err != nil {
		return nil, info, peer, fmt.Errorf("unpack DNSCrypt query: %w", err)
	}

	timeout, err := dnsCryptRemainingTimeout(ctx)
	if err != nil {
		return nil, info, peer, err
	}
	client := dnscrypt.Client{Net: "udp", Timeout: timeout, UDPSize: dnsCryptUDPSize}
	resolver, err := client.Dial(stamp)
	if err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, peer, fmt.Errorf("authenticate DNSCrypt resolver: %w", err)
	}
	peer.ServerAddress = resolver.ServerAddress
	peer.ProviderName = resolver.ProviderName
	peer.CertificateSerial = resolver.ResolverCert.Serial
	info.ServerAuthenticated = true
	info.CryptoConstruction = resolver.ResolverCert.EsVersion.String()

	timeout, err = dnsCryptRemainingTimeout(ctx)
	if err != nil {
		info.ElapsedMS = time.Since(started).Milliseconds()
		return nil, info, peer, err
	}
	client.Timeout = timeout
	response, err := client.Exchange(&query, resolver)
	info.ElapsedMS = time.Since(started).Milliseconds()
	if err != nil {
		return nil, info, peer, fmt.Errorf("exchange DNSCrypt query: %w", err)
	}
	wireResponse, err := response.Pack()
	if err != nil {
		return nil, info, peer, fmt.Errorf("pack DNSCrypt response: %w", err)
	}
	return wireResponse, info, peer, nil
}

func dnsCryptRemainingTimeout(ctx context.Context) (time.Duration, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("DNSCrypt query context: %w", err)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return dnsCryptDefaultTimeout, nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, fmt.Errorf("DNSCrypt query context: %w", context.DeadlineExceeded)
	}
	return remaining, nil
}
