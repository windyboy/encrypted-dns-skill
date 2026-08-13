package edns

import "time"

type QueryOptions struct {
	Name       string
	RecordType string
	Protocol   string
	Provider   string
	Method     string
}

type CompareTarget struct {
	Protocol string `json:"protocol"`
	Provider string `json:"provider"`
	Method   string `json:"method,omitempty"`
}

type CompareOptions struct {
	Name           string
	RecordType     string
	Targets        []CompareTarget
	AttemptTimeout time.Duration
	MaxAttempts    int
}

type Result struct {
	SchemaVersion int           `json:"schema_version"`
	Operation     string        `json:"operation"`
	Completed     bool          `json:"completed"`
	Query         QueryInfo     `json:"query"`
	Resolver      ResolverInfo  `json:"resolver"`
	Transport     TransportInfo `json:"transport"`
	DNS           DNSInfo       `json:"dns"`
	Warnings      []string      `json:"warnings,omitempty"`
	Error         *ErrorInfo    `json:"error,omitempty"`
}

type CompareResult struct {
	SchemaVersion int            `json:"schema_version"`
	Operation     string         `json:"operation"`
	Completed     bool           `json:"completed"`
	Query         QueryInfo      `json:"query"`
	Attempts      []Result       `json:"attempts"`
	Summary       CompareSummary `json:"summary"`
	Error         *ErrorInfo     `json:"error,omitempty"`
}

type CompareSummary struct {
	Total       int `json:"total"`
	Completed   int `json:"completed"`
	Failed      int `json:"failed"`
	Unsupported int `json:"unsupported"`
}

type QueryInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ResolverInfo struct {
	Provider           string `json:"provider"`
	Endpoint           string `json:"endpoint"`
	Profile            string `json:"profile"`
	AuthenticationName string `json:"authentication_name,omitempty"`
	CertificateSerial  uint32 `json:"certificate_serial,omitempty"`
}

type TransportInfo struct {
	Protocol            string `json:"protocol"`
	Encrypted           bool   `json:"encrypted"`
	ServerAuthenticated bool   `json:"server_authenticated"`
	ElapsedMS           int64  `json:"elapsed_ms"`
	Bootstrap           string `json:"bootstrap"`
	TLSVersion          string `json:"tls_version,omitempty"`
	ALPN                string `json:"alpn,omitempty"`
	HTTPVersion         string `json:"http_version,omitempty"`
	HTTPAgeSeconds      int64  `json:"http_age_seconds,omitempty"`
	QUICVersion         string `json:"quic_version,omitempty"`
	CryptoConstruction  string `json:"crypto_construction,omitempty"`
}

type DNSInfo struct {
	RCode                              string         `json:"rcode"`
	RCodeValue                         int            `json:"rcode_value"`
	ResolverReportsDNSSECAuthenticated bool           `json:"resolver_reports_dnssec_authenticated"`
	ClientValidatedDNSSEC              bool           `json:"client_validated_dnssec"`
	Answers                            []AnswerRecord `json:"answers"`
}

type AnswerRecord map[string]any

type ErrorInfo struct {
	Class   string `json:"class"`
	Message string `json:"message"`
}
