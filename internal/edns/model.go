package edns

type QueryOptions struct {
	Name       string
	RecordType string
	Protocol   string
	Provider   string
	Method     string
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

type QueryInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type ResolverInfo struct {
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	Profile  string `json:"profile"`
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
	QUICVersion         string `json:"quic_version,omitempty"`
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
