package edns

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRealQueryAndCompareResultsValidateAgainstResultV1(t *testing.T) {
	query := queryWithExchange(t.Context(), QueryOptions{
		Name: "example.com", RecordType: "A", Protocol: "doh", Provider: "cloudflare", Method: "post",
	}, successfulTestExchange(0, 10))
	if !query.Completed {
		t.Fatalf("query fixture did not complete: %#v", query)
	}
	query.Transport.Proxy = "http://proxy.example:8080"
	validateResultV1(t, query)

	comparison := compareWithQuery(t.Context(), CompareOptions{
		Name: "example.com", RecordType: "A", AttemptTimeout: time.Second, MaxAttempts: 2,
		Targets: []CompareTarget{
			{Protocol: "doh", Provider: "cloudflare", Method: "post"},
			{Protocol: "doh3", Provider: "google", Method: "post"},
		},
	}, func(ctx context.Context, options QueryOptions) Result {
		return queryWithExchange(ctx, options, successfulTestExchange(0, 0))
	})
	if !comparison.Completed {
		t.Fatalf("compare fixture did not complete: %#v", comparison)
	}
	validateResultV1(t, comparison)
}

func validateResultV1(t *testing.T, result any) {
	t.Helper()
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	if err := ValidateResultV1JSON(document); err != nil {
		t.Fatalf("result does not validate against result-v1: %v\n%s", err, document)
	}
}
