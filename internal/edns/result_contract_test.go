package edns

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestRealQueryAndCompareResultsValidateAgainstResultV1(t *testing.T) {
	query := queryWithExchange(t.Context(), QueryOptions{
		Name: "example.com", RecordType: "A", Protocol: "doh", Provider: "cloudflare", Method: "post",
	}, successfulTestExchange(0, 10))
	if !query.Completed {
		t.Fatalf("query fixture did not complete: %#v", query)
	}
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
	schemaBytes, err := os.ReadFile(filepath.Join("..", "..", "schemas", "result-v1.schema.json"))
	if err != nil {
		t.Fatalf("read result schema: %v", err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		t.Fatalf("decode result schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("result-v1.schema.json", schemaDocument); err != nil {
		t.Fatalf("add result schema: %v", err)
	}
	schema, err := compiler.Compile("result-v1.schema.json")
	if err != nil {
		t.Fatalf("compile result schema: %v", err)
	}
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("result does not validate against result-v1: %v\n%s", err, document)
	}
}
