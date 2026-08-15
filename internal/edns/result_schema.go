package edns

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func ValidateResultV1JSON(document []byte) error {
	schemaBytes, err := os.ReadFile(resultSchemaPath())
	if err != nil {
		return fmt.Errorf("read result schema: %w", err)
	}
	var schemaDocument any
	if err := json.Unmarshal(schemaBytes, &schemaDocument); err != nil {
		return fmt.Errorf("decode result schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("result-v1.schema.json", schemaDocument); err != nil {
		return fmt.Errorf("add result schema: %w", err)
	}
	schema, err := compiler.Compile("result-v1.schema.json")
	if err != nil {
		return fmt.Errorf("compile result schema: %w", err)
	}
	var value any
	if err := json.Unmarshal(document, &value); err != nil {
		return fmt.Errorf("decode result JSON: %w", err)
	}
	if err := schema.Validate(value); err != nil {
		return err
	}
	return nil
}

func resultSchemaPath() string {
	dir, err := os.Getwd()
	if err != nil {
		return filepath.Join("..", "..", "schemas", "result-v1.schema.json")
	}
	for {
		candidate := filepath.Join(dir, "schemas", "result-v1.schema.json")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join("..", "..", "schemas", "result-v1.schema.json")
		}
		dir = parent
	}
}
