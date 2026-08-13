package edns

import (
	"context"
	"fmt"
	"sync"
	"time"
)

func Compare(ctx context.Context, options CompareOptions) CompareResult {
	return compareWithQuery(ctx, options, Query)
}

func compareWithQuery(ctx context.Context, options CompareOptions, queryFunc func(context.Context, QueryOptions) Result) CompareResult {
	result := CompareResult{
		SchemaVersion: 1,
		Operation:     "compare",
		Attempts:      []Result{},
	}
	_, query, _, err := BuildQuery(options.Name, options.RecordType)
	if err != nil {
		result.Query = QueryInfo{Name: options.Name, Type: options.RecordType}
		result.Error = &ErrorInfo{Class: "input", Message: err.Error()}
		return result
	}
	result.Query = query
	if options.MaxAttempts < 2 || options.MaxAttempts > 8 {
		result.Error = &ErrorInfo{Class: "input", Message: "max attempts must be between 2 and 8"}
		return result
	}
	if len(options.Targets) < 2 {
		result.Error = &ErrorInfo{Class: "input", Message: "compare requires at least two targets"}
		return result
	}
	if len(options.Targets) > options.MaxAttempts {
		result.Error = &ErrorInfo{Class: "input", Message: fmt.Sprintf("compare has %d targets, exceeding max attempts %d", len(options.Targets), options.MaxAttempts)}
		return result
	}
	if options.AttemptTimeout < 250*time.Millisecond || options.AttemptTimeout > 30*time.Second {
		result.Error = &ErrorInfo{Class: "input", Message: "attempt timeout must be between 250ms and 30s"}
		return result
	}

	result.Summary.Total = len(options.Targets)
	if err := ctx.Err(); err != nil {
		result.Error = &ErrorInfo{Class: "transport", Message: fmt.Sprintf("compare context: %v", err)}
		return result
	}

	result.Attempts = make([]Result, len(options.Targets))
	var waitGroup sync.WaitGroup
	for index, target := range options.Targets {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			attemptContext, cancel := context.WithTimeout(ctx, options.AttemptTimeout)
			defer cancel()
			result.Attempts[index] = queryFunc(attemptContext, QueryOptions{
				Name:       options.Name,
				RecordType: options.RecordType,
				Protocol:   target.Protocol,
				Provider:   target.Provider,
				Method:     target.Method,
			})
		}()
	}
	waitGroup.Wait()

	for _, attempt := range result.Attempts {
		if attempt.Completed {
			result.Summary.Completed++
		} else {
			result.Summary.Failed++
			if attempt.Error != nil && attempt.Error.Class == "unsupported" {
				result.Summary.Unsupported++
			}
		}
	}

	result.Completed = result.Summary.Completed == result.Summary.Total
	if !result.Completed {
		class := compareFailureClass(result.Attempts)
		result.Error = &ErrorInfo{Class: class, Message: fmt.Sprintf("%d of %d comparison attempts did not complete", result.Summary.Failed, result.Summary.Total)}
	}
	return result
}

func compareFailureClass(attempts []Result) string {
	classes := map[string]bool{}
	for _, attempt := range attempts {
		if attempt.Error != nil {
			classes[attempt.Error.Class] = true
		}
	}
	for _, class := range []string{"internal", "input", "transport", "protocol", "unsupported"} {
		if classes[class] {
			return class
		}
	}
	return "internal"
}
