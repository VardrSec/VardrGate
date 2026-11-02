package main

import (
	"strings"
	"testing"
)

func TestRequestGuardRefusesMissingLiteralJobAndOverrides(t *testing.T) {
	for _, args := range [][]string{
		{"--cases", "unused", "--request-guard", "unused"},
		{"--job", "unused", "--request-guard", "unused"},
		{"--job", "unused", "--literal-job", "--request-guard", "unused", "--allow-mutating"},
		{"--job", "unused", "--literal-job", "--request-guard", "unused", "--strict-identity-preflight=false"},
	} {
		if err := runCases(args); err == nil || !strings.Contains(err.Error(), "unchanged literal job") {
			t.Fatalf("unsafe invocation was not rejected before file access: %v", err)
		}
	}
}
