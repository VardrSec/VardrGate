package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/VardrSec/vardrgate/internal/model"
)

// Digest the original individual JSON object before environment/setup resolution.
// Compact preserves field order, numbers and escapes: only exterior whitespace
// is ignored. This is source correlation, not authenticated scanner attestation,
// and deliberately is not Runner/Map's differently canonicalized case_hash.
func inputDigest(raw json.RawMessage) string {
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return ""
	}
	sum := sha256.Sum256(compact.Bytes())
	return "sha256-json-compact-v1:" + hex.EncodeToString(sum[:])
}

func caseTemplates(data []byte) ([]model.AuthorizationTestCase, map[string]string, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		var single map[string]json.RawMessage
		if json.Unmarshal(data, &single) != nil || single == nil {
			return nil, nil, errors.New("parse cases: expected an object or array of objects")
		}
		raw = []json.RawMessage{data}
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("cases file contains no test cases")
	}
	cases := make([]model.AuthorizationTestCase, 0, len(raw))
	digests := map[string]string{}
	seen := map[string]bool{}
	for _, item := range raw {
		var tc model.AuthorizationTestCase
		if err := json.Unmarshal(item, &tc); err != nil || bytes.Equal(bytes.TrimSpace(item), []byte("null")) {
			return nil, nil, errors.New("parse cases: expected test case objects")
		}
		if seen[tc.ID] {
			return nil, nil, fmt.Errorf("case ID %q is not unique", tc.ID)
		}
		seen[tc.ID] = true
		// Never emit a digest of literal credentials or known secret request
		// values. Existing execution of such local inputs remains supported.
		if portableRegression(tc) == nil {
			digests[tc.ID] = inputDigest(item)
		}
		cases = append(cases, tc)
	}
	return cases, digests, nil
}
