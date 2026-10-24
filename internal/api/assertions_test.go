package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseAssertionAPIValidation(t *testing.T) {
	for _, tt := range []struct {
		rule   string
		status int
	}{
		{`{"json_pointer":"/private","equals":null,"decision":"allow"}`, 200},
		{`{"json_pointer":"/private","decision":"allow"}`, 422},
		{`{"json_pointer":"private-sensitive-path","equals":true,"decision":"allow"}`, 422},
		{`{"json_pointer":"/private","equals":true,"decision":"sensitive-invalid-decision"}`, 422},
	} {
		var payload map[string]any
		if err := json.Unmarshal([]byte(validTestCaseJSON()), &payload); err != nil {
			t.Fatal(err)
		}
		var rule map[string]any
		if err := json.Unmarshal([]byte(tt.rule), &rule); err != nil {
			t.Fatal(err)
		}
		payload["expected_access"].([]any)[0].(map[string]any)["response_assertions"] = []any{rule}
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		newTestHandlerWithResponses(map[string]int{"admin": 200, "user": 403}).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/tests/execute", bytes.NewReader(body)))
		if rr.Code != tt.status {
			t.Fatalf("expected %d, got %d: %s", tt.status, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "sensitive") {
			t.Fatal("validation response exposed assertion content")
		}
		if tt.status == 200 {
			var result map[string]json.RawMessage
			if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if _, ok := result["assessments"]; !ok {
				t.Fatal("API omitted assessments")
			}
		}
	}
}
