// Package job parses the offline execution envelope used by `vardrgate run`.
//
// The envelope is the CLI/binary contract between VardrGate and VardrRunner:
// the runner writes a job file, invokes `vardrgate run --job job.json --out
// result.json`, and uploads the sanitized result. The runner never imports
// VardrGate internals — JSON over a file boundary is the whole coupling.
package job

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/VardrSec/vardrgate/internal/client"
	"github.com/VardrSec/vardrgate/internal/model"
)

// Envelope is the top-level job document.
type Envelope struct {
	ID        string `json:"id,omitempty"`
	Type      string `json:"type,omitempty"`
	ProgramID int    `json:"program_id,omitempty"`
	Config    Config `json:"config"`
}

// Config carries the test case and execution settings.
type Config struct {
	PolicyID  string                      `json:"policy_id,omitempty"`
	TestCase  model.AuthorizationTestCase `json:"test_case"`
	Execution Execution                   `json:"execution"`
}

// Execution controls the HTTP client for this job. Zero values use client defaults.
type Execution struct {
	TimeoutSeconds      int   `json:"timeout_seconds,omitempty"`
	MaxResponseBytes    int64 `json:"max_response_bytes,omitempty"`
	AllowPrivateTargets bool  `json:"allow_private_targets,omitempty"`
}

// Load reads and parses a job file.
func Load(path string) (Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Envelope{}, fmt.Errorf("read job: %w", err)
	}
	return Parse(data)
}

// Parse decodes a job envelope. For convenience it also accepts a bare
// AuthorizationTestCase (a document with no "config" key), so a plain test case
// file can be run directly without wrapping it in an envelope.
func Parse(data []byte) (Envelope, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return Envelope{}, fmt.Errorf("parse job: %w", err)
	}

	var e Envelope
	if _, wrapped := probe["config"]; wrapped {
		if err := json.Unmarshal(data, &e); err != nil {
			return Envelope{}, fmt.Errorf("parse job: %w", err)
		}
	} else {
		var tc model.AuthorizationTestCase
		if err := json.Unmarshal(data, &tc); err != nil {
			return Envelope{}, fmt.Errorf("parse job: %w", err)
		}
		e.Config.TestCase = tc
	}
	return e, nil
}

// ClientConfig derives the HTTP client configuration from the execution block,
// leaving unset fields to fall back to client defaults.
func (e Envelope) ClientConfig() client.Config {
	ex := e.Config.Execution
	cfg := client.Config{AllowPrivateTargets: ex.AllowPrivateTargets}
	if ex.TimeoutSeconds > 0 {
		cfg.Timeout = time.Duration(ex.TimeoutSeconds) * time.Second
	}
	if ex.MaxResponseBytes > 0 {
		cfg.MaxBodyBytes = ex.MaxResponseBytes
	}
	return cfg
}

// TestCase returns the test case to execute.
func (e Envelope) TestCase() model.AuthorizationTestCase {
	return e.Config.TestCase
}
