package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/VardrSec/vardrgate/internal/model"
	"github.com/VardrSec/vardrgate/internal/secretref"
)

// LoadIdentities reads a JSON array of identities used to bind a policy.
//
// Each identity's Role must match a key in the policy's expect map — that is
// what connects a concrete credential to a logical role in the control.
//
// Credential values support ${VAR} references, resolved from the process
// environment at load time. A policy binding is committed alongside the policy
// it binds, so the file must be able to name a secret without containing one.
func LoadIdentities(path string) ([]model.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identities: %w", err)
	}
	return ParseIdentities(data)
}

// ParseIdentities decodes an identities document and expands ${VAR} references
// in credential values.
func ParseIdentities(data []byte) ([]model.Identity, error) {
	var ids []model.Identity
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("identities file contains no identities")
	}
	for i := range ids {
		if ids[i].ID == "" {
			return nil, fmt.Errorf("identities[%d] must have an id", i)
		}
		if ids[i].Role == "" {
			return nil, fmt.Errorf("identity %q must have a role matching a key in the policy's expect map", ids[i].ID)
		}
	}
	if err := secretref.ExpandIdentities(ids); err != nil {
		return nil, err
	}
	return ids, nil
}
