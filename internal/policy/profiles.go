package policy

import "fmt"

// DenialProfile is an operator-confirmed response convention, scoped to an
// explicit list of method/path templates. It compiles into existing assertions.
type DenialProfile struct {
	Confirmed bool            `yaml:"confirmed"`
	Endpoints []string        `yaml:"endpoints"`
	Rules     []AssertionSpec `yaml:"rules"`
}

func (p Policy) profileAssertions(shared map[string]DenialProfile) ([]AssertionSpec, error) {
	var out []AssertionSpec
	for _, name := range p.Response.Profiles {
		profile, ok := p.DenialProfiles[name]
		if _, duplicate := shared[name]; ok && duplicate {
			return nil, fmt.Errorf("denial profile %q defined in both policy and suite", name)
		}
		if !ok {
			profile, ok = shared[name]
		}
		if !ok || !profile.Confirmed || len(profile.Rules) == 0 {
			return nil, fmt.Errorf("denial profile %q must exist, be confirmed and contain rules", name)
		}
		inScope := false
		for _, endpoint := range profile.Endpoints {
			inScope = inScope || endpoint == p.API.Endpoint
		}
		if !inScope {
			return nil, fmt.Errorf("denial profile %q does not explicitly cover this endpoint", name)
		}
		for _, rule := range profile.Rules {
			if rule.Decision != "" && rule.Decision != "deny" {
				return nil, fmt.Errorf("denial profile %q must contain only deny rules", name)
			}
			rule.Decision = "deny"
			out = append(out, rule)
		}
	}
	return out, nil
}
