// Package discover proposes authorization policies from evidence.
//
// It exists to attack the cost that limits VardrGate's reach: the engine is
// silent about every endpoint nobody wrote a policy for, and writing policies
// by hand is the expensive part. Discovery reads an OpenAPI spec and, when
// available, a captured response body, and infers the *structure* of a control
// — which path parameter addresses an object, which response field carries a
// tenant, which fields are sensitive.
//
// What it deliberately never infers is the expectation. Which callers *should*
// reach an endpoint is a statement about intent that lives outside any artifact
// a machine can read, so every expectation is emitted as the unparseable
// marker TODO. A draft policy cannot execute until a human replaces it. That
// keeps a heuristic from ever appearing behind a VardrGate finding, which is
// the property the whole tool trades on.
package discover

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/VardrSec/vardrgate/internal/compare"
	"github.com/VardrSec/vardrgate/internal/openapi"
	"github.com/VardrSec/vardrgate/internal/policy"
)

// Draft is a proposed policy for one operation, plus the reasoning behind it.
type Draft struct {
	// Filename is a suggested file name, e.g. "get-users-userid.policy.yaml".
	Filename string
	// Endpoint is "<METHOD> <path>".
	Endpoint string
	// YAML is the draft policy document.
	YAML string
	// Notes explain each inference so a reviewer can check the reasoning rather
	// than trust it.
	Notes []string
}

// Options controls what evidence discovery has to work with.
type Options struct {
	// Sample is a captured JSON response body from the API, used to find the
	// tenant field and any sensitive properties. Optional.
	Sample []byte
	// Roles are the logical identities to write into each policy's expect map.
	// Defaults to owner, other_user, anonymous.
	Roles []string
}

// DefaultRoles are the three callers almost every ownership control needs: the
// legitimate owner, a different authenticated user, and nobody at all.
var DefaultRoles = []string{"owner", "other_user", "anonymous"}

// idParamPattern recognises a path parameter that addresses an object.
//
// The match is on the whole parameter name after normalisation, never a
// substring: "user" appearing inside "username" is the kind of noise that is
// free in a prober and unacceptable in something whose output a person signs.
var idParamPattern = regexp.MustCompile(`^(id|uid|uuid|guid|key|.*(id|uuid|guid|key|ref|no|num|number))$`)

// FromSpec proposes one draft policy per operation that addresses an object.
//
// Operations with no path parameter are skipped: an endpoint that takes no
// object identifier has no object-level authorization to state, and emitting an
// empty draft for it would bury the useful ones.
func FromSpec(spec openapi.Spec, opts Options) []Draft {
	roles := opts.Roles
	if len(roles) == 0 {
		roles = DefaultRoles
	}

	var sample *sampleFacts
	if len(opts.Sample) > 0 {
		sample = analyzeSample(opts.Sample)
	}

	var drafts []Draft
	for _, op := range spec.Operations() {
		params := pathParams(op.Path)
		if len(params) == 0 {
			continue
		}
		drafts = append(drafts, buildDraft(op.Method, op.Path, params, roles, sample))
	}
	sort.Slice(drafts, func(i, j int) bool { return drafts[i].Filename < drafts[j].Filename })
	return drafts
}

type sampleFacts struct {
	tenantField     string
	sensitivePaths  []string
	elevatedPresent bool
}

// analyzeSample reads a captured response body for the two things a spec cannot
// tell us: which field carries the tenant, and which properties are sensitive.
func analyzeSample(body []byte) *sampleFacts {
	facts := &sampleFacts{}

	for _, candidate := range []string{"tenant_id", "tenantId", "org_id", "organization_id", "account_id", "workspace_id"} {
		if _, ok := compare.FieldValue(body, candidate); ok {
			facts.tenantField = candidate
			break
		}
	}

	for _, hit := range compare.ScanSensitive(body, nil) {
		facts.sensitivePaths = append(facts.sensitivePaths, hit.Path)
		if hit.Tier == "elevated" {
			facts.elevatedPresent = true
		}
	}
	return facts
}

func buildDraft(method, path string, params, roles []string, sample *sampleFacts) Draft {
	var notes []string

	// The object identifier is the last id-shaped parameter in the path:
	// /orgs/{org_id}/users/{user_id} addresses a user, not an org.
	idParam := ""
	for _, p := range params {
		if idParamPattern.MatchString(normalize(p)) {
			idParam = p
		}
	}
	if idParam == "" && len(params) > 0 {
		idParam = params[len(params)-1]
		notes = append(notes, fmt.Sprintf("no parameter looked like an object id; guessed %q because it is last in the path — check this", idParam))
	} else if idParam != "" {
		notes = append(notes, fmt.Sprintf("id_param=%q inferred from the path", idParam))
	}

	resourceType := resourceTypeFromPath(path)
	if resourceType != "" {
		notes = append(notes, fmt.Sprintf("resource type %q inferred from the path segment before the identifier", resourceType))
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# DRAFT — generated by `vardrgate discover`.\n")
	fmt.Fprintf(&b, "#\n")
	fmt.Fprintf(&b, "# Every expectation below is %s. Discovery can infer the shape of a\n", policy.DraftMarker)
	fmt.Fprintf(&b, "# control but not its intent: only you know who should be able to call\n")
	fmt.Fprintf(&b, "# this endpoint. The policy will not run until each %s is replaced with\n", policy.DraftMarker)
	fmt.Fprintf(&b, "# allow, deny, or skip.\n")
	fmt.Fprintf(&b, "api:\n")
	fmt.Fprintf(&b, "  endpoint: %s %s\n", strings.ToUpper(method), path)
	fmt.Fprintf(&b, "  owner: identity:%s\n", roles[0])

	if model := strings.ToUpper(method); model != "GET" && model != "HEAD" {
		fmt.Fprintf(&b, "  # %s changes state and would be replayed once per identity.\n", model)
		fmt.Fprintf(&b, "  mutating: false  # set true only if replaying it %d times is acceptable\n", len(roles))
		notes = append(notes, fmt.Sprintf("%s is an unsafe method: the draft leaves mutating false so it will refuse to run until reviewed", model))
	}

	fmt.Fprintf(&b, "  resource:\n")
	if resourceType != "" {
		fmt.Fprintf(&b, "    type: %s\n", resourceType)
	}
	if idParam != "" {
		fmt.Fprintf(&b, "    id_param: %s\n", idParam)
	}
	if sample != nil && sample.tenantField != "" {
		fmt.Fprintf(&b, "    tenant_field: %s\n", sample.tenantField)
		notes = append(notes, fmt.Sprintf("tenant_field=%q found in the sample response", sample.tenantField))
	} else {
		fmt.Fprintf(&b, "    # tenant_field: <response field carrying the object's tenant, if any>\n")
	}

	fmt.Fprintf(&b, "\nexpect:\n")
	for _, role := range roles {
		fmt.Fprintf(&b, "  %s: %s\n", role, policy.DraftMarker)
	}

	fmt.Fprintf(&b, "\nresponse:\n")
	fmt.Fprintf(&b, "  deny_status: [401, 403]\n")
	fmt.Fprintf(&b, "  # If this API hides existence behind 404, add it above.\n")
	fmt.Fprintf(&b, "  # If it answers 200 with an error body, declare that here:\n")
	fmt.Fprintf(&b, "  # deny_when:\n")
	fmt.Fprintf(&b, "  #   json_field: { path: error, equals: forbidden }\n")

	if sample != nil && len(sample.sensitivePaths) > 0 {
		fmt.Fprintf(&b, "  sensitive_fields:\n")
		fmt.Fprintf(&b, "    forbidden_for:\n")
		for _, role := range roles[1:] {
			fmt.Fprintf(&b, "      - %s\n", role)
		}
		fmt.Fprintf(&b, "  # Sensitive properties seen in the sample response:\n")
		for _, p := range sample.sensitivePaths {
			fmt.Fprintf(&b, "  #   %s\n", p)
		}
		notes = append(notes, fmt.Sprintf("%d sensitive field(s) found in the sample response", len(sample.sensitivePaths)))
		if sample.elevatedPresent {
			notes = append(notes, "the sample contains authorization-bearing properties (role, is_admin, balance or similar) — object_property_exposure is worth checking here")
		}
	}

	return Draft{
		Filename: filename(method, path),
		Endpoint: strings.ToUpper(method) + " " + path,
		YAML:     b.String(),
		Notes:    notes,
	}
}

var pathParamPattern = regexp.MustCompile(`\{([^}]+)\}`)

func pathParams(path string) []string {
	matches := pathParamPattern.FindAllStringSubmatch(path, -1)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m[1])
	}
	return out
}

// resourceTypeFromPath takes the collection segment preceding the identifier
// and singularises it: /users/{user_id}/profile → "profile", /users/{id} → "user".
func resourceTypeFromPath(path string) string {
	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		s := segments[i]
		if s == "" || strings.HasPrefix(s, "{") {
			continue
		}
		return singular(s)
	}
	return ""
}

// notPluralSuffixes end in "s" without being plural, so "status" must not
// become "statu". This is a naming nicety in a draft a human reviews, not a
// correctness boundary — the resource type is a label.
var notPluralSuffixes = []string{"ss", "us", "is", "os", "as"}

func singular(s string) string {
	lower := strings.ToLower(s)
	for _, suffix := range notPluralSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return s
		}
	}
	switch {
	case strings.HasSuffix(s, "ies"):
		return strings.TrimSuffix(s, "ies") + "y"
	case strings.HasSuffix(s, "ses"), strings.HasSuffix(s, "xes"), strings.HasSuffix(s, "hes"):
		return strings.TrimSuffix(s, "es")
	case strings.HasSuffix(s, "s"):
		return strings.TrimSuffix(s, "s")
	default:
		return s
	}
}

func filename(method, path string) string {
	slug := strings.ToLower(strings.ToUpper(method) + path)
	slug = strings.NewReplacer("/", "-", "{", "", "}", "", "_", "", " ", "-").Replace(slug)
	slug = strings.Trim(slug, "-")
	return slug + ".policy.yaml"
}

func normalize(s string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(s))
}
