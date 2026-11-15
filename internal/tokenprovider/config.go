// Package tokenprovider obtains scan credentials (typically a JWT) from an
// operator-configured token API, keeps them fresh for the life of a scan, and
// hands the resulting auth header to the HTTP layer.
//
// A Provider describes HOW to call the token API (a request template plus
// JSONPath-style extraction rules); a Profile is a named parameter set (user,
// tenant, roles, audience, ...) rendered into that template. Because the
// target's microservices authorize statelessly from the JWT's claims, each
// profile is effectively a distinct identity, so profiles double as the roles
// compared by the authorization matrix (role A = default session, role B =
// the "other" identity).
//
// Nothing in this package executes operator- or collection-supplied scripts:
// tokens are obtained purely by declarative HTTP requests.
package tokenprovider

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// BodyType selects how the request body is encoded.
const (
	BodyJSON = "json"
	BodyForm = "form"
	BodyRaw  = "raw"
)

// RequestSpec is a templated HTTP request. Every string value (URL, header
// values, body leaves) may contain {{name}} placeholders resolved from the
// profile parameters, {{secret:name}} resolved from the provider's secrets,
// and — for refresh requests — {{refresh_token}} / {{access_token}}.
type RequestSpec struct {
	Method   string            `json:"method"`
	URL      string            `json:"url"`
	Headers  map[string]string `json:"headers,omitempty"`
	BodyType string            `json:"body_type,omitempty"` // json (default) | form | raw
	// Body is a JSON value for BodyJSON (object/array/scalars, placeholders
	// substituted in string leaves), a flat object of strings for BodyForm,
	// or a string for BodyRaw.
	Body any `json:"body,omitempty"`
}

// ExtractSpec says where each value lives in the token API's response.
// Each rule is one of:
//
//	$.data.accessToken      JSONPath subset ($, .key, [n], ['key'])
//	header:X-Auth-Token     a response header
//	regex:token=([^&]+)     first capture group (or whole match) over the body
type ExtractSpec struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresIn is a number of seconds (or a numeric string). When absent the
	// JWT "exp" claim is used, then RefreshSpec.MaxTTLSeconds.
	ExpiresIn string `json:"expires_in,omitempty"`
}

// ApplySpec says how the token is presented to the target.
type ApplySpec struct {
	Header string `json:"header,omitempty"` // default Authorization
	Format string `json:"format,omitempty"` // default "Bearer {{token}}"
}

// RefreshSpec configures keeping the token fresh.
type RefreshSpec struct {
	// Request is the refresh call. Nil means "repeat the full token request".
	Request *RequestSpec `json:"request,omitempty"`
	// Extract overrides the provider's extraction rules for the refresh
	// response. Nil reuses the provider's Extract.
	Extract *ExtractSpec `json:"extract,omitempty"`
	// BeforeExpirySeconds refreshes this long before expiry (default 60).
	BeforeExpirySeconds int `json:"before_expiry_seconds,omitempty"`
	// MaxTTLSeconds is the assumed lifetime when the response states none and
	// the token is not a JWT with "exp" (default 900).
	MaxTTLSeconds int `json:"max_ttl_seconds,omitempty"`
	// OnStatus lists target response codes that force a refresh + one retry
	// (default [401]).
	OnStatus []int `json:"on_status,omitempty"`
}

// Provider is one configured token API.
type Provider struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Request     RequestSpec `json:"request"`
	Extract     ExtractSpec `json:"extract"`
	Apply       ApplySpec   `json:"apply,omitempty"`
	Refresh     RefreshSpec `json:"refresh,omitempty"`
	// Secrets are referenced as {{secret:name}}; they are never returned by
	// the API (see Masked) and are registered for telemetry redaction.
	Secrets map[string]string `json:"secrets,omitempty"`
	// Profiles maps a profile name to its parameters ({{name}} values).
	Profiles map[string]map[string]string `json:"profiles,omitempty"`
	// TLSSkipVerify allows self-signed token APIs in lab environments.
	TLSSkipVerify bool `json:"tls_skip_verify,omitempty"`
}

var idRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// ValidID reports whether s is a safe provider/profile identifier.
func ValidID(s string) bool { return idRe.MatchString(s) }

// Normalize fills defaults in place.
func (p *Provider) Normalize() {
	p.ID = strings.TrimSpace(p.ID)
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		p.Name = p.ID
	}
	normalizeRequest(&p.Request)
	if p.Refresh.Request != nil {
		normalizeRequest(p.Refresh.Request)
	}
	if strings.TrimSpace(p.Apply.Header) == "" {
		p.Apply.Header = "Authorization"
	}
	if strings.TrimSpace(p.Apply.Format) == "" {
		p.Apply.Format = "Bearer {{token}}"
	}
	if p.Refresh.BeforeExpirySeconds <= 0 {
		p.Refresh.BeforeExpirySeconds = 60
	}
	if p.Refresh.MaxTTLSeconds <= 0 {
		p.Refresh.MaxTTLSeconds = 900
	}
	if len(p.Refresh.OnStatus) == 0 {
		p.Refresh.OnStatus = []int{401}
	}
}

func normalizeRequest(r *RequestSpec) {
	r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
	if r.Method == "" {
		r.Method = "POST"
	}
	r.URL = strings.TrimSpace(r.URL)
	r.BodyType = strings.ToLower(strings.TrimSpace(r.BodyType))
	if r.BodyType == "" {
		r.BodyType = BodyJSON
	}
}

// Validate checks the provider is usable. Call after Normalize.
func (p *Provider) Validate() error {
	if !ValidID(p.ID) {
		return errors.New("id must be 1-64 chars of letters, digits, '-' or '_'")
	}
	if err := validateRequest("request", p.Request); err != nil {
		return err
	}
	if p.Refresh.Request != nil {
		if err := validateRequest("refresh.request", *p.Refresh.Request); err != nil {
			return err
		}
	}
	if strings.TrimSpace(p.Extract.Token) == "" {
		return errors.New("extract.token is required (e.g. $.access_token)")
	}
	if err := validateRule(p.Extract.Token); err != nil {
		return fmt.Errorf("extract.token: %w", err)
	}
	for name, rule := range map[string]string{"extract.refresh_token": p.Extract.RefreshToken, "extract.expires_in": p.Extract.ExpiresIn} {
		if rule != "" {
			if err := validateRule(rule); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if !strings.Contains(p.Apply.Format, "{{token}}") {
		return errors.New("apply.format must contain {{token}}")
	}
	if !validHeaderName(p.Apply.Header) {
		return errors.New("apply.header is not a valid HTTP header name")
	}
	for name := range p.Profiles {
		if !ValidID(name) {
			return fmt.Errorf("profile name %q must be letters, digits, '-' or '_'", name)
		}
	}
	return nil
}

func validateRequest(field string, r RequestSpec) error {
	switch r.Method {
	case "GET", "POST", "PUT", "PATCH":
	default:
		return fmt.Errorf("%s.method %q not supported (GET, POST, PUT, PATCH)", field, r.Method)
	}
	if r.URL == "" {
		return fmt.Errorf("%s.url is required", field)
	}
	// The URL may be templated ({{base}}/token); validate the scheme only
	// when it is literal.
	if !strings.HasPrefix(r.URL, "{{") {
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%s.url must be an absolute http(s) URL", field)
		}
	}
	switch r.BodyType {
	case BodyJSON, BodyForm, BodyRaw:
	default:
		return fmt.Errorf("%s.body_type must be json, form or raw", field)
	}
	for k := range r.Headers {
		if !validHeaderName(k) {
			return fmt.Errorf("%s.headers: invalid header name %q", field, k)
		}
	}
	return nil
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", c) {
			return false
		}
	}
	return true
}

func validateRule(rule string) error {
	switch {
	case strings.HasPrefix(rule, "header:"):
		if !validHeaderName(strings.TrimSpace(strings.TrimPrefix(rule, "header:"))) {
			return errors.New("invalid header name")
		}
	case strings.HasPrefix(rule, "regex:"):
		if _, err := regexp.Compile(strings.TrimPrefix(rule, "regex:")); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	default:
		if _, err := parsePath(rule); err != nil {
			return err
		}
	}
	return nil
}

// ProfileNames returns the profile names sorted.
func (p *Provider) ProfileNames() []string {
	out := make([]string, 0, len(p.Profiles))
	for k := range p.Profiles {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Masked is the operator-safe view: secret values are replaced, keys kept.
func (p Provider) Masked() Provider {
	cp := p
	if len(p.Secrets) > 0 {
		cp.Secrets = make(map[string]string, len(p.Secrets))
		for k, v := range p.Secrets {
			if v == "" {
				cp.Secrets[k] = ""
			} else {
				cp.Secrets[k] = MaskedValue
			}
		}
	}
	return cp
}

// MaskedValue is the placeholder returned instead of a stored secret. Saving
// a provider with this value keeps the previously stored secret.
const MaskedValue = "********"

// MergeSecrets keeps stored secrets wherever the update carries MaskedValue.
func (p *Provider) MergeSecrets(prev *Provider) {
	if prev == nil {
		return
	}
	for k, v := range p.Secrets {
		if v == MaskedValue {
			if old, ok := prev.Secrets[k]; ok {
				p.Secrets[k] = old
			} else {
				delete(p.Secrets, k)
			}
		}
	}
}
