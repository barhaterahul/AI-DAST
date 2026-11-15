package tokenprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Token is one obtained credential.
type Token struct {
	Value      string    `json:"-"`
	Refresh    string    `json:"-"`
	Expiry     time.Time `json:"expiry"`
	ObtainedAt time.Time `json:"obtained_at"`
	// HeaderName/HeaderValue is the rendered auth header (e.g.
	// "Authorization: Bearer eyJ...").
	HeaderName  string   `json:"header_name"`
	HeaderValue string   `json:"-"`
	JWT         *JWTInfo `json:"jwt,omitempty"`
	// Source is "fetch" or "refresh".
	Source string `json:"source"`
}

// Headers returns the auth header map for the HTTP layer.
func (t *Token) Headers() map[string]string {
	if t == nil || t.HeaderName == "" {
		return nil
	}
	return map[string]string{t.HeaderName: t.HeaderValue}
}

// Doer is the subset of *http.Client used, so tests can stub transport.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client fetches tokens. The zero value is not usable; use NewClient.
type Client struct {
	HTTP Doer
	Now  func() time.Time
}

const (
	maxTokenResponse = 1 << 20 // 1 MiB
	requestTimeout   = 20 * time.Second
)

// NewClient returns a Client with a dedicated http.Client honoring the
// environment proxy. TLS verification is skipped only when the provider asks.
func NewClient(p *Provider) *Client {
	var tr *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		tr = dt.Clone()
	} else {
		tr = &http.Transport{}
	}
	tr.Proxy = http.ProxyFromEnvironment
	if p != nil && p.TLSSkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator opt-in for lab token APIs
	}
	return &Client{
		HTTP: &http.Client{Timeout: requestTimeout, Transport: tr},
		Now:  time.Now,
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// ErrMissingParams is returned when a template references undefined values.
type ErrMissingParams struct{ Names []string }

func (e *ErrMissingParams) Error() string {
	return "token request references undefined values: " + strings.Join(e.Names, ", ")
}

// Fetch obtains a fresh token for the named profile ("" = no parameters).
func (c *Client) Fetch(ctx context.Context, p *Provider, profile string) (*Token, error) {
	params, err := profileParams(p, profile)
	if err != nil {
		return nil, err
	}
	tok, err := c.do(ctx, p, p.Request, p.Extract, params, nil)
	if err != nil {
		return nil, err
	}
	tok.Source = "fetch"
	return tok, nil
}

// Refresh renews prev. It uses the configured refresh request when one exists
// and prev carries a refresh token; on refresh failure (or with no refresh
// request) it falls back to a full Fetch.
func (c *Client) Refresh(ctx context.Context, p *Provider, profile string, prev *Token) (*Token, error) {
	if p.Refresh.Request != nil && prev != nil && prev.Refresh != "" {
		params, err := profileParams(p, profile)
		if err != nil {
			return nil, err
		}
		ex := p.Extract
		if p.Refresh.Extract != nil {
			ex = *p.Refresh.Extract
		}
		extra := map[string]string{"refresh_token": prev.Refresh, "access_token": prev.Value}
		tok, rerr := c.do(ctx, p, *p.Refresh.Request, ex, params, extra)
		if rerr == nil {
			if tok.Refresh == "" { // non-rotating refresh tokens stay valid
				tok.Refresh = prev.Refresh
			}
			tok.Source = "refresh"
			return tok, nil
		}
		if ctx.Err() != nil {
			return nil, rerr
		}
		full, ferr := c.Fetch(ctx, p, profile)
		if ferr != nil {
			return nil, fmt.Errorf("refresh failed (%w); full token request also failed: %w", rerr, ferr)
		}
		return full, nil
	}
	return c.Fetch(ctx, p, profile)
}

func profileParams(p *Provider, profile string) (map[string]string, error) {
	if profile == "" {
		return map[string]string{}, nil
	}
	params, ok := p.Profiles[profile]
	if !ok {
		return nil, fmt.Errorf("profile %q not found in provider %q", profile, p.ID)
	}
	return params, nil
}

func (c *Client) do(ctx context.Context, p *Provider, spec RequestSpec, ex ExtractSpec, params, extra map[string]string) (*Token, error) {
	v := &vars{params: params, secrets: p.Secrets, extra: extra, missing: map[string]bool{}}
	req, err := buildRequest(ctx, spec, v)
	if err != nil {
		return nil, err
	}
	if m := v.missingList(); len(m) > 0 {
		return nil, &ErrMissingParams{Names: m}
	}
	if req == nil {
		return nil, errors.New("token request could not be built")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token API request failed: %w", redactErr(err, p, params))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse))
	if err != nil {
		return nil, fmt.Errorf("reading token API response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("token API returned HTTP %d: %s", resp.StatusCode, snippet(body, p, extra))
	}
	var doc any
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if dec.Decode(&doc) != nil {
			doc = nil
		} else {
			doc = normalizeNumbers(doc)
		}
	}
	value, err := extractValue(ex.Token, resp.Header, body, doc)
	if err != nil {
		return nil, fmt.Errorf("extract.token: %w", err)
	}
	if value == "" {
		return nil, fmt.Errorf("token not found in response using %q (HTTP %d): %s", ex.Token, resp.StatusCode, snippet(body, p, extra))
	}
	tok := &Token{Value: value, ObtainedAt: c.now()}
	if ex.RefreshToken != "" {
		if r, err := extractValue(ex.RefreshToken, resp.Header, body, doc); err == nil {
			tok.Refresh = r
		}
	}
	tok.JWT = DecodeJWT(value)
	tok.Expiry = c.expiry(p, ex, resp.Header, body, doc, tok)
	tok.HeaderName = p.Apply.Header
	tok.HeaderValue = strings.ReplaceAll(p.Apply.Format, "{{token}}", value)
	return tok, nil
}

func (c *Client) expiry(p *Provider, ex ExtractSpec, h http.Header, body []byte, doc any, tok *Token) time.Time {
	if ex.ExpiresIn != "" {
		if s, err := extractValue(ex.ExpiresIn, h, body, doc); err == nil && s != "" {
			if n, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && n > 0 {
				// Heuristic: a value that looks like a Unix timestamp is an
				// absolute expiry, not a duration.
				if n > 1e9 {
					return time.Unix(int64(n), 0)
				}
				return tok.ObtainedAt.Add(time.Duration(n * float64(time.Second)))
			}
		}
	}
	if tok.JWT != nil && !tok.JWT.Expiry.IsZero() {
		return tok.JWT.Expiry
	}
	return tok.ObtainedAt.Add(time.Duration(p.Refresh.MaxTTLSeconds) * time.Second)
}

// normalizeNumbers converts json.Number leaves to float64 so extraction and
// JWT helpers see uniform types.
func normalizeNumbers(x any) any {
	switch t := x.(type) {
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return t.String()
		}
		return f
	case map[string]any:
		for k, v := range t {
			t[k] = normalizeNumbers(v)
		}
	case []any:
		for i, v := range t {
			t[i] = normalizeNumbers(v)
		}
	}
	return x
}

func buildRequest(ctx context.Context, spec RequestSpec, v *vars) (*http.Request, error) {
	u := v.render(spec.URL)
	parsed, err := url.Parse(u)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		if len(v.missing) > 0 {
			// Report the undefined placeholder rather than a confusing URL error.
			return nil, nil
		}
		return nil, fmt.Errorf("token request URL %q is not an absolute http(s) URL", u)
	}
	var body io.Reader
	contentType := ""
	if spec.Body != nil && spec.Method != "GET" {
		switch spec.BodyType {
		case BodyForm:
			form := url.Values{}
			switch b := spec.Body.(type) {
			case map[string]any:
				for k, val := range b {
					form.Set(v.render(k), v.render(fmt.Sprint(val)))
				}
			case map[string]string:
				for k, val := range b {
					form.Set(v.render(k), v.render(val))
				}
			default:
				return nil, errors.New("form body must be an object of strings")
			}
			body = strings.NewReader(form.Encode())
			contentType = "application/x-www-form-urlencoded"
		case BodyRaw:
			s, ok := spec.Body.(string)
			if !ok {
				return nil, errors.New("raw body must be a string")
			}
			body = strings.NewReader(v.render(s))
		default:
			rendered := v.renderValue(spec.Body)
			b, err := json.Marshal(rendered)
			if err != nil {
				return nil, fmt.Errorf("encoding JSON body: %w", err)
			}
			body = bytes.NewReader(b)
			contentType = "application/json"
		}
	}
	req, err := http.NewRequestWithContext(ctx, spec.Method, parsed.String(), body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range spec.Headers {
		req.Header.Set(k, v.render(val))
	}
	return req, nil
}

// snippet returns a short, secret-redacted excerpt of a response body for
// error messages shown to the operator.
func snippet(body []byte, p *Provider, extra map[string]string) string {
	s := strings.TrimSpace(string(body))
	s = redactString(s, p, extra)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

func redactString(s string, p *Provider, extra map[string]string) string {
	for _, v := range p.Secrets {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	for _, v := range extra {
		if len(v) >= 4 {
			s = strings.ReplaceAll(s, v, "***")
		}
	}
	return s
}

func redactErr(err error, p *Provider, _ map[string]string) error {
	return errors.New(redactString(err.Error(), p, nil))
}

// SecretValues returns the provider's secret values plus a token's sensitive
// parts, for telemetry redaction.
func SecretValues(p *Provider, toks ...*Token) []string {
	var out []string
	for _, v := range p.Secrets {
		if len(strings.TrimSpace(v)) >= 4 {
			out = append(out, v)
		}
	}
	for _, t := range toks {
		if t == nil {
			continue
		}
		for _, v := range []string{t.Value, t.Refresh, t.HeaderValue} {
			if len(strings.TrimSpace(v)) >= 8 {
				out = append(out, v)
			}
		}
	}
	return out
}

// MaskToken renders a token as a short, non-sensitive preview.
func MaskToken(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 12 {
		return strings.Repeat("•", len(s))
	}
	return s[:6] + "…" + s[len(s)-4:]
}
