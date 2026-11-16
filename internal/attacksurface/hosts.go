package attacksurface

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Host scoping for uploaded context.
//
// API collections and HAR captures routinely call services the operator does
// not own (identity providers, payment gateways, analytics). Every host they
// mention used to become a scan target. Hosts now carry a first-/third-party
// classification for the UI, and a scan only keeps the endpoints on the hosts
// the operator put in scope (Options.Hosts, written at scan start).

// HostInfo describes one host referenced by the uploaded context.
type HostInfo struct {
	BaseURL    string `json:"base_url"` // scheme://host[:port]
	Host       string `json:"host"`     // lowercased hostname, no port
	Requests   int    `json:"requests"` // endpoints on this host
	ThirdParty bool   `json:"third_party"`
	Reason     string `json:"reason,omitempty"`
}

// knownThirdParty lists registrable domains of common SaaS / platform
// services that show up in collections and captures but are almost never the
// system under test. Matched against the host's eTLD+1.
var knownThirdParty = map[string]string{
	// identity
	"auth0.com": "identity provider", "okta.com": "identity provider", "oktapreview.com": "identity provider",
	"onelogin.com": "identity provider", "microsoftonline.com": "identity provider", "duosecurity.com": "identity provider",
	"firebaseapp.com": "identity provider",
	// google / meta / microsoft platforms
	"googleapis.com": "Google API", "google.com": "Google", "gstatic.com": "Google CDN", "googleusercontent.com": "Google",
	"google-analytics.com": "analytics", "googletagmanager.com": "analytics", "doubleclick.net": "ads",
	"facebook.com": "Meta", "facebook.net": "Meta", "fbcdn.net": "Meta CDN", "live.com": "Microsoft", "office.com": "Microsoft",
	// payments
	"stripe.com": "payments", "paypal.com": "payments", "braintreegateway.com": "payments", "adyen.com": "payments",
	"razorpay.com": "payments", "squareup.com": "payments",
	// messaging / email
	"twilio.com": "messaging", "sendgrid.com": "email", "sendgrid.net": "email", "mailgun.net": "email",
	"mailchimp.com": "email", "postmarkapp.com": "email", "slack.com": "messaging",
	// analytics / monitoring / support
	"segment.io": "analytics", "segment.com": "analytics", "mixpanel.com": "analytics", "amplitude.com": "analytics",
	"hotjar.com": "analytics", "sentry.io": "monitoring", "datadoghq.com": "monitoring", "newrelic.com": "monitoring",
	"nr-data.net": "monitoring", "intercom.io": "support", "zendesk.com": "support",
	// code hosting / CDNs
	"github.com": "code hosting", "githubusercontent.com": "code hosting", "gitlab.com": "code hosting",
	"jsdelivr.net": "CDN", "unpkg.com": "CDN", "cdnjs.com": "CDN", "cloudflare.com": "CDN",
	// API-client and documentation placeholders
	"getpostman.com": "Postman", "postman.com": "Postman", "postman-echo.com": "Postman echo service",
	"httpbin.org": "test service", "example.com": "documentation placeholder", "example.org": "documentation placeholder",
	"example.net": "documentation placeholder",
}

// absoluteHost returns the lowercased host and scheme://host[:port] of an
// absolute http(s) URL. unresolved reports a host still holding a
// {{variable}}.
func absoluteHost(raw string) (host, base string, unresolved bool) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "{{") {
		return "", "", true
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", "", strings.Contains(raw, "{{")
	}
	if strings.Contains(u.Host, "{{") {
		return "", "", true
	}
	return strings.ToLower(u.Hostname()), u.Scheme + "://" + strings.ToLower(u.Host), false
}

// registrableDomain is the eTLD+1 of host, or host itself for IPs, single
// labels and anything the public-suffix list cannot split.
func registrableDomain(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// Hosts lists every absolute host the result references, most-used first,
// classified as first- or third-party. The primary domain is the registrable
// domain with the most requests among hosts that are not known services.
func (r *Result) Hosts() []HostInfo {
	if r == nil {
		return nil
	}
	byBase := map[string]*HostInfo{}
	add := func(raw string, count int) {
		host, base, _ := absoluteHost(raw)
		if host == "" {
			return
		}
		hi := byBase[base]
		if hi == nil {
			hi = &HostInfo{BaseURL: base, Host: host}
			byBase[base] = hi
		}
		hi.Requests += count
	}
	for _, e := range r.Endpoints {
		add(e.Path, 1)
	}
	for _, b := range r.BaseURLs {
		add(b, 0)
	}

	domainReqs := map[string]int{}
	for _, hi := range byBase {
		d := registrableDomain(hi.Host)
		if _, known := knownThirdParty[d]; !known {
			domainReqs[d] += hi.Requests + 1 // +1 so host-only entries count
		}
	}
	best := 0
	for _, n := range domainReqs {
		if n > best {
			best = n
		}
	}
	primary := map[string]bool{}
	var primaryNames []string
	for d, n := range domainReqs {
		if n == best {
			primary[d] = true
			primaryNames = append(primaryNames, d)
		}
	}
	sort.Strings(primaryNames)

	out := make([]HostInfo, 0, len(byBase))
	for _, hi := range byBase {
		d := registrableDomain(hi.Host)
		switch {
		case knownThirdParty[d] != "":
			hi.ThirdParty, hi.Reason = true, "known third-party service ("+knownThirdParty[d]+")"
		case !primary[d]:
			hi.ThirdParty, hi.Reason = true, "different domain from "+strings.Join(primaryNames, ", ")
		}
		out = append(out, *hi)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ThirdParty != out[j].ThirdParty {
			return !out[i].ThirdParty
		}
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].BaseURL < out[j].BaseURL
	})
	return out
}

// FirstPartyBaseURLs returns the base URLs of the hosts classified as
// first-party, used as targets when the operator typed none.
func (r *Result) FirstPartyBaseURLs() []string {
	var out []string
	for _, h := range r.Hosts() {
		if !h.ThirdParty {
			out = append(out, h.BaseURL)
		}
	}
	return out
}

// UnresolvedHostRequests counts endpoints whose host is still a {{variable}}.
func (r *Result) UnresolvedHostRequests() int {
	if r == nil {
		return 0
	}
	n := 0
	for _, e := range r.Endpoints {
		if _, _, unresolved := absoluteHost(e.Path); unresolved {
			n++
		}
	}
	return n
}

// hostInScope reports whether host is one of scope, or (subdomains) a
// subdomain of one.
func hostInScope(host string, scope map[string]bool, subdomains bool) bool {
	if scope[host] {
		return true
	}
	if subdomains {
		for s := range scope {
			if strings.HasSuffix(host, "."+s) {
				return true
			}
		}
	}
	return false
}

// RestrictToHosts drops endpoints on absolute hosts outside scope (and the
// matching base URLs). Relative endpoints, which have no host to judge, are
// kept. Returns the number of endpoints dropped.
func (r *Result) RestrictToHosts(hosts []string, subdomains bool) int {
	if r == nil || len(hosts) == 0 {
		return 0
	}
	scope := map[string]bool{}
	for _, h := range hosts {
		if h = normalizeScopeHost(h); h != "" {
			scope[h] = true
		}
	}
	if len(scope) == 0 {
		return 0
	}
	kept := r.Endpoints[:0]
	dropped := 0
	for _, e := range r.Endpoints {
		host, _, unresolved := absoluteHost(e.Path)
		if unresolved || (host != "" && !hostInScope(host, scope, subdomains)) {
			dropped++
			continue
		}
		kept = append(kept, e)
	}
	r.Endpoints = kept
	bases := r.BaseURLs[:0]
	for _, b := range r.BaseURLs {
		if host, _, _ := absoluteHost(b); host == "" || hostInScope(host, scope, subdomains) {
			bases = append(bases, b)
		}
	}
	r.BaseURLs = bases
	r.OutOfScope += dropped
	return dropped
}

// normalizeScopeHost turns a target ("https://api.x.com/v1", "api.x.com:8443",
// "API.x.com") into a bare lowercased hostname.
func normalizeScopeHost(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return ""
	}
	if !strings.Contains(t, "://") {
		t = "http://" + t
	}
	u, err := url.Parse(t)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// ScopeHosts converts scan targets into the host list stored in Options.Hosts.
func ScopeHosts(targets []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		if h := normalizeScopeHost(t); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}
