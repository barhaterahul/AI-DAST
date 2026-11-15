package web

// Heuristics for the Exploration Graph that make agent-written data usable:
// validating ledger finding_ref links, inferring a hypothesis for findings the
// ledger never linked, and pulling the injected value out of a finding's prose
// proof when no structured request carries it.

import (
	"regexp"
	"strings"
)

// ---- vulnerability class families ----

type egFamilyRule struct {
	family   string
	keywords []string
	cwes     []string
}

// Ordered: specific families first, so "XSS steals the session token" is xss,
// not access.
var egFamilyRules = []egFamilyRule{
	{"xxe", []string{"xxe", "xml external", "external entit"}, []string{"611", "776"}},
	{"sqli", []string{"sqli", "sql injection", "sql-injection", "blind sql", "nosql"}, []string{"89", "564", "943"}},
	{"xss", []string{"xss", "cross-site scripting", "cross site scripting", "html injection", "dom-based"}, []string{"79", "80", "83", "87"}},
	{"ssti", []string{"ssti", "template injection"}, []string{"1336", "94"}},
	{"cmdi", []string{"command injection", "cmdi", "rce", "remote code", "os command", "code injection", "deserializ"}, []string{"77", "78", "502"}},
	{"lfi", []string{"lfi", "rfi", "path traversal", "directory traversal", "traversal", "file inclusion", "file read", "arbitrary file"}, []string{"22", "23", "35", "73", "98"}},
	{"ssrf", []string{"ssrf", "server-side request", "server side request"}, []string{"918"}},
	{"csrf", []string{"csrf", "cross-site request forgery", "cross site request forgery", "xsrf"}, []string{"352"}},
	{"redirect", []string{"open redirect", "open_redirect", "redirect"}, []string{"601"}},
	{"access", []string{"idor", "bola", "bfla", "authz", "authorization", "access control", "access_control", "privilege",
		"auth", "credential", "login", "session", "jwt", "token", "password", "admin"},
		[]string{"639", "284", "285", "862", "863", "287", "798", "521", "1392", "306", "307", "384", "613", "522", "256", "257", "312", "319", "347", "345"}},
	{"info", []string{"information disclosure", "info_disclosure", "disclosure", "exposure", "leak"}, []string{"200", "209", "215", "497", "538", "548"}},
}

var egCWENumRe = regexp.MustCompile(`(?i)CWE[-\s:]*(\d+)`)

// classFamilyEG maps a vuln class / title / CWE to a coarse family, or "".
func classFamilyEG(cwe string, texts ...string) string {
	if m := egCWENumRe.FindStringSubmatch(cwe); m != nil {
		for _, r := range egFamilyRules {
			for _, c := range r.cwes {
				if c == m[1] {
					return r.family
				}
			}
		}
	}
	for _, t := range texts {
		l := strings.ToLower(t)
		if strings.TrimSpace(l) == "" {
			continue
		}
		for _, r := range egFamilyRules {
			for _, k := range r.keywords {
				if strings.Contains(l, k) {
					return r.family
				}
			}
		}
	}
	return ""
}

func findingFamilyEG(v *VulnSummary) string {
	return classFamilyEG(v.CWE, v.Title)
}

func hypothesisFamilyEG(h *egHypothesis) string {
	return classFamilyEG("", h.VulnClass, h.Title)
}

// hypothesisEndpointEG is the raw endpoint a hypothesis targets (its own
// endpoint field, else the dedup key's endpoint part).
func hypothesisEndpointEG(h *egHypothesis) string {
	if e := strings.TrimSpace(h.Endpoint); e != "" {
		return e
	}
	parts := strings.Split(h.DedupKey, "|")
	if len(parts) >= 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// linkPlausibleEG reports whether a ledger finding_ref from h to v is
// believable. Agents occasionally attach a finding_ref to the wrong
// hypothesis (e.g. an SSRF lane recording an IDOR finding it did not
// produce); such a link is dropped when both the endpoint and the vuln family
// disagree.
func (b *explorationBuilder) linkPlausibleEG(h *egHypothesis, v *VulnSummary) bool {
	_, hp, _ := b.normalizeEndpoint(hypothesisEndpointEG(h), "")
	_, fp, _ := b.normalizeEndpoint(v.Endpoint, v.Method)
	if hp == "" || fp == "" || hp == fp {
		return true
	}
	hf, ff := hypothesisFamilyEG(h), findingFamilyEG(v)
	return hf != "" && hf == ff
}

// inferHypothesisEG picks the ledger hypothesis that most plausibly produced
// a finding the ledger never linked: same templated endpoint and same vuln
// family, preferring proven status, exploit evidence, a matching parameter
// and higher confidence. Returns -1 when nothing matches.
func (b *explorationBuilder) inferHypothesisEG(hyps []egHypothesis, v *VulnSummary) int {
	_, fp, _ := b.normalizeEndpoint(v.Endpoint, v.Method)
	ff := findingFamilyEG(v)
	if fp == "" || ff == "" {
		return -1
	}
	param := strings.ToLower(paramFromFindingEG(v))
	best, bestScore := -1, -1.0
	for i := range hyps {
		h := &hyps[i]
		if h.ID == "" || strings.EqualFold(strings.TrimSpace(h.Status), "queued") {
			continue
		}
		if hypothesisFamilyEG(h) != ff {
			continue
		}
		if _, hp, _ := b.normalizeEndpoint(hypothesisEndpointEG(h), ""); hp != fp {
			continue
		}
		score := h.Confidence
		if strings.EqualFold(strings.TrimSpace(h.Status), "proven") {
			score += 10
		}
		if param != "" && strings.EqualFold(cleanParamEG(h.Parameter), param) {
			score += 5
		}
		for _, e := range h.Evidence {
			if isExploitEvidenceEG(e) {
				score += 2
				break
			}
		}
		if score > bestScore {
			best, bestScore = i, score
		}
	}
	return best
}

// ---- prose payload / parameter extraction ----

var (
	egProseParamRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9_\[\].-])([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63})=`)
	egInjectionRe  = regexp.MustCompile(`(?i)['"<>` + "`" + `;|]|\.\./|\.\.\\|\$\{|\{\{|--|%27|%22|%3c|%3e|%60|\bor\s+\d|\bunion\b|\bselect\b|sleep\(|javascript:|<!`)
	egProseStopRe  = regexp.MustCompile(`\s(?:to|and|then|which|returns?|observe[ds]?|gives?|yields?|on|at|with|->|=>|→)\s`)
	// HTML attribute names that appear inside injected markup, not request parameters.
	egAttrNames = map[string]bool{"src": true, "href": true, "style": true, "class": true, "xmlns": true, "version": true,
		"encoding": true, "action": true, "method": true, "type": true, "charset": true}
)

func isAttrNameEG(name string) bool {
	l := strings.ToLower(name)
	return egAttrNames[l] || (strings.HasPrefix(l, "on") && len(l) > 4)
}

func hasInjectionEG(v string) bool {
	return egInjectionRe.MatchString(v)
}

// proseValueEG reads a parameter value starting at s (just after "name="),
// stopping where prose resumes.
func proseValueEG(s string) string {
	if s == "" {
		return ""
	}
	if s[0] == '<' {
		// Markup: read whole tags (quotes inside a tag may hide '>') plus any
		// directly adjacent text, e.g. <script>alert(1)</script>.
		var quote byte
		inTag := false
		end := -1
	scan:
		for i := 0; i < len(s) && i < 2000; i++ {
			c := s[i]
			if quote != 0 {
				if c == quote {
					quote = 0
				}
				continue
			}
			switch {
			case inTag && (c == '"' || c == '\''):
				quote = c
			case c == '<':
				inTag = true
			case c == '>':
				inTag = false
				end = i + 1
			case c == '\n' || c == '\r':
				break scan
			case !inTag && (c == ' ' || c == '\t' || c == '&'):
				break scan
			}
		}
		if end > 0 {
			return s[:end]
		}
	}
	end := len(s)
	if i := strings.IndexAny(s, "&\n\r`"); i >= 0 {
		end = i
	}
	v := s[:end]
	// SQL-style payloads carry spaces up to a trailing comment marker:
	// "2000-01-01' ORDER BY 1 --".
	if i := strings.Index(v, "--"); i > 0 && i <= 150 && strings.ContainsAny(v[:i], "'\"") {
		return strings.TrimSpace(v[:i+2])
	}
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		v = v[:i]
	}
	// An unbalanced closing quote belongs to the surrounding prose:
	// `acct=1001"` -> 1001.
	if strings.Count(v, "\"")%2 == 1 && !strings.HasPrefix(v, "\"") {
		v = v[:strings.LastIndex(v, "\"")]
	}
	return strings.TrimRight(strings.TrimSpace(v), ".,;:)")
}

type egProseCandidate struct {
	name, value   string
	injected      bool
	requestShaped bool // preceded by ?/& or followed by &
}

func proseCandidatesEG(text string) []egProseCandidate {
	var out []egProseCandidate
	for _, m := range egProseParamRe.FindAllStringSubmatchIndex(text, -1) {
		name := text[m[2]:m[3]]
		if isAttrNameEG(name) {
			continue
		}
		raw := proseValueEG(text[m[1]:])
		if raw == "" {
			continue
		}
		val := raw
		if strings.Contains(val, "%") {
			val = decodeEG(val)
		}
		shaped := false
		if m[2] > 0 && (text[m[2]-1] == '?' || text[m[2]-1] == '&') {
			shaped = true
		}
		if rest := text[m[1]:]; len(raw) <= len(rest) && strings.HasPrefix(rest[len(raw):], "&") {
			shaped = true
		}
		out = append(out, egProseCandidate{name: name, value: val, injected: hasInjectionEG(raw) || hasInjectionEG(val), requestShaped: shaped})
		if len(out) >= 64 {
			break
		}
	}
	return out
}

// payloadFromTextEG extracts the value sent for param from free-text proof
// (exploitation_proof, PoC steps): request lines and curl commands first, then
// "param=value" mentions, preferring a value that looks injected over a
// baseline value. Returns "" when the parameter is not mentioned.
func payloadFromTextEG(text, param string, requireInjected bool) string {
	if param == "" || strings.TrimSpace(text) == "" {
		return ""
	}
	if len(text) > 64<<10 {
		text = text[:64<<10]
	}
	if strings.ContainsAny(param, " \t") {
		// A body-level "parameter" ("XML body"): the payload is the body.
		return truncateRunesEG(bodyFromTextEG(text), explorationPayloadMax)
	}
	if !strings.Contains(text, param) {
		return ""
	}
	first := ""
	for _, line := range strings.Split(text, "\n") {
		if !strings.Contains(line, param) {
			continue
		}
		line = strings.TrimSpace(line)
		cands := []string{line}
		if i := strings.Index(strings.ToLower(line), "curl "); i > 0 {
			cands = append([]string{line[i:]}, cands...)
		}
		if u := egURLRe.FindString(line); u != "" {
			cands = append(cands, u)
		}
		for _, c := range cands {
			p := parseRequestEG(c)
			if v, loc := extractParamValueEG(p, "", param); v != "" && loc != "unknown" {
				if hasInjectionEG(v) {
					return truncateRunesEG(v, explorationPayloadMax)
				}
				if first == "" {
					first = v
				}
			}
		}
	}
	jsonRe := regexp.MustCompile(`"` + regexp.QuoteMeta(param) + `"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	for _, m := range jsonRe.FindAllStringSubmatch(text, 16) {
		if hasInjectionEG(m[1]) {
			return truncateRunesEG(m[1], explorationPayloadMax)
		}
		if first == "" {
			first = m[1]
		}
	}
	for _, c := range proseCandidatesEG(text) {
		if c.name != param {
			continue
		}
		if c.injected {
			return truncateRunesEG(c.value, explorationPayloadMax)
		}
		if first == "" {
			first = c.value
		}
	}
	if requireInjected {
		return ""
	}
	return truncateRunesEG(first, explorationPayloadMax)
}

var egXMLBodyRe = regexp.MustCompile(`(?s)<\?xml.*?(?:\]>|\?>)[^'\n]*|<!DOCTYPE[^\n']*`)

// bodyFromTextEG returns a request body found in proof text (a curl
// -d/--data argument, else an inline XML document), preferring one that
// carries an entity/DOCTYPE or other injected content over a benign control.
func bodyFromTextEG(text string) string {
	var bodies []string
	for _, line := range strings.Split(text, "\n") {
		i := strings.Index(strings.ToLower(line), "curl ")
		if i < 0 {
			continue
		}
		if p := parseRequestEG(strings.TrimSpace(line[i:])); strings.TrimSpace(p.body) != "" {
			bodies = append(bodies, strings.TrimSpace(p.body))
		}
	}
	if m := egXMLBodyRe.FindString(text); m != "" {
		bodies = append(bodies, strings.TrimSpace(m))
	}
	// "POST /api/login  Content-Type: application/json  {"username":...}"
	for _, line := range strings.Split(text, "\n") {
		if !egBodyMethodLineRe.MatchString(line) {
			continue
		}
		if m := egInlineJSONRe.FindString(line); m != "" {
			bodies = append(bodies, m)
		}
	}
	for _, b := range bodies {
		if strings.Contains(b, "<!ENTITY") || strings.Contains(b, "<!DOCTYPE") {
			return b
		}
	}
	if len(bodies) > 0 {
		return bodies[0]
	}
	return ""
}

var (
	egBodyMethodLineRe = regexp.MustCompile(`\b(?:POST|PUT|PATCH)\s+/`)
	egInlineJSONRe     = regexp.MustCompile(`\{"[^{}\n]{1,400}?"\s*\}`)
)

var egPlaceholderNameRe = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]{0,63})\}`)

// placeholderParamEG returns a path-parameter name written as a {placeholder}
// in a finding's title or endpoint ("/api/account/{accountId}/transactions").
func placeholderParamEG(v *VulnSummary) string {
	for _, t := range []string{v.Endpoint, v.Title} {
		if m := egPlaceholderNameRe.FindStringSubmatch(t); m != nil && m[1] != "id" {
			return m[1]
		}
	}
	return ""
}

// pathValueFromTextEG returns the concrete value used for the first {id}
// segment of a templated path, as seen in text ("/api/account/1001"). The
// target's context path is optional in the text.
func (b *explorationBuilder) pathValueFromTextEG(text, tpl string) string {
	if !strings.Contains(tpl, "{id}") || strings.HasPrefix(tpl, "//") {
		return ""
	}
	rel := tpl
	if b.basePath != "" && strings.HasPrefix(tpl, b.basePath+"/") {
		rel = strings.TrimPrefix(tpl, b.basePath)
	}
	parts := strings.Split(rel, "{id}")
	var sb strings.Builder
	if b.basePath != "" {
		sb.WriteString("(?:" + regexp.QuoteMeta(b.basePath) + ")?")
	}
	for i, part := range parts {
		sb.WriteString(regexp.QuoteMeta(part))
		if i < len(parts)-1 {
			if i == 0 {
				sb.WriteString(`([^/\s?#"'&<>]+)`)
			} else {
				sb.WriteString(`[^/\s?#"'&<>]+`)
			}
		}
	}
	re, err := regexp.Compile(sb.String())
	if err != nil {
		return ""
	}
	for _, m := range re.FindAllStringSubmatch(text, 8) {
		if m[1] != "" && !strings.HasPrefix(m[1], "{") && !strings.HasPrefix(m[1], ":") {
			return decodeEG(m[1])
		}
	}
	return ""
}

// injectionFamilyEG reports whether a vuln family is about injecting a
// crafted value (so a plain baseline value is not a meaningful payload).
func injectionFamilyEG(f string) bool {
	switch f {
	case "xss", "sqli", "xxe", "ssti", "cmdi", "lfi", "ssrf", "redirect":
		return true
	}
	return false
}

// paramFromProofEG names the parameter a finding's proof injected into: the
// first "name=value" mention whose value looks injected.
func paramFromProofEG(v *VulnSummary) string {
	for _, text := range []string{v.PoCDescription, v.ExploitationProof} {
		for _, c := range proseCandidatesEG(text) {
			// Only request-shaped mentions count (after "?"/"&", or a form
			// body "a=b&c=d"); "loggedIn=false" in prose or base64 padding
			// ("ZGVtbzEyMzQ=") are not parameters.
			if c.injected && c.requestShaped && !strings.Contains(c.name, ".") {
				if name := cleanParamEG(c.name); name != "" {
					return name
				}
			}
		}
	}
	return ""
}

// locationFromTextEG infers where param travels from proof text and method.
func locationFromTextEG(text, param, method string) string {
	if param == "" || !strings.Contains(text, param) {
		return "unknown"
	}
	if strings.Contains(text, "?"+param+"=") {
		return "query"
	}
	if regexp.MustCompile(`(?i)(?:cookie:[^\n]*\b)` + regexp.QuoteMeta(param) + `=`).MatchString(text) {
		return "cookie"
	}
	mentioned := strings.Contains(text, param+"=") || strings.Contains(text, `"`+param+`"`)
	if !mentioned {
		return "unknown"
	}
	if isBodyMethodEG(method) {
		return "body"
	}
	if method == "GET" || method == "DELETE" || method == "HEAD" {
		return "query"
	}
	return "unknown"
}

func isBodyMethodEG(m string) bool {
	switch strings.ToUpper(m) {
	case "POST", "PUT", "PATCH":
		return true
	}
	return false
}

// findingProofTextEG joins the prose fields that may hold the injected value.
func findingProofTextEG(v *VulnSummary) string {
	return v.PoCDescription + "\n" + v.ExploitationProof
}
