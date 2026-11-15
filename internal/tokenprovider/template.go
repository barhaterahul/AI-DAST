package tokenprovider

import (
	"regexp"
	"sort"
	"strings"
)

var placeholderRe = regexp.MustCompile(`\{\{\s*([a-zA-Z0-9_.:-]+)\s*\}\}`)

// vars is the resolution scope for one rendering.
type vars struct {
	params  map[string]string // profile parameters
	secrets map[string]string // provider secrets ({{secret:x}})
	extra   map[string]string // refresh_token / access_token / token
	missing map[string]bool
}

func (v *vars) lookup(name string) (string, bool) {
	if s, ok := strings.CutPrefix(name, "secret:"); ok {
		val, found := v.secrets[s]
		return val, found
	}
	if val, ok := v.extra[name]; ok {
		return val, true
	}
	val, ok := v.params[name]
	return val, ok
}

// render substitutes placeholders in s. Unknown placeholders are left intact
// and recorded as missing so the caller can fail with a precise message.
func (v *vars) render(s string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		if val, ok := v.lookup(name); ok {
			return val
		}
		if v.missing != nil {
			v.missing[name] = true
		}
		return m
	})
}

// renderValue walks a decoded JSON value substituting placeholders in string
// leaves (and object keys). Values are substituted as plain strings, so the
// result re-encodes as valid, correctly escaped JSON.
func (v *vars) renderValue(x any) any {
	switch t := x.(type) {
	case string:
		return v.render(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[v.render(k)] = v.renderValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = v.renderValue(val)
		}
		return out
	default:
		return x
	}
}

func (v *vars) missingList() []string {
	out := make([]string, 0, len(v.missing))
	for k := range v.missing {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Placeholders lists every {{name}} referenced by the provider's requests
// (excluding secrets and runtime token values), so the UI can show which
// parameters a profile must define.
func (p *Provider) Placeholders() []string {
	seen := map[string]bool{}
	var walk func(any)
	collect := func(s string) {
		for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
			name := m[1]
			if strings.HasPrefix(name, "secret:") {
				continue
			}
			switch name {
			case "token", "access_token", "refresh_token":
				continue
			}
			seen[name] = true
		}
	}
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			collect(t)
		case map[string]any:
			for k, val := range t {
				collect(k)
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		case map[string]string:
			for k, val := range t {
				collect(k)
				collect(val)
			}
		}
	}
	reqs := []*RequestSpec{&p.Request}
	if p.Refresh.Request != nil {
		reqs = append(reqs, p.Refresh.Request)
	}
	for _, r := range reqs {
		collect(r.URL)
		for k, val := range r.Headers {
			collect(k)
			collect(val)
		}
		walk(r.Body)
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
