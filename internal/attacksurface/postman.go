package attacksurface

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ── Postman collection (v2.0 / v2.1) + environments/globals ─────────────────

type postmanColl struct {
	Info struct {
		Name   string `json:"name"`
		Schema string `json:"schema"`
	} `json:"info"`
	Item     []postmanItem  `json:"item"`
	Variable []postmanVar   `json:"variable"` // collection-level variables
	Auth     *postmanAuth   `json:"auth"`     // collection-level default auth
	Event    []postmanEvent `json:"event"`
}

type postmanItem struct {
	Name     string          `json:"name"`
	Item     []postmanItem   `json:"item"` // folders nest items
	Request  *postmanRequest `json:"request"`
	Auth     *postmanAuth    `json:"auth"` // folder-level auth (cascades to children)
	Event    []postmanEvent  `json:"event"`
	Variable []postmanVar    `json:"variable"`
}

type postmanEvent struct {
	Listen string `json:"listen"`
	Script struct {
		Exec json.RawMessage `json:"exec"` // []string or string
	} `json:"script"`
}

func (e postmanEvent) nonEmpty() bool {
	var lines []string
	if json.Unmarshal(e.Script.Exec, &lines) == nil {
		for _, l := range lines {
			if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "//") {
				return true
			}
		}
		return false
	}
	var s string
	return json.Unmarshal(e.Script.Exec, &s) == nil && strings.TrimSpace(s) != ""
}

func countScripts(evs []postmanEvent) int {
	n := 0
	for _, e := range evs {
		if e.nonEmpty() {
			n++
		}
	}
	return n
}

type postmanKV struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	Type     string `json:"type"` // formdata: text | file
	Disabled bool   `json:"disabled"`
}

type postmanRequest struct {
	Method string          `json:"method"`
	Header json.RawMessage `json:"header"` // []postmanKV (v2.1) or string (v2.0)
	URL    json.RawMessage `json:"url"`    // string OR object
	Auth   *postmanAuth    `json:"auth"`
	Body   *postmanBody    `json:"body"`
}

type postmanBody struct {
	Mode       string      `json:"mode"`
	Raw        string      `json:"raw"`
	URLEncoded []postmanKV `json:"urlencoded"`
	FormData   []postmanKV `json:"formdata"`
	GraphQL    *struct {
		Query     string `json:"query"`
		Variables string `json:"variables"`
	} `json:"graphql"`
	Options struct {
		Raw struct {
			Language string `json:"language"`
		} `json:"raw"`
	} `json:"options"`
}

type postmanURL struct {
	Raw      string      `json:"raw"`
	Query    []postmanKV `json:"query"`
	Variable []postmanKV `json:"variable"`
}

// postmanVar is one variable from a collection's variable[] list or an
// environment/globals export's values[] list. Postman disables collection
// variables with "disabled":true and environment values with "enabled":false —
// both are honored so we don't resolve against a value the operator turned off.
type postmanVar struct {
	Key      string `json:"key"`
	Value    any    `json:"value"`
	Disabled bool   `json:"disabled"`
	Enabled  *bool  `json:"enabled"`
}

func (v postmanVar) active() bool {
	if v.Disabled || strings.TrimSpace(v.Key) == "" {
		return false
	}
	return v.Enabled == nil || *v.Enabled
}

func (v postmanVar) str() string {
	switch t := v.Value.(type) {
	case nil:
		return ""
	case string:
		return t
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func varsMap(list []postmanVar) map[string]string {
	out := map[string]string{}
	for _, v := range list {
		if v.active() {
			out[v.Key] = v.str()
		}
	}
	return out
}

// postmanAuth is a Postman auth block, which can sit at collection, folder, or
// request level. Only the fields for the selected Type are populated.
type postmanAuth struct {
	Type   string          `json:"type"`
	Bearer []postmanAuthKV `json:"bearer"`
	Basic  []postmanAuthKV `json:"basic"`
	APIKey []postmanAuthKV `json:"apikey"`
	OAuth2 []postmanAuthKV `json:"oauth2"`
}

type postmanAuthKV struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
}

func authKVGet(kvs []postmanAuthKV, key string) string {
	for _, kv := range kvs {
		if strings.EqualFold(strings.TrimSpace(kv.Key), key) {
			if s, ok := kv.Value.(string); ok {
				return s
			}
			if kv.Value != nil {
				b, _ := json.Marshal(kv.Value)
				return string(b)
			}
		}
	}
	return ""
}

// postmanCtx carries variable scopes from sibling files of a collection.
type postmanCtx struct {
	env     map[string]string // selected environment
	globals map[string]string
	opts    Options
	envs    []string // names of all environments seen
}

// parsePostman parses a collection with sibling environment variables (kept
// for callers/tests of the original API).
func parsePostman(data []byte, extraVars map[string]string) *Result {
	return parsePostmanWith(data, &postmanCtx{env: extraVars})
}

func parsePostmanWith(data []byte, pc *postmanCtx) *Result {
	var coll postmanColl
	if err := json.Unmarshal(data, &coll); err != nil {
		return nil
	}
	if pc == nil {
		pc = &postmanCtx{}
	}
	// Scope order (first wins): operator vars > environment > collection > globals.
	root := newResolver(pc.opts.Vars, pc.env, varsMap(coll.Variable), pc.globals)

	res := &Result{AuthHeaders: map[string]string{}, Environments: pc.envs, Environment: selectedEnvName(pc.envs, pc.opts.Env)}
	if strings.Contains(coll.Info.Schema, "v2.0") {
		res.Notes = append(res.Notes, "Postman collection schema v2.0")
	}
	scripts := countScripts(coll.Event)
	var reqs []collReq

	var walk func(items []postmanItem, inherited *postmanAuth, folder string, rv *resolver)
	walk = func(items []postmanItem, inherited *postmanAuth, folder string, rv *resolver) {
		for _, it := range items {
			scripts += countScripts(it.Event)
			eff := inherited
			if it.Auth != nil { // folder/request-level auth cascades
				eff = it.Auth
			}
			irv := rv
			if len(it.Variable) > 0 {
				irv = rv.with(varsMap(it.Variable))
			}
			if len(it.Item) > 0 || it.Request == nil {
				sub := it.Name
				if folder != "" {
					sub = folder + "/" + it.Name
				}
				walk(it.Item, eff, sub, irv)
			}
			if it.Request == nil {
				continue
			}
			cr, ok := postmanRequestToColl(it, folder, eff, irv)
			if ok {
				reqs = append(reqs, cr)
			}
		}
	}
	walk(coll.Item, coll.Auth, "", root)

	res = collectionResult("postman", reqs, res, pc.opts)
	addScriptNote(res, scripts)
	res.MissingVars = root.missingList()
	return res
}

func postmanRequestToColl(it postmanItem, folder string, inherited *postmanAuth, rv *resolver) (collReq, bool) {
	r := it.Request
	cr := collReq{source: "postman", name: it.Name, folder: folder, method: r.Method, pathVars: map[string]string{}}

	// URL: bare string or structured object.
	var s string
	var obj postmanURL
	switch {
	case len(r.URL) == 0:
		return cr, false
	case json.Unmarshal(r.URL, &s) == nil:
		cr.rawURL = rv.resolve(s)
	case json.Unmarshal(r.URL, &obj) == nil:
		cr.rawURL = rv.resolve(obj.Raw)
		for _, q := range obj.Query {
			if !q.Disabled && strings.TrimSpace(q.Key) != "" {
				cr.query = append(cr.query, kv{rv.resolve(q.Key), rv.resolve(q.Value)})
			}
		}
		for _, v := range obj.Variable {
			if strings.TrimSpace(v.Key) != "" {
				cr.pathVars[v.Key] = rv.resolve(v.Value)
			}
		}
	}
	if strings.TrimSpace(cr.rawURL) == "" {
		return cr, false
	}

	// Headers: v2.1 array or v2.0 "Key: value\n" string.
	var hdrs []postmanKV
	if json.Unmarshal(r.Header, &hdrs) != nil {
		var hs string
		if json.Unmarshal(r.Header, &hs) == nil {
			for _, line := range strings.Split(hs, "\n") {
				if k, v, ok := strings.Cut(line, ":"); ok {
					hdrs = append(hdrs, postmanKV{Key: strings.TrimSpace(k), Value: strings.TrimSpace(v)})
				}
			}
		}
	}
	for _, h := range hdrs {
		if !h.Disabled && strings.TrimSpace(h.Key) != "" {
			cr.headers = append(cr.headers, kv{h.Key, rv.resolve(h.Value)})
		}
	}

	// Auth: request-level, else inherited (folder/collection).
	ra := r.Auth
	if ra == nil {
		ra = inherited
	}
	if ra != nil && strings.EqualFold(ra.Type, "apikey") && strings.EqualFold(strings.TrimSpace(authKVGet(ra.APIKey, "in")), "query") {
		if name := strings.TrimSpace(rv.resolve(authKVGet(ra.APIKey, "key"))); name != "" {
			cr.query = append(cr.query, kv{name, rv.resolve(authKVGet(ra.APIKey, "value"))})
		}
	} else if name, val := postmanAuthHeaderR(ra, rv); name != "" {
		cr.authHdrs = append(cr.authHdrs, kv{name, val})
	}

	// Body.
	if b := r.Body; b != nil {
		switch strings.ToLower(b.Mode) {
		case "raw", "":
			cr.body = rv.resolve(b.Raw)
			switch strings.ToLower(b.Options.Raw.Language) {
			case "json":
				cr.bodyMode = "json"
			case "xml":
				cr.bodyMode = "xml"
			default:
				t := strings.TrimSpace(cr.body)
				switch {
				case strings.HasPrefix(t, "{") || strings.HasPrefix(t, "["):
					cr.bodyMode = "json"
				case strings.HasPrefix(t, "<"):
					cr.bodyMode = "xml"
				case t != "":
					cr.bodyMode = "text"
				}
			}
		case "urlencoded":
			cr.bodyMode = "form"
			var parts []string
			for _, f := range b.URLEncoded {
				if f.Disabled || strings.TrimSpace(f.Key) == "" {
					continue
				}
				k := rv.resolve(f.Key)
				cr.fields = append(cr.fields, k)
				parts = append(parts, k+"="+rv.resolve(f.Value))
			}
			cr.body = strings.Join(parts, "&")
		case "formdata":
			cr.bodyMode = "multipart"
			for _, f := range b.FormData {
				if f.Disabled || strings.TrimSpace(f.Key) == "" {
					continue
				}
				cr.fields = append(cr.fields, rv.resolve(f.Key))
			}
		case "graphql":
			if b.GraphQL != nil {
				cr.bodyMode = "graphql"
				payload := map[string]any{"query": rv.resolve(b.GraphQL.Query)}
				if v := strings.TrimSpace(rv.resolve(b.GraphQL.Variables)); v != "" {
					var vars any
					if json.Unmarshal([]byte(v), &vars) == nil {
						payload["variables"] = vars
					}
				}
				enc, _ := json.Marshal(payload)
				cr.body = string(enc)
			}
		}
	}
	return cr, true
}

// postmanAuthHeader renders a Postman auth block as a single HTTP header,
// resolving {{variables}} from vars. Returns ("","") for empty, query-param,
// or unsupported auth.
func postmanAuthHeader(auth *postmanAuth, vars map[string]string) (string, string) {
	return postmanAuthHeaderR(auth, newResolver(vars))
}

func postmanAuthHeaderR(auth *postmanAuth, rv *resolver) (string, string) {
	if auth == nil {
		return "", ""
	}
	switch strings.ToLower(strings.TrimSpace(auth.Type)) {
	case "bearer":
		tok := strings.TrimSpace(rv.resolve(authKVGet(auth.Bearer, "token")))
		if tok == "" {
			return "", ""
		}
		return "Authorization", "Bearer " + tok
	case "oauth2":
		tok := strings.TrimSpace(rv.resolve(authKVGet(auth.OAuth2, "accessToken")))
		if tok == "" {
			return "", ""
		}
		prefix := strings.TrimSpace(authKVGet(auth.OAuth2, "headerPrefix"))
		if prefix == "" {
			prefix = "Bearer"
		}
		return "Authorization", prefix + " " + tok
	case "basic":
		user := rv.resolve(authKVGet(auth.Basic, "username"))
		pass := rv.resolve(authKVGet(auth.Basic, "password"))
		if strings.TrimSpace(user) == "" && strings.TrimSpace(pass) == "" {
			return "", ""
		}
		return "Authorization", "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	case "apikey":
		val := strings.TrimSpace(rv.resolve(authKVGet(auth.APIKey, "value")))
		if val == "" {
			return "", ""
		}
		if strings.EqualFold(strings.TrimSpace(authKVGet(auth.APIKey, "in")), "query") {
			return "", "" // query-param keys aren't request headers
		}
		name := strings.TrimSpace(rv.resolve(authKVGet(auth.APIKey, "key")))
		if name == "" {
			name = "X-Api-Key" // Postman's default when the key name is blank
		}
		return name, val
	}
	return "", ""
}

// resolvePostmanVars replaces {{variable}} placeholders using vars. Unknown
// placeholders are left intact.
func resolvePostmanVars(s string, vars map[string]string) string {
	return newResolver(vars).resolve(s)
}

// postmanEnv is a Postman environment or globals export.
type postmanEnv struct {
	Name   string       `json:"name"`
	Scope  string       `json:"_postman_variable_scope"`
	Values []postmanVar `json:"values"`
}

// readPostmanEnv parses an environment/globals export. ok is false when the
// bytes are not such a file (safe to try on every uploaded file).
func readPostmanEnv(data []byte) (env postmanEnv, ok bool) {
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "{") {
		return env, false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(data, &probe) != nil {
		return env, false
	}
	// An environment/globals file has "values" but is neither a collection
	// ("item") nor an OpenAPI spec ("paths"/"swagger"/"openapi").
	if !hasKey(probe, "values") || hasKey(probe, "item") ||
		hasKey(probe, "paths") || hasKey(probe, "swagger") || hasKey(probe, "openapi") {
		return env, false
	}
	if json.Unmarshal(data, &env) != nil {
		return env, false
	}
	return env, true
}

// parsePostmanEnv extracts active variables from an environment/globals file.
func parsePostmanEnv(data []byte) map[string]string {
	env, ok := readPostmanEnv(data)
	if !ok {
		return nil
	}
	out := varsMap(env.Values)
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectPostmanCtx scans a directory for environment/globals exports and
// picks the environment per opts (by name; the only one when there is one;
// otherwise all merged, sorted by name, so behavior stays deterministic).
func collectPostmanCtx(dir string, opts Options) *postmanCtx {
	pc := &postmanCtx{opts: opts, globals: map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return pc
	}
	envs := map[string]map[string]string{}
	for _, e := range entries {
		if e.IsDir() || e.Name() == SelectionFile {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil || len(data) == 0 {
			continue
		}
		env, ok := readPostmanEnv(data)
		if !ok {
			continue
		}
		vals := varsMap(env.Values)
		if strings.EqualFold(env.Scope, "globals") {
			for k, v := range vals {
				pc.globals[k] = v
			}
			continue
		}
		name := strings.TrimSpace(env.Name)
		if name == "" {
			name = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		}
		envs[name] = vals
	}
	names := make([]string, 0, len(envs))
	for n := range envs {
		names = append(names, n)
	}
	sort.Strings(names)
	pc.envs = names
	pc.env = selectEnv(envs, names, opts.Env)
	return pc
}

// selectEnv picks env vars by name (case-insensitive). With no selection it
// uses the first environment by name, so a multi-environment upload never
// silently mixes values from several environments.
func selectEnv(envs map[string]map[string]string, names []string, want string) map[string]string {
	if name := selectedEnvName(names, want); name != "" {
		return envs[name]
	}
	return nil
}

// selectedEnvName resolves the environment actually used: the requested one
// (case-insensitive), else the first by name; "" when there is none or the
// requested name does not exist.
func selectedEnvName(names []string, want string) string {
	if want = strings.TrimSpace(want); want != "" {
		for _, n := range names {
			if strings.EqualFold(n, want) {
				return n
			}
		}
		return ""
	}
	if len(names) > 0 {
		return names[0]
	}
	return ""
}
