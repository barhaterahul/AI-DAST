package attacksurface

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// ── Bruno collections ────────────────────────────────────────────────────────
//
// Bruno stores a collection as a directory tree:
//
//	bruno.json                 collection config (marks the root)
//	collection.bru             collection-level headers / auth / vars / scripts
//	environments/<name>.bru    vars { } and vars:secret [ ]
//	<folder>/folder.bru        folder-level headers / auth / vars
//	<folder>/<request>.bru     one request per file
//
// It is accepted as an uploaded directory, a .zip of that directory, single
// .bru files, or Bruno's JSON export. Scripts (script:pre-request,
// script:post-response, tests) are counted and reported but NEVER executed.

const (
	maxBrunoFiles     = 2000
	maxBrunoFileBytes = 1 << 20
	maxBrunoZipBytes  = 50 << 20
)

// bruBlock is one top-level block of a .bru file.
type bruBlock struct {
	name string
	dict []bruKV
	text string
	list []string
}

type bruKV struct {
	k, v    string
	enabled bool
}

func (b *bruBlock) get(key string) string {
	for _, kv := range b.dict {
		if kv.enabled && strings.EqualFold(kv.k, key) {
			return kv.v
		}
	}
	return ""
}

func (b *bruBlock) enabledMap() map[string]string {
	out := map[string]string{}
	for _, kv := range b.dict {
		if kv.enabled && kv.k != "" {
			out[kv.k] = kv.v
		}
	}
	return out
}

type bruFile struct{ blocks []*bruBlock }

func (f *bruFile) block(names ...string) *bruBlock {
	for _, n := range names {
		for _, b := range f.blocks {
			if b.name == n {
				return b
			}
		}
	}
	return nil
}

// isBruTextBlock reports blocks whose body is verbatim text, not key: value.
func isBruTextBlock(name string) bool {
	switch name {
	case "body:form-urlencoded", "body:multipart-form", "body:file":
		return false
	case "tests", "docs":
		return true
	}
	return strings.HasPrefix(name, "body") || strings.HasPrefix(name, "script:")
}

// parseBru parses .bru text. The format places each block opener
// ("name {" / "name [") at column 0, indents contents by two spaces and
// closes with "}" / "]" at column 0.
func parseBru(text string) *bruFile {
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(text, "\n")
	f := &bruFile{}
	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t")
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		var opener byte
		switch {
		case strings.HasSuffix(line, "{"):
			opener = '{'
		case strings.HasSuffix(line, "["):
			opener = '['
		default:
			continue
		}
		name := strings.TrimSpace(line[:len(line)-1])
		if name == "" || strings.ContainsAny(name, " \t") {
			continue
		}
		closer := "}"
		if opener == '[' {
			closer = "]"
		}
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimRight(lines[j], " \t") == closer {
				break
			}
			body = append(body, lines[j])
		}
		i = j
		b := &bruBlock{name: name}
		switch {
		case opener == '[':
			for _, l := range body {
				l = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(l), ","))
				if l != "" && !strings.HasPrefix(l, "~") {
					b.list = append(b.list, l)
				}
			}
		case isBruTextBlock(name):
			for k, l := range body {
				body[k] = strings.TrimPrefix(l, "  ")
			}
			b.text = strings.TrimSpace(strings.Join(body, "\n"))
		default:
			for _, l := range body {
				t := strings.TrimSpace(l)
				if t == "" {
					continue
				}
				kv := bruKV{enabled: true}
				if strings.HasPrefix(t, "~") {
					kv.enabled = false
					t = strings.TrimSpace(t[1:])
				}
				k, v, ok := strings.Cut(t, ":")
				if !ok {
					continue
				}
				kv.k = strings.Trim(strings.TrimSpace(k), `"'`)
				kv.v = strings.TrimSpace(v)
				b.dict = append(b.dict, kv)
			}
		}
		f.blocks = append(f.blocks, b)
	}
	return f
}

// bruSettings are headers/auth/vars shared by collection and folders.
type bruSettings struct {
	headers  []kv
	authMode string // "" or "inherit" means inherit
	auth     map[string]string
	vars     map[string]string
	scripts  int
}

var bruMethods = []string{"get", "post", "put", "patch", "delete", "options", "head", "connect", "trace"}

func bruAuthFrom(f *bruFile, mode string) map[string]string {
	if mode == "" {
		return nil
	}
	if b := f.block("auth:" + mode); b != nil {
		m := b.enabledMap()
		m["__mode"] = mode
		return m
	}
	return map[string]string{"__mode": mode}
}

func bruScripts(f *bruFile) int {
	n := 0
	for _, b := range f.blocks {
		if (strings.HasPrefix(b.name, "script:") || b.name == "tests") && strings.TrimSpace(b.text) != "" {
			n++
		}
	}
	return n
}

func settingsFrom(f *bruFile) bruSettings {
	s := bruSettings{vars: map[string]string{}}
	if f == nil {
		return s
	}
	if h := f.block("headers"); h != nil {
		for _, e := range h.dict {
			if e.enabled {
				s.headers = append(s.headers, kv{e.k, e.v})
			}
		}
	}
	if a := f.block("auth"); a != nil {
		s.authMode = strings.ToLower(a.get("mode"))
		s.auth = bruAuthFrom(f, s.authMode)
	}
	if v := f.block("vars:pre-request", "vars"); v != nil {
		s.vars = v.enabledMap()
	}
	s.scripts = bruScripts(f)
	return s
}

// bruReq is a request decoded from .bru (or Bruno JSON) before resolution.
type bruReq struct {
	name, folder, method, url string
	query                     []kv
	pathParams                map[string]string
	headers                   []kv
	bodyMode                  string // bruno mode: json, text, xml, formUrlEncoded, multipartForm, graphql, none
	bodies                    map[string]string
	form, multipart           []kv
	authMode                  string
	auth                      map[string]string
	vars                      map[string]string
	scripts                   int
}

func bruReqFrom(f *bruFile, fallbackName, folder string) (bruReq, bool) {
	r := bruReq{folder: folder, pathParams: map[string]string{}, bodies: map[string]string{}, vars: map[string]string{}}
	if m := f.block("meta"); m != nil {
		r.name = m.get("name")
	}
	if r.name == "" {
		r.name = fallbackName
	}
	for _, mth := range bruMethods {
		if b := f.block(mth); b != nil {
			r.method = strings.ToUpper(mth)
			r.url = b.get("url")
			r.bodyMode = b.get("body")
			r.authMode = strings.ToLower(b.get("auth"))
			break
		}
	}
	if r.method == "" || strings.TrimSpace(r.url) == "" {
		return r, false
	}
	if q := f.block("params:query", "query"); q != nil {
		for _, e := range q.dict {
			if e.enabled {
				r.query = append(r.query, kv{e.k, e.v})
			}
		}
	}
	if p := f.block("params:path"); p != nil {
		r.pathParams = p.enabledMap()
	}
	if h := f.block("headers"); h != nil {
		for _, e := range h.dict {
			if e.enabled {
				r.headers = append(r.headers, kv{e.k, e.v})
			}
		}
	}
	for _, b := range f.blocks {
		switch {
		case b.name == "body:form-urlencoded":
			for _, e := range b.dict {
				if e.enabled {
					r.form = append(r.form, kv{e.k, e.v})
				}
			}
		case b.name == "body:multipart-form":
			for _, e := range b.dict {
				if e.enabled {
					r.multipart = append(r.multipart, kv{e.k, e.v})
				}
			}
		case strings.HasPrefix(b.name, "body:"):
			r.bodies[strings.TrimPrefix(b.name, "body:")] = b.text
		}
	}
	r.auth = bruAuthFrom(f, r.authMode)
	if v := f.block("vars:pre-request"); v != nil {
		r.vars = v.enabledMap()
	}
	r.scripts = bruScripts(f)
	return r, true
}

// brunoTree is a whole collection ready for resolution.
type brunoTree struct {
	collection bruSettings
	folders    map[string]bruSettings // folder path -> settings
	envs       map[string]map[string]string
	secrets    map[string][]string // env -> secret var names (values not exported)
	reqs       []bruReq
}

func (t *brunoTree) result(opts Options) *Result {
	names := make([]string, 0, len(t.envs))
	for n := range t.envs {
		names = append(names, n)
	}
	sort.Strings(names)
	env := selectEnv(t.envs, names, opts.Env)
	root := newResolver(opts.Vars, env, t.collection.vars)
	res := &Result{AuthHeaders: map[string]string{}, Environments: names, Environment: selectedEnvName(names, opts.Env)}
	scripts := t.collection.scripts
	for _, f := range t.folders {
		scripts += f.scripts
	}

	var out []collReq
	for _, r := range t.reqs {
		scripts += r.scripts
		// Folder chain from outermost to innermost.
		var chain []bruSettings
		if r.folder != "" {
			parts := strings.Split(r.folder, "/")
			for i := range parts {
				if st, ok := t.folders[strings.Join(parts[:i+1], "/")]; ok {
					chain = append(chain, st)
				}
			}
		}
		scopes := []map[string]string{r.vars}
		for i := len(chain) - 1; i >= 0; i-- {
			scopes = append(scopes, chain[i].vars)
		}
		rv := root.with(scopes...)
		// opts.Vars must still win over request/folder vars.
		rv = rv.with(opts.Vars)

		cr := collReq{source: "bruno", name: r.name, folder: r.folder, method: r.method, rawURL: rv.resolve(r.url), pathVars: map[string]string{}}
		for k, v := range r.pathParams {
			cr.pathVars[k] = rv.resolve(v)
		}
		for _, q := range r.query {
			cr.query = append(cr.query, kv{rv.resolve(q.k), rv.resolve(q.v)})
		}
		// Headers: collection < folders < request (later wins by name).
		hdr := map[string]kv{}
		order := []string{}
		add := func(list []kv) {
			for _, h := range list {
				key := strings.ToLower(h.k)
				if _, ok := hdr[key]; !ok {
					order = append(order, key)
				}
				hdr[key] = kv{h.k, rv.resolve(h.v)}
			}
		}
		add(t.collection.headers)
		for _, f := range chain {
			add(f.headers)
		}
		add(r.headers)
		for _, k := range order {
			cr.headers = append(cr.headers, hdr[k])
		}
		// Auth: request, else nearest folder, else collection.
		auth := r.auth
		if r.authMode == "" || r.authMode == "inherit" {
			auth = nil
			for i := len(chain) - 1; i >= 0 && auth == nil; i-- {
				if m := chain[i].authMode; m != "" && m != "inherit" {
					auth = chain[i].auth
				}
			}
			if auth == nil && t.collection.authMode != "" && t.collection.authMode != "inherit" {
				auth = t.collection.auth
			}
		}
		applyBrunoAuth(&cr, auth, rv)
		applyBrunoBody(&cr, r, rv)
		out = append(out, cr)
	}
	res = collectionResult("bruno", out, res, opts)
	addScriptNote(res, scripts)
	res.MissingVars = root.missingList()
	if sec := t.secrets[selectedEnvName(names, opts.Env)]; len(sec) > 0 {
		res.Notes = append(res.Notes, "Bruno secret variables have no exported value and must be supplied: "+strings.Join(sec, ", "))
	}
	return res
}

func applyBrunoAuth(cr *collReq, auth map[string]string, rv *resolver) {
	if auth == nil {
		return
	}
	switch auth["__mode"] {
	case "bearer":
		if tok := strings.TrimSpace(rv.resolve(auth["token"])); tok != "" {
			cr.authHdrs = append(cr.authHdrs, kv{"Authorization", "Bearer " + tok})
		}
	case "basic":
		user, pass := rv.resolve(auth["username"]), rv.resolve(auth["password"])
		if strings.TrimSpace(user+pass) != "" {
			cr.authHdrs = append(cr.authHdrs, kv{"Authorization", "Basic " + basicB64(user, pass)})
		}
	case "apikey":
		key, val := strings.TrimSpace(rv.resolve(auth["key"])), rv.resolve(auth["value"])
		if key == "" || strings.TrimSpace(val) == "" {
			return
		}
		if strings.HasPrefix(strings.ToLower(auth["placement"]), "query") {
			cr.query = append(cr.query, kv{key, val})
		} else {
			cr.authHdrs = append(cr.authHdrs, kv{key, val})
		}
	case "oauth2":
		if tok := strings.TrimSpace(rv.resolve(firstNonEmpty(auth["access_token"], auth["accessToken"], auth["token"]))); tok != "" && !strings.Contains(tok, "{{") {
			cr.authHdrs = append(cr.authHdrs, kv{"Authorization", "Bearer " + tok})
		}
	}
}

func applyBrunoBody(cr *collReq, r bruReq, rv *resolver) {
	switch strings.ToLower(r.bodyMode) {
	case "json":
		cr.bodyMode, cr.body = "json", rv.resolve(r.bodies["json"])
	case "xml":
		cr.bodyMode, cr.body = "xml", rv.resolve(r.bodies["xml"])
	case "text":
		cr.bodyMode, cr.body = "text", rv.resolve(r.bodies["text"])
	case "formurlencoded", "form-urlencoded":
		cr.bodyMode = "form"
		var parts []string
		for _, f := range r.form {
			k := rv.resolve(f.k)
			cr.fields = append(cr.fields, k)
			parts = append(parts, k+"="+rv.resolve(f.v))
		}
		cr.body = strings.Join(parts, "&")
	case "multipartform", "multipart-form":
		cr.bodyMode = "multipart"
		for _, f := range r.multipart {
			cr.fields = append(cr.fields, rv.resolve(f.k))
		}
	case "graphql":
		cr.bodyMode = "graphql"
		payload := map[string]any{"query": rv.resolve(r.bodies["graphql"])}
		if v := strings.TrimSpace(rv.resolve(r.bodies["graphql:vars"])); v != "" {
			var vars any
			if json.Unmarshal([]byte(v), &vars) == nil {
				payload["variables"] = vars
			}
		}
		b, _ := json.Marshal(payload)
		cr.body = string(b)
	}
}

func basicB64(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ── loading a .bru tree from any fs.FS (directory or zip) ───────────────────

// isBrunoDir reports whether dir (non-recursively) holds a Bruno collection.
func isBrunoDir(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || found {
			return fs.SkipAll
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() && rel != "." && strings.Count(rel, string(filepath.Separator)) >= 2 {
			return fs.SkipDir
		}
		n := strings.ToLower(d.Name())
		if !d.IsDir() && (n == "bruno.json" || strings.HasSuffix(n, ".bru")) {
			found = true
		}
		return nil
	})
	return found
}

func parseBrunoFS(fsys fs.FS, opts Options) *Result {
	type entry struct {
		p    string
		data []byte
	}
	var files []entry
	root := ""
	rootDepth := -1
	total := 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "__MACOSX":
				return fs.SkipDir
			}
			return nil
		}
		if len(files) >= maxBrunoFiles {
			return fs.SkipAll
		}
		name := strings.ToLower(d.Name())
		if name == "bruno.json" {
			if depth := strings.Count(p, "/"); rootDepth < 0 || depth < rootDepth {
				rootDepth, root = depth, path.Dir(p)
			}
			return nil
		}
		if !strings.HasSuffix(name, ".bru") {
			return nil
		}
		fh, err := fsys.Open(p)
		if err != nil {
			return nil
		}
		data, _ := io.ReadAll(io.LimitReader(fh, maxBrunoFileBytes))
		_ = fh.Close()
		total += len(data)
		if total > maxBrunoZipBytes {
			return fs.SkipAll
		}
		files = append(files, entry{p, data})
		return nil
	})
	if len(files) == 0 {
		return nil
	}
	if root == "" {
		root = "."
	}
	rel := func(p string) (string, bool) {
		if root == "." {
			return p, true
		}
		if strings.HasPrefix(p, root+"/") {
			return strings.TrimPrefix(p, root+"/"), true
		}
		return "", false
	}
	t := &brunoTree{folders: map[string]bruSettings{}, envs: map[string]map[string]string{}, secrets: map[string][]string{}}
	for _, f := range files {
		r, ok := rel(f.p)
		if !ok {
			continue
		}
		dir, base := path.Dir(r), path.Base(r)
		if dir == "." {
			dir = ""
		}
		bf := parseBru(string(f.data))
		switch {
		case dir == "environments":
			name := strings.TrimSuffix(base, path.Ext(base))
			vars := map[string]string{}
			if v := bf.block("vars"); v != nil {
				vars = v.enabledMap()
			}
			t.envs[name] = vars
			if s := bf.block("vars:secret"); s != nil {
				t.secrets[name] = s.list
			}
		case dir == "" && strings.EqualFold(base, "collection.bru"):
			t.collection = settingsFrom(bf)
		case strings.EqualFold(base, "folder.bru"):
			t.folders[dir] = settingsFrom(bf)
		default:
			if req, ok := bruReqFrom(bf, strings.TrimSuffix(base, path.Ext(base)), dir); ok {
				t.reqs = append(t.reqs, req)
			}
		}
	}
	if len(t.reqs) == 0 && len(t.envs) == 0 {
		return nil
	}
	return t.result(opts)
}

// parseBrunoZip parses a zipped Bruno collection; nil when the archive holds
// no .bru files (so APKs fall through). Entries are read in memory with
// count/size caps — nothing is extracted to disk.
func parseBrunoZip(data []byte, opts Options) *Result {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	hasBru := false
	var total uint64
	for _, f := range zr.File {
		total += f.UncompressedSize64
		if strings.HasSuffix(strings.ToLower(f.Name), ".bru") {
			hasBru = true
		}
	}
	if !hasBru || len(zr.File) > maxBrunoFiles*2 || total > maxBrunoZipBytes {
		return nil
	}
	return parseBrunoFS(zr, opts)
}

// parseBrunoSingle parses one loose .bru request file.
func parseBrunoSingle(data []byte, name string, opts Options) *Result {
	bf := parseBru(string(data))
	req, ok := bruReqFrom(bf, strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)), "")
	if !ok {
		return nil
	}
	t := &brunoTree{folders: map[string]bruSettings{}, envs: map[string]map[string]string{}, reqs: []bruReq{req}}
	return t.result(opts)
}

// ── Bruno JSON export ───────────────────────────────────────────────────────

func isBrunoJSONExport(probe map[string]json.RawMessage) bool {
	return hasKey(probe, "items") && (hasKey(probe, "brunoConfig") || (hasKey(probe, "version") && hasKey(probe, "environments")))
}

type brunoJSONVar struct {
	Name    string `json:"name"`
	Value   any    `json:"value"`
	Enabled *bool  `json:"enabled"`
	Secret  bool   `json:"secret"`
	Type    string `json:"type"` // params: query | path
}

func (v brunoJSONVar) on() bool { return v.Enabled == nil || *v.Enabled }

func (v brunoJSONVar) str() string {
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

type brunoJSONAuth struct {
	Mode   string            `json:"mode"`
	Bearer map[string]string `json:"bearer"`
	Basic  map[string]string `json:"basic"`
	APIKey map[string]string `json:"apikey"`
	OAuth2 map[string]any    `json:"oauth2"`
}

func (a *brunoJSONAuth) toMap() map[string]string {
	if a == nil || a.Mode == "" {
		return nil
	}
	m := map[string]string{"__mode": strings.ToLower(a.Mode)}
	var src map[string]string
	switch m["__mode"] {
	case "bearer":
		src = a.Bearer
	case "basic":
		src = a.Basic
	case "apikey":
		src = a.APIKey
	case "oauth2":
		for k, v := range a.OAuth2 {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
	}
	for k, v := range src {
		m[k] = v
	}
	return m
}

type brunoJSONScript struct {
	Req string `json:"req"`
	Res string `json:"res"`
}

func (s brunoJSONScript) count() int {
	n := 0
	if strings.TrimSpace(s.Req) != "" {
		n++
	}
	if strings.TrimSpace(s.Res) != "" {
		n++
	}
	return n
}

type brunoJSONRequest struct {
	URL     string         `json:"url"`
	Method  string         `json:"method"`
	Headers []brunoJSONVar `json:"headers"`
	Params  []brunoJSONVar `json:"params"`
	Body    struct {
		Mode           string         `json:"mode"`
		JSON           string         `json:"json"`
		Text           string         `json:"text"`
		XML            string         `json:"xml"`
		FormURLEncoded []brunoJSONVar `json:"formUrlEncoded"`
		MultipartForm  []brunoJSONVar `json:"multipartForm"`
		GraphQL        struct {
			Query     string `json:"query"`
			Variables string `json:"variables"`
		} `json:"graphql"`
	} `json:"body"`
	Auth   *brunoJSONAuth  `json:"auth"`
	Script brunoJSONScript `json:"script"`
	Vars   struct {
		Req []brunoJSONVar `json:"req"`
	} `json:"vars"`
	Tests string `json:"tests"`
}

type brunoJSONItem struct {
	Type    string            `json:"type"` // http-request | graphql-request | folder
	Name    string            `json:"name"`
	Request *brunoJSONRequest `json:"request"`
	Root    *struct {
		Request *brunoJSONRequest `json:"request"`
	} `json:"root"`
	Items []brunoJSONItem `json:"items"`
}

type brunoJSONExport struct {
	Items        []brunoJSONItem `json:"items"`
	Environments []struct {
		Name      string         `json:"name"`
		Variables []brunoJSONVar `json:"variables"`
	} `json:"environments"`
	Root *struct {
		Request *brunoJSONRequest `json:"request"`
	} `json:"root"`
}

func settingsFromJSON(r *brunoJSONRequest) bruSettings {
	s := bruSettings{vars: map[string]string{}}
	if r == nil {
		return s
	}
	for _, h := range r.Headers {
		if h.on() {
			s.headers = append(s.headers, kv{h.Name, h.str()})
		}
	}
	if r.Auth != nil {
		s.authMode = strings.ToLower(r.Auth.Mode)
		s.auth = r.Auth.toMap()
	}
	for _, v := range r.Vars.Req {
		if v.on() {
			s.vars[v.Name] = v.str()
		}
	}
	s.scripts = r.Script.count()
	if strings.TrimSpace(r.Tests) != "" {
		s.scripts++
	}
	return s
}

func parseBrunoJSON(data []byte, opts Options) *Result {
	var exp brunoJSONExport
	if json.Unmarshal(data, &exp) != nil {
		return nil
	}
	t := &brunoTree{folders: map[string]bruSettings{}, envs: map[string]map[string]string{}, secrets: map[string][]string{}}
	if exp.Root != nil {
		t.collection = settingsFromJSON(exp.Root.Request)
	}
	for _, e := range exp.Environments {
		vars := map[string]string{}
		for _, v := range e.Variables {
			if !v.on() {
				continue
			}
			if v.Secret && v.str() == "" {
				t.secrets[e.Name] = append(t.secrets[e.Name], v.Name)
				continue
			}
			vars[v.Name] = v.str()
		}
		t.envs[e.Name] = vars
	}
	var walk func(items []brunoJSONItem, folder string)
	walk = func(items []brunoJSONItem, folder string) {
		for _, it := range items {
			if it.Type == "folder" || len(it.Items) > 0 {
				sub := it.Name
				if folder != "" {
					sub = folder + "/" + it.Name
				}
				if it.Root != nil {
					t.folders[sub] = settingsFromJSON(it.Root.Request)
				}
				walk(it.Items, sub)
				continue
			}
			r := it.Request
			if r == nil || strings.TrimSpace(r.URL) == "" {
				continue
			}
			req := bruReq{name: it.Name, folder: folder, method: strings.ToUpper(r.Method), url: r.URL,
				pathParams: map[string]string{}, bodies: map[string]string{}, vars: map[string]string{}}
			for _, p := range r.Params {
				if !p.on() {
					continue
				}
				if p.Type == "path" {
					req.pathParams[p.Name] = p.str()
				} else {
					req.query = append(req.query, kv{p.Name, p.str()})
				}
			}
			for _, h := range r.Headers {
				if h.on() {
					req.headers = append(req.headers, kv{h.Name, h.str()})
				}
			}
			req.bodyMode = r.Body.Mode
			req.bodies["json"], req.bodies["text"], req.bodies["xml"] = r.Body.JSON, r.Body.Text, r.Body.XML
			req.bodies["graphql"], req.bodies["graphql:vars"] = r.Body.GraphQL.Query, r.Body.GraphQL.Variables
			for _, f := range r.Body.FormURLEncoded {
				if f.on() {
					req.form = append(req.form, kv{f.Name, f.str()})
				}
			}
			for _, f := range r.Body.MultipartForm {
				if f.on() {
					req.multipart = append(req.multipart, kv{f.Name, f.str()})
				}
			}
			if r.Auth != nil {
				req.authMode = strings.ToLower(r.Auth.Mode)
				req.auth = r.Auth.toMap()
			}
			for _, v := range r.Vars.Req {
				if v.on() {
					req.vars[v.Name] = v.str()
				}
			}
			req.scripts = r.Script.count()
			if strings.TrimSpace(r.Tests) != "" {
				req.scripts++
			}
			t.reqs = append(t.reqs, req)
		}
	}
	walk(exp.Items, "")
	if len(t.reqs) == 0 {
		return nil
	}
	return t.result(opts)
}
