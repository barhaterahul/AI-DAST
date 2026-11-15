package attacksurface

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func endpointByName(res *Result, name string) *Endpoint {
	for i := range res.Endpoints {
		if res.Endpoints[i].Name == name {
			return &res.Endpoints[i]
		}
	}
	return nil
}

const postmanFull = `{
  "info": {"name": "Shop API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "variable": [{"key": "base", "value": "https://api.shop.test"}],
  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{token}}"}]},
  "event": [{"listen": "prerequest", "script": {"exec": ["pm.environment.set('x', 1)"]}}],
  "item": [
    {"name": "Accounts", "item": [
      {"name": "Get account", "request": {
        "method": "GET",
        "url": {"raw": "{{base}}/accounts/:accountId?expand=owner",
                "query": [{"key": "expand", "value": "owner"}, {"key": "debug", "value": "1", "disabled": true}],
                "variable": [{"key": "accountId", "value": "1001"}]},
        "header": [{"key": "X-Tenant", "value": "{{tenant}}"}, {"key": "Accept", "value": "application/json"},
                   {"key": "X-Off", "value": "x", "disabled": true}]
      }},
      {"name": "Update account", "request": {
        "method": "PATCH",
        "url": "{{base}}/accounts/1001",
        "body": {"mode": "raw", "raw": "{\"email\":\"a@b.c\",\"profile\":{\"role\":\"user\"}}", "options": {"raw": {"language": "json"}}}
      }}
    ]},
    {"name": "Login form", "request": {
      "method": "POST", "url": "{{base}}/login",
      "auth": {"type": "noauth"},
      "body": {"mode": "urlencoded", "urlencoded": [{"key": "username", "value": "alice"}, {"key": "password", "value": "{{pw}}"}]}
    }},
    {"name": "Upload", "request": {
      "method": "POST", "url": "{{base}}/files",
      "body": {"mode": "formdata", "formdata": [{"key": "file", "type": "file"}, {"key": "label", "value": "x"}]}
    }},
    {"name": "GQL", "request": {
      "method": "POST", "url": "{{base}}/graphql",
      "auth": {"type": "apikey", "apikey": [{"key": "key", "value": "api_key"}, {"key": "value", "value": "k-123456"}, {"key": "in", "value": "query"}]},
      "body": {"mode": "graphql", "graphql": {"query": "query($id: ID!){ user(id:$id){ id } }", "variables": "{\"id\": \"7\"}"}}
    }},
    {"name": "Unresolved", "request": {"method": "GET", "url": "{{otherHost}}/x/{{$guid}}"}}
  ]
}`

func TestPostmanFullCollection(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "shop.postman_collection.json"), postmanFull)
	mustWrite(t, filepath.Join(dir, "dev.json"), `{"name":"Dev","values":[{"key":"token","value":"dev-token-1"},{"key":"tenant","value":"t-dev"}]}`)
	mustWrite(t, filepath.Join(dir, "prod.json"), `{"name":"Prod","values":[{"key":"token","value":"prod-token-2"},{"key":"tenant","value":"t-prod"}]}`)
	if err := WriteSelection(dir, Options{Env: "prod", Vars: map[string]string{"pw": "op-pass"}}); err != nil {
		t.Fatal(err)
	}
	res, err := LoadFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Environments, ",") != "Dev,Prod" {
		t.Fatalf("environments = %v", res.Environments)
	}
	if res.AuthHeaders["Authorization"] != "Bearer prod-token-2" {
		t.Fatalf("selected env not applied: %v", res.AuthHeaders)
	}
	get := endpointByName(res, "Get account")
	if get == nil || get.Path != "https://api.shop.test/accounts/1001" || get.Folder != "Accounts" {
		t.Fatalf("get account = %+v", get)
	}
	if get.ParamLocations["accountId"] != "path" || get.ParamLocations["expand"] != "query" {
		t.Fatalf("param locations = %v", get.ParamLocations)
	}
	if _, ok := get.ParamLocations["debug"]; ok {
		t.Fatal("disabled query param must be ignored")
	}
	if get.Headers["X-Tenant"] != "t-prod" || get.Headers["Accept"] != "application/json" || get.Headers["X-Off"] != "" {
		t.Fatalf("headers = %v", get.Headers)
	}
	upd := endpointByName(res, "Update account")
	if upd.BodyMode != "json" || upd.ContentType != "application/json" || upd.ParamLocations["profile.role"] != "body" {
		t.Fatalf("json body params = %+v", upd)
	}
	login := endpointByName(res, "Login form")
	if login.BodyMode != "form" || login.ParamLocations["password"] != "body" || !strings.Contains(login.Body, "password=op-pass") {
		t.Fatalf("form body = %+v", login)
	}
	up := endpointByName(res, "Upload")
	if up.BodyMode != "multipart" || up.ParamLocations["file"] != "body" {
		t.Fatalf("multipart = %+v", up)
	}
	gql := endpointByName(res, "GQL")
	if gql.BodyMode != "graphql" || gql.ParamLocations["variables.id"] != "" && gql.ParamLocations["query"] != "body" || gql.ParamLocations["api_key"] != "query" {
		t.Fatalf("graphql = %+v", gql)
	}
	if strings.Join(res.MissingVars, ",") != "otherHost" {
		t.Fatalf("missing vars = %v ($guid must resolve)", res.MissingVars)
	}
	if res.ScriptsSkipped != 1 || len(res.BaseURLs) != 1 || res.BaseURLs[0] != "https://api.shop.test" {
		t.Fatalf("scripts=%d base=%v", res.ScriptsSkipped, res.BaseURLs)
	}
	// Exclusion by request ID.
	if err := WriteSelection(dir, Options{Env: "prod", Exclude: []string{get.ID}}); err != nil {
		t.Fatal(err)
	}
	res2, _ := LoadFromPath(dir)
	if endpointByName(res2, "Get account") != nil || res2.Excluded != 1 {
		t.Fatal("excluded request still present")
	}
}

const bruCollection = `headers {
  X-Client: dast
}

auth {
  mode: bearer
}

auth:bearer {
  token: {{token}}
}

vars:pre-request {
  apiVersion: v2
}

script:pre-request {
  bru.setVar("x", 1)
}
`

const bruFolder = `meta {
  name: Admin
}

auth {
  mode: apikey
}

auth:apikey {
  key: X-Admin-Key
  value: {{adminKey}}
  placement: header
}
`

const bruGetUser = `meta {
  name: Get user
  type: http
  seq: 1
}

get {
  url: {{baseUrl}}/{{apiVersion}}/users/:id
  body: none
  auth: inherit
}

params:query {
  include: roles
  ~debug: true
}

params:path {
  id: 42
}

headers {
  X-Trace: abc
}

tests {
  test("ok", () => {})
}
`

const bruCreateUser = `meta {
  name: Create user
}

post {
  url: {{baseUrl}}/admin/users
  body: json
  auth: inherit
}

body:json {
  {
    "name": "bob",
    "role": "admin",
    "settings": {"mfa": false}
  }
}
`

const bruLogin = `meta {
  name: Login
}

post {
  url: {{baseUrl}}/login
  body: formUrlEncoded
  auth: none
}

body:form-urlencoded {
  username: alice
  password: {{password}}
}
`

const bruEnvDev = `vars {
  baseUrl: https://dev.api.test
  token: dev-jwt-123
  adminKey: adm-dev-1
}
vars:secret [
  password
]
`

const bruEnvProd = `vars {
  baseUrl: https://api.test
  token: prod-jwt-456
  adminKey: adm-prod-2
}
`

func writeBrunoTree(t *testing.T, dir string) {
	t.Helper()
	files := map[string]string{
		"bruno.json":             `{"version":"1","name":"Users","type":"collection"}`,
		"collection.bru":         bruCollection,
		"environments/dev.bru":   bruEnvDev,
		"environments/prod.bru":  bruEnvProd,
		"users/get-user.bru":     bruGetUser,
		"admin/folder.bru":       bruFolder,
		"admin/create-user.bru":  bruCreateUser,
		"login.bru":              bruLogin,
		"node_modules/x/bad.bru": "get {\n  url: http://evil\n}\n",
	}
	for p, c := range files {
		mustWrite(t, filepath.Join(dir, filepath.FromSlash(p)), c)
	}
}

func checkBruno(t *testing.T, res *Result, wantToken, wantBase string) {
	t.Helper()
	if res == nil {
		t.Fatal("no result")
	}
	get := endpointByName(res, "Get user")
	if get == nil || get.Path != wantBase+"/v2/users/42" || get.Source != "bruno" || get.Folder != "users" {
		t.Fatalf("get user = %+v", get)
	}
	if get.ParamLocations["id"] != "path" || get.ParamLocations["include"] != "query" || get.ParamLocations["debug"] != "" {
		t.Fatalf("get user params = %v", get.ParamLocations)
	}
	if get.Headers["X-Client"] != "dast" || get.Headers["X-Trace"] != "abc" {
		t.Fatalf("header inheritance = %v", get.Headers)
	}
	if res.AuthHeaders["Authorization"] != "Bearer "+wantToken {
		t.Fatalf("collection bearer auth = %v", res.AuthHeaders)
	}
	create := endpointByName(res, "Create user")
	if create == nil || create.BodyMode != "json" || create.ParamLocations["settings.mfa"] != "body" {
		t.Fatalf("create user = %+v", create)
	}
	if res.AuthHeaders["X-Admin-Key"] == "" {
		t.Fatalf("folder apikey auth not applied: %v", res.AuthHeaders)
	}
	login := endpointByName(res, "Login")
	if login == nil || login.BodyMode != "form" || login.ParamLocations["password"] != "body" {
		t.Fatalf("login = %+v", login)
	}
	for _, e := range res.Endpoints {
		if strings.Contains(e.Path, "evil") {
			t.Fatal("node_modules must be skipped")
		}
	}
	if res.ScriptsSkipped != 2 {
		t.Fatalf("scripts skipped = %d, want 2", res.ScriptsSkipped)
	}
}

func TestBrunoDirectoryWithEnvSelection(t *testing.T) {
	dir := t.TempDir()
	writeBrunoTree(t, dir)
	if err := WriteSelection(dir, Options{Env: "prod"}); err != nil {
		t.Fatal(err)
	}
	res, err := LoadFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	checkBruno(t, res, "prod-jwt-456", "https://api.test")
	if strings.Join(res.Environments, ",") != "dev,prod" {
		t.Fatalf("envs = %v", res.Environments)
	}
	if strings.Join(res.MissingVars, ",") != "password" {
		t.Fatalf("missing = %v", res.MissingVars)
	}

	// Dev env: secret var is reported; operator override fills it.
	_ = WriteSelection(dir, Options{Env: "dev", Vars: map[string]string{"password": "pw-1"}})
	res, _ = LoadFromPath(dir)
	checkBruno(t, res, "dev-jwt-123", "https://dev.api.test")
	if len(res.MissingVars) != 0 || !strings.Contains(strings.Join(res.Notes, "\n"), "secret variables") {
		t.Fatalf("missing=%v notes=%v", res.MissingVars, res.Notes)
	}
	if login := endpointByName(res, "Login"); !strings.Contains(login.Body, "password=pw-1") {
		t.Fatalf("override not applied: %q", login.Body)
	}
}

func TestBrunoZipUpload(t *testing.T) {
	src := t.TempDir()
	writeBrunoTree(t, src)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	_ = filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		w, _ := zw.Create("Users Collection/" + filepath.ToSlash(rel)) // top-level folder, like a real export
		b, _ := os.ReadFile(p)
		_, _ = w.Write(b)
		return nil
	})
	_ = zw.Close()

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "users.zip"), buf.String())
	_ = WriteSelection(dir, Options{Env: "prod"})
	res, err := LoadFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	checkBruno(t, res, "prod-jwt-456", "https://api.test")

	// A non-Bruno zip still falls through to the APK parser (nil here).
	var empty bytes.Buffer
	zw = zip.NewWriter(&empty)
	w, _ := zw.Create("readme.txt")
	_, _ = w.Write([]byte("hi"))
	_ = zw.Close()
	if parseBrunoZip(empty.Bytes(), Options{}) != nil {
		t.Fatal("zip without .bru must not parse as Bruno")
	}
}

func TestBrunoSingleFileAndParser(t *testing.T) {
	res := ParseBytes([]byte(bruCreateUser), "create.bru")
	if res == nil || len(res.Endpoints) != 1 || res.Endpoints[0].Method != "POST" {
		t.Fatalf("single .bru = %+v", res)
	}
	if strings.Join(res.MissingVars, ",") != "baseUrl" {
		t.Fatalf("missing = %v", res.MissingVars)
	}
	f := parseBru(bruGetUser)
	if b := f.block("params:query"); b == nil || len(b.dict) != 2 || b.dict[1].enabled {
		t.Fatalf("disabled (~) entry not parsed: %+v", b)
	}
	if b := f.block("tests"); b == nil || !strings.Contains(b.text, "test(") {
		t.Fatal("text block not captured")
	}
	if parseBru(bruEnvDev).block("vars:secret").list[0] != "password" {
		t.Fatal("list block not parsed")
	}
}

func TestBrunoJSONExport(t *testing.T) {
	exp := `{
	  "name": "Users", "version": "1",
	  "brunoConfig": {"version": "1"},
	  "root": {"request": {"auth": {"mode": "bearer", "bearer": {"token": "{{token}}"}}, "headers": [{"name": "X-Client", "value": "dast", "enabled": true}]}},
	  "environments": [{"name": "prod", "variables": [
	    {"name": "baseUrl", "value": "https://api.test", "enabled": true},
	    {"name": "token", "value": "prod-jwt-456", "enabled": true},
	    {"name": "secretThing", "value": "", "enabled": true, "secret": true}
	  ]}],
	  "items": [
	    {"type": "folder", "name": "users", "items": [
	      {"type": "http-request", "name": "Get user", "request": {
	        "url": "{{baseUrl}}/users/:id", "method": "GET",
	        "params": [{"name": "id", "value": "42", "type": "path", "enabled": true}, {"name": "include", "value": "roles", "type": "query", "enabled": true}],
	        "headers": [], "body": {"mode": "none"}, "auth": {"mode": "inherit"},
	        "script": {"req": "bru.setVar('a', 1)"}
	      }}
	    ]}
	  ]
	}`
	res := ParseBytes([]byte(exp), "users.json")
	if res == nil {
		t.Fatal("bruno json not detected")
	}
	get := endpointByName(res, "Get user")
	if get == nil || get.Path != "https://api.test/users/42" || get.Folder != "users" || get.Headers["X-Client"] != "dast" {
		t.Fatalf("get = %+v", get)
	}
	if res.AuthHeaders["Authorization"] != "Bearer prod-jwt-456" || res.ScriptsSkipped != 1 {
		t.Fatalf("auth=%v scripts=%d", res.AuthHeaders, res.ScriptsSkipped)
	}
	if !strings.Contains(strings.Join(res.Notes, "\n"), "secretThing") {
		t.Fatalf("secret var not reported: %v", res.Notes)
	}
}

func TestJSONBodyKeys(t *testing.T) {
	got := strings.Join(jsonBodyKeys(`[{"a":1,"b":{"c":2,"d":[1]},"e":[{"f":1}]}]`), ",")
	if got != "a,b,b.c,b.d,e,e.f" {
		t.Fatalf("keys = %s", got)
	}
	if jsonBodyKeys("not json") != nil || jsonBodyKeys(`"str"`) != nil {
		t.Fatal("non-object bodies have no keys")
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
