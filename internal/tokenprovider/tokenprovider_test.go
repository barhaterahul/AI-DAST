package tokenprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + ".c2ln"
}

// tokenServer emulates a custom JSON token API with a separate refresh call
// and rotating refresh tokens.
type tokenServer struct {
	t          *testing.T
	fetches    atomic.Int32
	refreshes  atomic.Int32
	lastBody   atomic.Value // map[string]any
	rejectRefr atomic.Bool
	exp        time.Time
}

func (ts *tokenServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/token", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		ts.lastBody.Store(body)
		if body["secret"] != "s3cr3t-value" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"bad secret s3cr3t-value"}`)
			return
		}
		n := ts.fetches.Add(1)
		claims := map[string]any{"sub": body["userId"], "tenant": body["tenantId"], "roles": body["roles"], "exp": float64(ts.exp.Unix())}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"accessToken":  makeJWT(ts.t, claims),
				"refreshToken": fmt.Sprintf("rt-%d", n),
			},
		})
	})
	mux.HandleFunc("/api/v1/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if ts.rejectRefr.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := ts.refreshes.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"accessToken":  makeJWT(ts.t, map[string]any{"sub": "refreshed", "rt": body["refreshToken"], "exp": float64(ts.exp.Unix())}),
				"refreshToken": fmt.Sprintf("rt-r%d", n),
			},
		})
	})
	return mux
}

func testProvider(base string) *Provider {
	p := &Provider{
		ID: "corp",
		Request: RequestSpec{
			URL: base + "/api/v1/token",
			Body: map[string]any{
				"clientId": "{{clientId}}",
				"secret":   "{{secret:clientSecret}}",
				"userId":   "{{userId}}",
				"tenantId": "{{tenantId}}",
				"roles":    "{{roles}}",
				"nested":   []any{"{{userId}}", 7.0},
			},
		},
		Extract: ExtractSpec{Token: "$.data.accessToken", RefreshToken: "$.data.refreshToken"},
		Refresh: RefreshSpec{
			Request: &RequestSpec{
				URL:  base + "/api/v1/token/refresh",
				Body: map[string]any{"refreshToken": "{{refresh_token}}"},
			},
		},
		Secrets: map[string]string{"clientSecret": "s3cr3t-value"},
		Profiles: map[string]map[string]string{
			"user_a": {"clientId": "dast", "userId": "u-1001", "tenantId": "t-1", "roles": "USER"},
			"user_b": {"clientId": "dast", "userId": "u-2002", "tenantId": "t-1", "roles": "USER"},
		},
	}
	p.Normalize()
	return p
}

func TestFetchRendersBodyAndExtracts(t *testing.T) {
	ts := &tokenServer{t: t, exp: time.Now().Add(10 * time.Minute).Truncate(time.Second)}
	srv := httptest.NewServer(ts.handler())
	defer srv.Close()
	p := testProvider(srv.URL)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	tok, err := NewClient(p).Fetch(context.Background(), p, "user_a")
	if err != nil {
		t.Fatal(err)
	}
	body := ts.lastBody.Load().(map[string]any)
	if body["userId"] != "u-1001" || body["secret"] != "s3cr3t-value" || body["clientId"] != "dast" {
		t.Fatalf("body not rendered: %v", body)
	}
	if nested := body["nested"].([]any); nested[0] != "u-1001" || nested[1] != 7.0 {
		t.Fatalf("nested not rendered: %v", nested)
	}
	if tok.Refresh != "rt-1" || tok.HeaderName != "Authorization" || !strings.HasPrefix(tok.HeaderValue, "Bearer ey") {
		t.Fatalf("unexpected token: %+v", tok)
	}
	if tok.JWT == nil || tok.JWT.Claims["sub"] != "u-1001" || tok.JWT.Claims["tenant"] != "t-1" {
		t.Fatalf("claims not decoded: %+v", tok.JWT)
	}
	if !tok.Expiry.Equal(ts.exp) {
		t.Fatalf("expiry %v, want JWT exp %v", tok.Expiry, ts.exp)
	}
}

func TestFetchErrorRedactsSecret(t *testing.T) {
	ts := &tokenServer{t: t, exp: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(ts.handler())
	defer srv.Close()
	p := testProvider(srv.URL)
	p.Secrets["clientSecret"] = "wrong-secret"
	_, err := NewClient(p).Fetch(context.Background(), p, "user_a")
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("want 401 error, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestMissingParams(t *testing.T) {
	p := testProvider("https://token.example")
	p.Profiles["thin"] = map[string]string{"clientId": "x"}
	_, err := NewClient(p).Fetch(context.Background(), p, "thin")
	var mp *ErrMissingParams
	if !errors.As(err, &mp) || strings.Join(mp.Names, ",") != "roles,tenantId,userId" {
		t.Fatalf("want missing params, got %v", err)
	}
	if _, err := NewClient(p).Fetch(context.Background(), p, "nope"); err == nil {
		t.Fatal("unknown profile must fail")
	}
}

func TestRefreshRotatesAndFallsBack(t *testing.T) {
	ts := &tokenServer{t: t, exp: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(ts.handler())
	defer srv.Close()
	p := testProvider(srv.URL)
	c := NewClient(p)
	first, err := c.Fetch(context.Background(), p, "user_a")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Refresh(context.Background(), p, "user_a", first)
	if err != nil {
		t.Fatal(err)
	}
	if second.Source != "refresh" || second.Refresh != "rt-r1" || second.JWT.Claims["rt"] != "rt-1" {
		t.Fatalf("refresh did not use/rotate refresh token: %+v %+v", second, second.JWT)
	}
	ts.rejectRefr.Store(true)
	third, err := c.Refresh(context.Background(), p, "user_a", second)
	if err != nil {
		t.Fatal(err)
	}
	if third.Source != "fetch" || ts.fetches.Load() != 2 {
		t.Fatalf("expected fallback to full fetch, got %s (fetches=%d)", third.Source, ts.fetches.Load())
	}
}

func TestExtractRules(t *testing.T) {
	body := []byte(`{"data":{"list":[{"t":"abc"}],"weird-key":{"v":42},"ok":true}}`)
	var doc any
	_ = json.Unmarshal(body, &doc)
	h := http.Header{"X-Auth-Token": {"hdr-tok"}}
	cases := map[string]string{
		"$.data.list[0].t":      "abc",
		"data.list[0].t":        "abc",
		"$.data['weird-key'].v": "42",
		"$.data.ok":             "true",
		"header:X-Auth-Token":   "hdr-tok",
		`regex:"t":"([a-z]+)"`:  "abc",
		"$.data.missing":        "",
		"$.data.list[5].t":      "",
		`$.data["weird-key"]`:   `{"v":42}`,
	}
	for rule, want := range cases {
		got, err := extractValue(rule, h, body, doc)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", rule, got, err, want)
		}
	}
	for _, bad := range []string{"$", "$.", "$.a[x]", "$.a[0"} {
		if _, err := parsePath(bad); err == nil {
			t.Errorf("parsePath(%q) should fail", bad)
		}
	}
}

func TestExpiresInAndFormBody(t *testing.T) {
	var gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotForm = string(b)
		w.Header().Set("X-Token", "opaque-token-value")
		_, _ = io.WriteString(w, `{"expires_in": 120}`)
	}))
	defer srv.Close()
	p := &Provider{
		ID:       "form",
		Request:  RequestSpec{URL: srv.URL, BodyType: "form", Body: map[string]any{"user": "{{u}}", "pw": "{{secret:pw}}"}},
		Extract:  ExtractSpec{Token: "header:X-Token", ExpiresIn: "$.expires_in"},
		Apply:    ApplySpec{Header: "X-Api-Token", Format: "{{token}}"},
		Secrets:  map[string]string{"pw": "p&w=1"},
		Profiles: map[string]map[string]string{"a": {"u": "alice"}},
	}
	p.Normalize()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	c := NewClient(p)
	c.Now = func() time.Time { return now }
	tok, err := c.Fetch(context.Background(), p, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotForm, "user=alice") || !strings.Contains(gotForm, "pw=p%26w%3D1") {
		t.Fatalf("form not encoded: %q", gotForm)
	}
	if tok.Expiry != now.Add(120*time.Second) || tok.Headers()["X-Api-Token"] != "opaque-token-value" {
		t.Fatalf("unexpected token %+v", tok)
	}
	if tok.JWT != nil {
		t.Fatal("opaque token must not decode as JWT")
	}
}

func TestValidate(t *testing.T) {
	good := testProvider("https://t.example")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := []func(p *Provider){
		func(p *Provider) { p.ID = "../x" },
		func(p *Provider) { p.Request.URL = "ftp://x" },
		func(p *Provider) { p.Request.Method = "DELETE" },
		func(p *Provider) { p.Extract.Token = "" },
		func(p *Provider) { p.Extract.Token = "regex:(" },
		func(p *Provider) { p.Apply.Format = "Bearer" },
		func(p *Provider) { p.Apply.Header = "Bad Header" },
		func(p *Provider) { p.Profiles["bad name"] = nil },
		func(p *Provider) { p.Request.Headers = map[string]string{"a:b": "x"} },
	}
	for i, m := range mut {
		p := testProvider("https://t.example")
		m(p)
		if err := p.Validate(); err == nil {
			t.Errorf("mutation %d should fail validation", i)
		}
	}
	// Templated base URL is allowed.
	p := testProvider("{{base}}")
	if err := p.Validate(); err != nil {
		t.Fatalf("templated URL rejected: %v", err)
	}
	if got := strings.Join(p.Placeholders(), ","); got != "base,clientId,roles,tenantId,userId" {
		t.Fatalf("placeholders = %s", got)
	}
}

func TestManagerSingleFlightAndHooks(t *testing.T) {
	ts := &tokenServer{t: t, exp: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(ts.handler())
	defer srv.Close()
	p := testProvider(srv.URL)
	var mu sync.Mutex
	seen := map[string]int{}
	m, err := NewManager(p, nil, map[string]string{RoleA: "user_a", RoleB: "user_b"}, Hooks{
		OnToken: func(role string, tok *Token) {
			mu.Lock()
			seen[role]++
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if m.Current(RoleB).JWT.Claims["sub"] != "u-2002" {
		t.Fatal("role B should carry profile user_b")
	}
	stale := m.Current(RoleA).HeaderValue
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !m.ForceRefresh(context.Background(), RoleA, stale) {
				t.Error("force refresh failed")
			}
		}()
	}
	wg.Wait()
	if n := ts.refreshes.Load(); n != 1 {
		t.Fatalf("20 concurrent 401s caused %d refreshes, want 1", n)
	}
	if m.Current(RoleA).HeaderValue == stale {
		t.Fatal("token not replaced")
	}
	st := m.Status()
	if len(st) != 2 || st[0].Role != RoleA || st[0].Refreshes != 1 || !st[0].Valid {
		t.Fatalf("status = %+v", st)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen[RoleA] != 2 || seen[RoleB] != 1 {
		t.Fatalf("hooks = %v", seen)
	}
	if !m.RefreshOn(401) || m.RefreshOn(403) {
		t.Fatal("default refresh status should be 401 only")
	}
}

func TestManagerStartFailsAndBackgroundRefresh(t *testing.T) {
	ts := &tokenServer{t: t, exp: time.Now().Add(time.Hour)}
	srv := httptest.NewServer(ts.handler())
	defer srv.Close()
	p := testProvider(srv.URL)
	p.Secrets["clientSecret"] = "nope"
	m, _ := NewManager(p, nil, map[string]string{RoleA: "user_a"}, Hooks{})
	if err := m.Start(context.Background()); err == nil {
		t.Fatal("start must fail with a bad secret")
	}
	if _, err := NewManager(p, nil, map[string]string{RoleA: "ghost"}, Hooks{}); err == nil {
		t.Fatal("unknown profile must fail")
	}

	// Short-lived token: background loop refreshes on its own.
	ts2 := &tokenServer{t: t, exp: time.Now().Add(400 * time.Millisecond)}
	srv2 := httptest.NewServer(ts2.handler())
	defer srv2.Close()
	p2 := testProvider(srv2.URL)
	got := make(chan string, 4)
	m2, _ := NewManager(p2, nil, map[string]string{RoleA: "user_a"}, Hooks{
		OnToken: func(_ string, tok *Token) { got <- tok.Source },
	})
	m2.minWait = 10 * time.Millisecond
	if err := m2.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer m2.Stop()
	<-got // initial fetch
	select {
	case src := <-got:
		if src != "refresh" {
			t.Fatalf("background update source = %s", src)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("background refresh did not happen")
	}
}

func TestStoreRoundTripMasksSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tp.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	p := *testProvider("https://t.example")
	if _, err := s.Put(p); err != nil {
		t.Fatal(err)
	}
	// Update with the masked value keeps the stored secret.
	upd := s.Get("corp").Masked()
	if upd.Secrets["clientSecret"] != MaskedValue {
		t.Fatal("masked view must hide the secret")
	}
	upd.Name = "Corp token API"
	if _, err := s.Put(upd); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Get("corp")
	if got == nil || got.Name != "Corp token API" || got.Secrets["clientSecret"] != "s3cr3t-value" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if ok, _ := s2.Delete("corp"); !ok || s2.Get("corp") != nil {
		t.Fatal("delete failed")
	}
	bad := p
	bad.ID = "bad id"
	if _, err := s2.Put(bad); err == nil {
		t.Fatal("invalid provider must be rejected")
	}
}

func TestDecodeJWTAndMask(t *testing.T) {
	jwt := makeJWT(t, map[string]any{"exp": 1700000000.0, "iat": 1699990000.0, "sub": "x"})
	info := DecodeJWT("Bearer " + jwt)
	if info == nil || info.Expiry.Unix() != 1700000000 || info.IssuedAt.Unix() != 1699990000 || info.Header["alg"] != "RS256" {
		t.Fatalf("decode = %+v", info)
	}
	for _, bad := range []string{"", "a.b", "a.b.c", "x.y.z.w"} {
		if DecodeJWT(bad) != nil {
			t.Errorf("DecodeJWT(%q) should be nil", bad)
		}
	}
	if MaskToken(jwt) == jwt || !strings.Contains(MaskToken(jwt), "…") {
		t.Fatal("mask must shorten")
	}
}
