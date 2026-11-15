package httpclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type fakeRefresher struct {
	ctx   string
	calls atomic.Int32
	fail  bool
}

func (f *fakeRefresher) RefreshOn(status int) bool { return status == http.StatusUnauthorized }

func (f *fakeRefresher) Refresh(_ context.Context, stale map[string]string) bool {
	f.calls.Add(1)
	if f.fail || stale["Authorization"] != "Bearer old" {
		return false
	}
	SetSessionAuth(f.ctx, map[string]string{"Authorization": "Bearer new"})
	return true
}

func TestHTTPRequestRefreshesExpiredSessionTokenOnce(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer new" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok body="+string(body))
	}))
	defer srv.Close()

	const ctxID = "refresh-ctx"
	SetSessionAuth(ctxID, map[string]string{"Authorization": "Bearer old"})
	defer SetSessionAuth(ctxID, nil)
	ref := &fakeRefresher{ctx: ctxID}
	SetAuthRefresher(ctxID, ref)
	defer SetAuthRefresher(ctxID, nil)

	res, err := executeWithContext(ctxID, nil, map[string]string{
		"url": srv.URL, "method": "POST", "body": `{"a":1}`, "follow_redirects": "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Output, "200 OK") || !strings.Contains(res.Output, `ok body={"a":1}`) {
		t.Fatalf("retry did not succeed / body not replayed:\n%s", res.Output)
	}
	if !strings.Contains(res.Output, "token provider issued a fresh token") {
		t.Fatalf("missing refresh note:\n%s", res.Output)
	}
	if ref.calls.Load() != 1 || hits.Load() != 2 {
		t.Fatalf("calls=%d hits=%d, want 1 refresh and 2 requests", ref.calls.Load(), hits.Load())
	}
}

func TestHTTPRequestNoRefreshForDeliberateUnauthProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	const ctxID = "refresh-ctx-probe"
	SetSessionAuth(ctxID, map[string]string{"Authorization": "Bearer old"})
	defer SetSessionAuth(ctxID, nil)
	ref := &fakeRefresher{ctx: ctxID}
	SetAuthRefresher(ctxID, ref)
	defer SetAuthRefresher(ctxID, nil)

	// Blank Authorization = agent intentionally testing without auth.
	res, err := executeWithContext(ctxID, nil, map[string]string{
		"url": srv.URL, "headers": `{"Authorization": ""}`, "follow_redirects": "false",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref.calls.Load() != 0 || !strings.Contains(res.Output, "401") {
		t.Fatalf("deliberate unauthenticated probe must not refresh (calls=%d)\n%s", ref.calls.Load(), res.Output)
	}

	// Failed refresh: original 401 is returned, no retry note.
	ref.fail = true
	res, err = executeWithContext(ctxID, nil, map[string]string{"url": srv.URL, "follow_redirects": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if ref.calls.Load() != 1 || strings.Contains(res.Output, "retried once") {
		t.Fatalf("failed refresh must surface the original response (calls=%d)\n%s", ref.calls.Load(), res.Output)
	}
}
