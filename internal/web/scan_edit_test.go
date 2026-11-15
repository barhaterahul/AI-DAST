package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addTestInstance(t *testing.T, s *Server, id, status string) *ScanInstance {
	t.Helper()
	inst := &ScanInstance{
		ID: id, Name: "orig", Targets: "https://shop.test", Status: status, ScanMode: "single",
		Instruction: "old instruction", Phases: []int{1, 2}, ReconMode: "active", ScanIntensity: "active",
		TargetAuth: "Authorization: Bearer secret-token-value",
	}
	switch status {
	case "saved":
		dir := filepath.Join(s.dataDir, "_saved", id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		s.saveScanRecordTo(&ScanRecord{ID: id, Name: "orig", Target: inst.Targets, Status: "saved", ScanMode: "single"}, dir)
	default:
		dir := filepath.Join(s.dataDir, "shop.test", "2026-11-15", id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		inst.scanDir = dir
		s.saveScanRecordTo(&ScanRecord{ID: id, InstanceID: id, Name: "orig", Target: inst.Targets, Status: status, ScanMode: "single"}, dir)
	}
	s.instancesMu.Lock()
	s.instances[id] = inst
	s.instancesMu.Unlock()
	return inst
}

func configCall(t *testing.T, s *Server, method, id, body string) (int, map[string]any, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.handleInstanceAction(rec, httptest.NewRequest(method, "/api/instances/"+id+"/config", bytes.NewBufferString(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Body.String()
}

func TestScanEditPolicyByStatus(t *testing.T) {
	cases := map[string]struct {
		targets, name bool
		applies       string
	}{
		"saved":    {true, true, "start"},
		"paused":   {false, true, "resume"},
		"finished": {false, true, "next_run"},
		"stopped":  {false, true, "next_run"},
		"failed":   {false, true, "next_run"},
		"running":  {false, false, ""},
		"pending":  {false, false, ""},
		"stopping": {false, false, ""},
	}
	for status, want := range cases {
		p := editPolicyFor(status)
		if p.allows(editTargets) != want.targets || p.allows(editName) != want.name || p.AppliesOn != want.applies {
			t.Errorf("%s: policy %+v", status, p)
		}
		if !want.name && p.LockedReason == "" {
			t.Errorf("%s: locked policy needs a reason", status)
		}
	}
}

func TestEditSavedScan(t *testing.T) {
	s := newTestServer(t, nil)
	addTestInstance(t, s, "saved1", "saved")

	code, out, raw := configCall(t, s, http.MethodGet, "saved1", "")
	if code != 200 || strings.Contains(raw, "secret-token-value") {
		t.Fatalf("GET config: %d %s", code, raw)
	}
	if out["config"].(map[string]any)["has_target_auth"] != true {
		t.Fatalf("has_target_auth missing: %s", raw)
	}

	body := `{"status":"saved","name":"  Shop API  ","targets":["https://shop.test","https://api.shop.test"],"scan_mode":"wildcard",
	  "instruction":"focus on /api","phases":[3,1,3],"scan_intensity":"passive","severity_filter":["HIGH","critical"],"target_auth":""}`
	code, out, raw = configCall(t, s, http.MethodPatch, "saved1", body)
	if code != 200 {
		t.Fatalf("PATCH saved: %d %s", code, raw)
	}
	cfg := out["config"].(map[string]any)
	if cfg["name"] != "Shop API" || len(cfg["targets"].([]any)) != 2 || cfg["scan_mode"] != "wildcard" {
		t.Fatalf("config = %v", cfg)
	}
	if cfg["recon_mode"] != "passive" || cfg["has_target_auth"] != false || len(cfg["phases"].([]any)) != 2 {
		t.Fatalf("normalization/clearing failed: %v", cfg)
	}
	rec, ok := loadScanRecordFromDir(filepath.Join(s.dataDir, "_saved", "saved1"))
	if !ok || rec.Name != "Shop API" || !strings.Contains(rec.Target, "api.shop.test") || rec.Instruction != "focus on /api" || rec.ScanMode != "wildcard" {
		t.Fatalf("saved record not persisted: %+v", rec)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dataDir, "_saved", "saved1", "scan.json")); strings.Contains(string(b), "secret-token-value") {
		t.Fatal("credential written to disk")
	}
}

func TestEditRunningScanIsLocked(t *testing.T) {
	s := newTestServer(t, nil)
	addTestInstance(t, s, "run1", "running")
	code, out, _ := configCall(t, s, http.MethodPatch, "run1", `{"name":"x"}`)
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "Pause or stop") {
		t.Fatalf("running edit: %d %v", code, out)
	}
}

func TestEditFinishedScanAppliesToNextRun(t *testing.T) {
	s := newTestServer(t, nil)
	inst := addTestInstance(t, s, "fin1", "finished")

	code, out, _ := configCall(t, s, http.MethodPatch, "fin1", `{"targets":["https://other.test"]}`)
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "targets") {
		t.Fatalf("targets on finished scan: %d %v", code, out)
	}
	code, out, raw := configCall(t, s, http.MethodPatch, "fin1", `{"name":"rerun","instruction":"new focus","target_auth":"Cookie: s=new-session-cookie"}`)
	if code != 200 || out["policy"].(map[string]any)["applies_on"] != "next_run" {
		t.Fatalf("finished edit: %d %s", code, raw)
	}
	if inst.TargetAuth != "Cookie: s=new-session-cookie" || inst.Targets != "https://shop.test" {
		t.Fatalf("instance not updated correctly: %+v", inst)
	}
	rec, _ := loadScanRecordFromDir(inst.scanDir)
	if rec.Name != "rerun" || rec.Instruction != "new focus" || rec.Target != "https://shop.test" {
		t.Fatalf("record = %+v (target of a finished run must not change)", rec)
	}
}

func TestEditValidationAndConflicts(t *testing.T) {
	s := newTestServer(t, nil)
	addTestInstance(t, s, "v1", "saved")
	outside := t.TempDir()
	for _, body := range []string{
		`{}`,
		`{"phases":[99]}`,
		`{"severity_filter":["urgent"]}`,
		`{"recon_mode":"loud"}`,
		`{"scan_mode":"dast"}`,
		`{"targets":[]}`,
		`{"targets":["127.0.0.1"]}`,
		`{"token_auth":{"provider":"ghost","profile":"a"}}`,
		`{"scan_context":"` + outside + `"}`,
		`{"logo_path":"/etc/passwd"}`,
		`{"unknown_field":1}`,
	} {
		if code, _, raw := configCall(t, s, http.MethodPatch, "v1", body); code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", body, code, raw)
		}
	}
	// The client saw "saved" but the scan has started meanwhile.
	if code, _, _ := configCall(t, s, http.MethodPatch, "v1", `{"status":"paused","name":"x"}`); code != http.StatusConflict {
		t.Fatalf("stale status not rejected: %d", code)
	}
	if code, _, _ := configCall(t, s, http.MethodPatch, "nope", `{"name":"x"}`); code != http.StatusNotFound {
		t.Fatalf("unknown instance: %d", code)
	}
}

func TestEditTokenAuthValidatesProfiles(t *testing.T) {
	s := newTestServer(t, nil)
	api, _ := newFakeTokenAPI(t)
	if code, _, raw := doJSON(t, s, http.MethodPost, "/api/token-providers", providerJSON(api.URL)); code != 200 {
		t.Fatal(raw)
	}
	inst := addTestInstance(t, s, "tok1", "stopped")
	for _, body := range []string{
		`{"token_auth":{"provider":"corp"}}`,
		`{"token_auth":{"provider":"corp","profile":"zed"}}`,
		`{"token_auth":{"provider":"corp","profile":"alice","profile_b":"alice"}}`,
	} {
		if code, _, raw := configCall(t, s, http.MethodPatch, "tok1", body); code != http.StatusBadRequest {
			t.Errorf("%s accepted: %d %s", body, code, raw)
		}
	}
	code, _, raw := configCall(t, s, http.MethodPatch, "tok1", `{"token_auth":{"provider":"corp","profile":"alice","profile_b":"bob"}}`)
	if code != 200 || inst.TokenAuth == nil || inst.TokenAuth.ProfileB != "bob" {
		t.Fatalf("token auth edit: %d %s", code, raw)
	}
	if rec, _ := loadScanRecordFromDir(inst.scanDir); rec.TokenAuth == nil || rec.TokenAuth.Profile != "alice" {
		t.Fatalf("token auth not persisted: %+v", rec.TokenAuth)
	}
	if code, _, _ := configCall(t, s, http.MethodPatch, "tok1", `{"token_auth":{"provider":""}}`); code != 200 || inst.TokenAuth != nil {
		t.Fatal("clearing token auth failed")
	}
}

// A paused scan must resume with its credentials (which queue state never
// records) and with edits made while paused (written into queue state).
func TestPausedResumeKeepsAuthAndEdits(t *testing.T) {
	s := newTestServer(t, nil)
	inst := addTestInstance(t, s, "p1", "paused")
	inst.TargetAuthSecondary = "Authorization: Bearer second-account"
	inst.TokenAuth = &TokenAuthSelection{Provider: "corp", Profile: "alice"}
	inst.ScanContext = "/ctx/dir"
	s.saveQueueState(0, ScanRequest{
		InstanceID: "p1", Targets: []string{"https://shop.test"}, ScanMode: "single",
		Instruction: "queued instruction", ReconMode: "active", ScanIntensity: "active",
	}, queueProgress{ActiveTarget: "https://shop.test", ActiveScanDir: inst.scanDir, ActiveScanID: "p1"})

	// Without an edit, queue state wins for config; credentials still carry.
	req, ok, reason := s.scanRequestForPausedInstance("p1", inst)
	if !ok {
		t.Fatalf("resume request: %s", reason)
	}
	if req.Instruction != "queued instruction" {
		t.Fatalf("queue state must stay authoritative: %q", req.Instruction)
	}
	if req.TargetAuth != inst.TargetAuth || req.TargetAuthSecondary != inst.TargetAuthSecondary ||
		req.TokenAuth == nil || req.TokenAuth.Profile != "alice" || req.ScanContext != "/ctx/dir" {
		t.Fatalf("resume request lost credentials/context: %+v", req)
	}

	// Edit while paused → the next resume uses it.
	if code, _, raw := configCall(t, s, http.MethodPatch, "p1", `{"instruction":"edited while paused","recon_mode":"passive"}`); code != 200 {
		t.Fatalf("paused edit: %d %s", code, raw)
	}
	req, _, _ = s.scanRequestForPausedInstance("p1", inst)
	if req.Instruction != "edited while paused" || req.ReconMode != "passive" {
		t.Fatalf("edit not applied on resume: %q %q", req.Instruction, req.ReconMode)
	}
	if code, _, _ := configCall(t, s, http.MethodPatch, "p1", `{"scan_mode":"wildcard"}`); code != http.StatusConflict {
		t.Fatal("scan mode must be locked while paused")
	}
}
