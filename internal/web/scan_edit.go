package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Scan editing.
//
// A scan's configuration can be changed only while no session is using it:
//
//	saved                      everything            applies when started
//	paused                     all but targets/mode  applies on resume
//	stopped/finished/failed    all but targets/mode  applies to the next Start
//	running/pending/stopping…  nothing (pause first)
//
// Targets and scan mode are fixed once a scan has run: a paused queue resumes
// from its saved position, and a finished run's record describes what was
// actually scanned. Use a new scan for different targets.

// Editable field names (also used in API responses).
const (
	editName           = "name"
	editTargets        = "targets"
	editScanMode       = "scan_mode"
	editInstruction    = "instruction"
	editPhases         = "phases"
	editReconMode      = "recon_mode"
	editScanIntensity  = "scan_intensity"
	editSeverityFilter = "severity_filter"
	editCompanyName    = "company_name"
	editLogoPath       = "logo_path"
	editTargetAuth     = "target_auth"
	editTargetAuthB    = "target_auth_b"
	editTokenAuth      = "token_auth"
	editScanContext    = "scan_context"
)

var allEditFields = []string{
	editName, editTargets, editScanMode, editInstruction, editPhases, editReconMode,
	editScanIntensity, editSeverityFilter, editCompanyName, editLogoPath,
	editTargetAuth, editTargetAuthB, editTokenAuth, editScanContext,
}

// scanEditPolicy describes what may be edited in a given status.
type scanEditPolicy struct {
	Editable     []string `json:"editable"`
	AppliesOn    string   `json:"applies_on,omitempty"` // start | resume | next_run
	LockedReason string   `json:"locked_reason,omitempty"`
}

func (p scanEditPolicy) allows(field string) bool {
	for _, f := range p.Editable {
		if f == field {
			return true
		}
	}
	return false
}

func editPolicyFor(status string) scanEditPolicy {
	allButQueue := make([]string, 0, len(allEditFields))
	for _, f := range allEditFields {
		if f != editTargets && f != editScanMode {
			allButQueue = append(allButQueue, f)
		}
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "saved":
		return scanEditPolicy{Editable: append([]string(nil), allEditFields...), AppliesOn: "start"}
	case "paused":
		return scanEditPolicy{Editable: allButQueue, AppliesOn: "resume"}
	case "stopped", "finished", "failed":
		return scanEditPolicy{Editable: allButQueue, AppliesOn: "next_run"}
	default:
		return scanEditPolicy{Editable: []string{}, LockedReason: "The scan is " + status + ". Pause or stop it to change its settings."}
	}
}

// ScanEdit is a partial update; nil fields are left unchanged. For the auth
// strings an empty value clears the stored credential.
type ScanEdit struct {
	Name           *string             `json:"name,omitempty"`
	Targets        *[]string           `json:"targets,omitempty"`
	ScanMode       *string             `json:"scan_mode,omitempty"`
	Instruction    *string             `json:"instruction,omitempty"`
	Phases         *[]int              `json:"phases,omitempty"`
	ReconMode      *string             `json:"recon_mode,omitempty"`
	ScanIntensity  *string             `json:"scan_intensity,omitempty"`
	SeverityFilter *[]string           `json:"severity_filter,omitempty"`
	CompanyName    *string             `json:"company_name,omitempty"`
	LogoPath       *string             `json:"logo_path,omitempty"`
	TargetAuth     *string             `json:"target_auth,omitempty"`
	TargetAuthB    *string             `json:"target_auth_b,omitempty"`
	TokenAuth      *TokenAuthSelection `json:"token_auth,omitempty"` // provider "" clears
	ScanContext    *string             `json:"scan_context,omitempty"`
	// Status is the status the client saw; if it no longer matches, the edit
	// is rejected (409) instead of applying under a different policy.
	Status string `json:"status,omitempty"`
}

func (e *ScanEdit) fields() []string {
	var out []string
	add := func(set bool, f string) {
		if set {
			out = append(out, f)
		}
	}
	add(e.Name != nil, editName)
	add(e.Targets != nil, editTargets)
	add(e.ScanMode != nil, editScanMode)
	add(e.Instruction != nil, editInstruction)
	add(e.Phases != nil, editPhases)
	add(e.ReconMode != nil, editReconMode)
	add(e.ScanIntensity != nil, editScanIntensity)
	add(e.SeverityFilter != nil, editSeverityFilter)
	add(e.CompanyName != nil, editCompanyName)
	add(e.LogoPath != nil, editLogoPath)
	add(e.TargetAuth != nil, editTargetAuth)
	add(e.TargetAuthB != nil, editTargetAuthB)
	add(e.TokenAuth != nil, editTokenAuth)
	add(e.ScanContext != nil, editScanContext)
	return out
}

// scanConfigView is the editable configuration as returned to the UI.
// Credentials are never returned — only whether they are set.
type scanConfigView struct {
	Name           string              `json:"name"`
	Targets        []string            `json:"targets"`
	ScanMode       string              `json:"scan_mode"`
	Instruction    string              `json:"instruction"`
	Phases         []int               `json:"phases"`
	ReconMode      string              `json:"recon_mode"`
	ScanIntensity  string              `json:"scan_intensity"`
	SeverityFilter []string            `json:"severity_filter"`
	CompanyName    string              `json:"company_name"`
	LogoPath       string              `json:"logo_path"`
	HasTargetAuth  bool                `json:"has_target_auth"`
	HasTargetAuthB bool                `json:"has_target_auth_b"`
	TokenAuth      *TokenAuthSelection `json:"token_auth,omitempty"`
	ScanContext    string              `json:"scan_context"`
}

type scanConfigResponse struct {
	ID     string         `json:"id"`
	Status string         `json:"status"`
	Policy scanEditPolicy `json:"policy"`
	Config scanConfigView `json:"config"`
}

func configView(inst *ScanInstance) scanConfigResponse {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	var tok *TokenAuthSelection
	if inst.TokenAuth.enabled() {
		cp := *inst.TokenAuth
		tok = &cp
	}
	return scanConfigResponse{
		ID:     inst.ID,
		Status: inst.Status,
		Policy: editPolicyFor(inst.Status),
		Config: scanConfigView{
			Name:           inst.Name,
			Targets:        splitInstanceTargets(inst.Targets),
			ScanMode:       inst.ScanMode,
			Instruction:    inst.Instruction,
			Phases:         append([]int{}, inst.Phases...),
			ReconMode:      inst.ReconMode,
			ScanIntensity:  inst.ScanIntensity,
			SeverityFilter: append([]string{}, inst.SeverityFilter...),
			CompanyName:    inst.CompanyName,
			LogoPath:       inst.LogoPath,
			HasTargetAuth:  strings.TrimSpace(inst.TargetAuth) != "",
			HasTargetAuthB: strings.TrimSpace(inst.TargetAuthSecondary) != "",
			TokenAuth:      tok,
			ScanContext:    inst.ScanContext,
		},
	}
}

var validSeverities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// validateScanEdit checks values (not permissions) and normalizes them.
func (s *Server) validateScanEdit(e *ScanEdit) error {
	if e.Name != nil {
		n := strings.TrimSpace(*e.Name)
		if len(n) > 200 {
			return errors.New("name is too long (max 200 characters)")
		}
		e.Name = &n
	}
	if e.Targets != nil {
		var clean []string
		for _, t := range *e.Targets {
			if t = strings.TrimSpace(t); t != "" {
				clean = append(clean, t)
			}
		}
		if len(clean) == 0 {
			return errors.New("at least one target is required")
		}
		if len(clean) > 500 {
			return errors.New("too many targets (max 500)")
		}
		allBlocked := true
		for _, t := range clean {
			if !s.isBlockedTarget(t) {
				allBlocked = false
				break
			}
		}
		if allBlocked {
			return errors.New("all targets are local/internal addresses or the dashboard itself (self-scan protection)")
		}
		e.Targets = &clean
	}
	if e.ScanMode != nil {
		m := strings.ToLower(strings.TrimSpace(*e.ScanMode))
		switch m {
		case "single", "wildcard":
		default:
			return errors.New("scan_mode must be single or wildcard")
		}
		e.ScanMode = &m
	}
	if e.Instruction != nil {
		if len(*e.Instruction) > 20000 {
			return errors.New("instruction is too long (max 20000 characters)")
		}
		v := strings.TrimSpace(*e.Instruction)
		e.Instruction = &v
	}
	if e.Phases != nil {
		seen := map[int]bool{}
		var out []int
		for _, p := range *e.Phases {
			if p < 1 || p > len(methodologyPhaseNames) {
				return fmt.Errorf("phase %d does not exist (1-%d)", p, len(methodologyPhaseNames))
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		sort.Ints(out)
		e.Phases = &out
	}
	for name, v := range map[string]*string{"recon_mode": e.ReconMode, "scan_intensity": e.ScanIntensity} {
		if v == nil {
			continue
		}
		m := strings.ToLower(strings.TrimSpace(*v))
		if m != "active" && m != "passive" {
			return fmt.Errorf("%s must be active or passive", name)
		}
		*v = m
	}
	if e.ScanIntensity != nil && *e.ScanIntensity == "passive" {
		passive := "passive"
		e.ReconMode = &passive // passive testing implies passive recon (as on New Scan)
	}
	if e.SeverityFilter != nil {
		var out []string
		for _, sv := range *e.SeverityFilter {
			sv = strings.ToLower(strings.TrimSpace(sv))
			if !validSeverities[sv] {
				return fmt.Errorf("unknown severity %q", sv)
			}
			out = append(out, sv)
		}
		e.SeverityFilter = &out
	}
	if e.CompanyName != nil && len(*e.CompanyName) > 200 {
		return errors.New("company_name is too long")
	}
	if e.LogoPath != nil && strings.TrimSpace(*e.LogoPath) != "" {
		lp := filepath.Clean(strings.TrimSpace(*e.LogoPath))
		rel, err := filepath.Rel(filepath.Join(s.dataDir, "logos"), lp)
		if err != nil || strings.HasPrefix(rel, "..") {
			return errors.New("logo_path must be an uploaded logo")
		}
		e.LogoPath = &lp
	}
	for name, v := range map[string]*string{"target_auth": e.TargetAuth, "target_auth_b": e.TargetAuthB} {
		if v != nil && len(*v) > 16<<10 {
			return fmt.Errorf("%s is too long", name)
		}
	}
	if e.TokenAuth != nil && e.TokenAuth.enabled() {
		store, err := s.tokenStore()
		if err != nil {
			return errors.New("token provider store unavailable")
		}
		p := store.Get(strings.TrimSpace(e.TokenAuth.Provider))
		if p == nil {
			return fmt.Errorf("token provider %q not found", e.TokenAuth.Provider)
		}
		for _, prof := range []string{e.TokenAuth.Profile, e.TokenAuth.ProfileB} {
			if prof = strings.TrimSpace(prof); prof != "" {
				if _, ok := p.Profiles[prof]; !ok {
					return fmt.Errorf("profile %q not found in token provider %q", prof, p.ID)
				}
			}
		}
		if strings.TrimSpace(e.TokenAuth.Profile) == "" && len(p.Profiles) > 0 {
			return errors.New("choose the token provider profile for the default session")
		}
		if e.TokenAuth.Profile != "" && e.TokenAuth.Profile == e.TokenAuth.ProfileB {
			return errors.New("role A and role B must be different profiles")
		}
	}
	if e.ScanContext != nil && strings.TrimSpace(*e.ScanContext) != "" {
		dir, err := s.resolveContextDir(*e.ScanContext)
		if err != nil {
			return fmt.Errorf("scan_context: %w", err)
		}
		e.ScanContext = &dir
	}
	return nil
}

// applyScanEdit writes the edit into the instance. inst.mu must be held.
func applyScanEdit(inst *ScanInstance, e *ScanEdit) {
	if e.Name != nil {
		inst.Name = *e.Name
	}
	if e.Targets != nil {
		inst.Targets = strings.Join(*e.Targets, ", ")
	}
	if e.ScanMode != nil {
		inst.ScanMode = *e.ScanMode
	}
	if e.Instruction != nil {
		inst.Instruction = *e.Instruction
	}
	if e.Phases != nil {
		inst.Phases = append([]int(nil), (*e.Phases)...)
		if inst.Status == "saved" {
			inst.CurrentPhase = firstSelectedPhase(inst.Phases)
		}
	}
	if e.ReconMode != nil {
		inst.ReconMode = *e.ReconMode
	}
	if e.ScanIntensity != nil {
		inst.ScanIntensity = *e.ScanIntensity
	}
	if e.SeverityFilter != nil {
		inst.SeverityFilter = append([]string(nil), (*e.SeverityFilter)...)
	}
	if e.CompanyName != nil {
		inst.CompanyName = strings.TrimSpace(*e.CompanyName)
	}
	if e.LogoPath != nil {
		inst.LogoPath = strings.TrimSpace(*e.LogoPath)
	}
	if e.TargetAuth != nil {
		inst.TargetAuth = strings.TrimSpace(*e.TargetAuth)
	}
	if e.TargetAuthB != nil {
		inst.TargetAuthSecondary = strings.TrimSpace(*e.TargetAuthB)
	}
	if e.TokenAuth != nil {
		if e.TokenAuth.enabled() {
			cp := TokenAuthSelection{
				Provider: strings.TrimSpace(e.TokenAuth.Provider),
				Profile:  strings.TrimSpace(e.TokenAuth.Profile),
				ProfileB: strings.TrimSpace(e.TokenAuth.ProfileB),
			}
			inst.TokenAuth = &cp
		} else {
			inst.TokenAuth = nil
		}
	}
	if e.ScanContext != nil {
		inst.ScanContext = strings.TrimSpace(*e.ScanContext)
	}
}

// persistScanEdit mirrors the edited, non-secret config into the scan's
// on-disk record so it survives a restart. Credentials stay in memory only.
func (s *Server) persistScanEdit(inst *ScanInstance) {
	inst.mu.RLock()
	status := inst.Status
	dir := inst.scanDir
	if status == "saved" {
		dir = filepath.Join(s.dataDir, "_saved", inst.ID)
	}
	name, targets, mode := inst.Name, inst.Targets, inst.ScanMode
	instruction, recon, intensity := inst.Instruction, inst.ReconMode, inst.ScanIntensity
	phases := append([]int(nil), inst.Phases...)
	sev := append([]string(nil), inst.SeverityFilter...)
	company, logo := inst.CompanyName, inst.LogoPath
	var tok *TokenAuthSelection
	if inst.TokenAuth.enabled() {
		cp := *inst.TokenAuth
		tok = &cp
	}
	inst.mu.RUnlock()
	if dir == "" {
		return
	}
	rec, ok := loadScanRecordFromDir(dir)
	if !ok || rec == nil {
		return
	}
	rec.Name = name
	if status == "saved" {
		// Only a saved scan's record describes intended (not scanned) targets.
		rec.Target = targets
		rec.ScanMode = mode
		rec.CurrentPhase = firstSelectedPhase(phases)
	}
	rec.Instruction = instruction
	rec.Phases = phases
	rec.SeverityFilter = sev
	rec.ReconMode = recon
	rec.ScanIntensity = intensity
	rec.CompanyName = company
	rec.LogoPath = logo
	rec.TokenAuth = tok
	s.saveScanRecordTo(rec, dir)
}

// handleScanConfig serves GET/PATCH /api/instances/{id}/config.
func (s *Server) handleScanConfig(w http.ResponseWriter, r *http.Request, inst *ScanInstance) {
	switch r.Method {
	case http.MethodGet:
		writeJSONStatus(w, http.StatusOK, configView(inst))
		return
	case http.MethodPatch, http.MethodPut:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var e ScanEdit
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	fields := e.fields()
	if len(fields) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "no changes"})
		return
	}
	if err := s.validateScanEdit(&e); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// A paused run releases its queue lock only once fully exited; hold it
	// while editing so a still-exiting session cannot overwrite the record.
	inst.mu.RLock()
	paused := inst.Status == "paused"
	inst.mu.RUnlock()
	if paused {
		ownership, owned, err := s.acquireQueueOwnershipWithin(r.Context(), inst.ID, queueOwnershipWait)
		if err != nil || !owned {
			writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "the paused run is still shutting down; retry shortly"})
			return
		}
		defer ownership.release()
	}

	inst.mu.Lock()
	status := inst.Status
	if e.Status != "" && !strings.EqualFold(e.Status, status) {
		inst.mu.Unlock()
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "the scan is now " + status + "; reload and try again"})
		return
	}
	policy := editPolicyFor(status)
	var denied []string
	for _, f := range fields {
		if !policy.allows(f) {
			denied = append(denied, f)
		}
	}
	if len(denied) > 0 {
		inst.mu.Unlock()
		msg := policy.LockedReason
		if msg == "" {
			msg = "cannot change " + strings.Join(denied, ", ") + " while the scan is " + status
			if status != "saved" {
				msg += " (targets and scan mode are fixed once a scan has run; start a new scan instead)"
			}
		}
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": msg, "denied": denied})
		return
	}
	applyScanEdit(inst, &e)
	inst.mu.Unlock()

	s.persistScanEdit(inst)
	if status == "paused" {
		if err := s.updateQueueStateConfig(inst); err != nil {
			log.Printf("[scan] edit %s: could not update queue state: %v", inst.ID, err)
		}
	}
	log.Printf("[scan] edited %s (%s): %s", inst.ID, status, strings.Join(fields, ", "))
	s.broadcastToInstance(inst.ID, WSEvent{Type: "message", Content: "Scan settings updated: " + strings.Join(fields, ", "), Timestamp: time.Now().Format(time.RFC3339)})
	s.broadcastDashboard(WSEvent{Type: "instance_updated", Content: inst.ID})
	writeJSONStatus(w, http.StatusOK, configView(inst))
}

// resumeOverrides carries what saved queue state never records — per-scan
// credentials, the token provider selection, uploaded context and source —
// from the instance onto a resume request. Editable config (instruction,
// phases, …) is not overridden here: queue state stays authoritative for it,
// and edits to a paused scan are written into the queue state itself
// (updateQueueStateConfig).
func resumeOverrides(req *ScanRequest, inst *ScanInstance) {
	inst.mu.RLock()
	defer inst.mu.RUnlock()
	req.TargetAuth = inst.TargetAuth
	req.TargetAuthSecondary = inst.TargetAuthSecondary
	req.SourceRepo = inst.SourceRepo
	req.ScanContext = inst.ScanContext
	if inst.TokenAuth.enabled() {
		cp := *inst.TokenAuth
		req.TokenAuth = &cp
	} else {
		req.TokenAuth = nil
	}
}

// updateQueueStateConfig writes a paused scan's edited config into its saved
// queue state, which is what resume reads. No-op when there is none.
func (s *Server) updateQueueStateConfig(inst *ScanInstance) error {
	path := s.queueStatePathForInstance(inst.ID)
	entry, err := s.loadQueueStateEntry(path)
	if err != nil || entry.state == nil {
		return nil
	}
	inst.mu.RLock()
	entry.state.Name = inst.Name
	entry.state.Instruction = inst.Instruction
	entry.state.SeverityFilter = append([]string(nil), inst.SeverityFilter...)
	entry.state.Phases = append([]int(nil), inst.Phases...)
	entry.state.ReconMode = inst.ReconMode
	entry.state.ScanIntensity = inst.ScanIntensity
	entry.state.CompanyName = inst.CompanyName
	entry.state.LogoPath = inst.LogoPath
	inst.mu.RUnlock()
	return s.writeQueueStateAtomic(path, entry.state)
}
