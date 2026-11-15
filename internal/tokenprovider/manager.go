package tokenprovider

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Role names used by the scan integration. RoleA is the default session
// applied to every request; RoleB is the comparison identity used to prove
// cross-account access. Additional roles are allowed (any name).
const (
	RoleA = "A"
	RoleB = "B"
)

// RoleStatus is the operator-visible state of one role's credential.
type RoleStatus struct {
	Role         string    `json:"role"`
	Profile      string    `json:"profile"`
	Valid        bool      `json:"valid"`
	Expiry       time.Time `json:"expiry,omitempty"`
	ObtainedAt   time.Time `json:"obtained_at,omitempty"`
	Refreshes    int       `json:"refreshes"`
	Failures     int       `json:"failures"`
	LastError    string    `json:"last_error,omitempty"`
	TokenPreview string    `json:"token_preview,omitempty"`
}

// Hooks receive manager events. All are optional and may be called from the
// manager's goroutines.
type Hooks struct {
	// OnToken fires after every successful fetch/refresh.
	OnToken func(role string, tok *Token)
	// OnError fires on every failed refresh; fatal is true once the role has
	// failed MaxFailures times in a row (the token is likely unusable).
	OnError func(role string, err error, fatal bool)
}

// MaxFailures is the consecutive-failure count reported as fatal.
const MaxFailures = 3

type roleState struct {
	mu        sync.Mutex // serializes refreshes (single-flight per role)
	role      string
	profile   string
	tok       *Token
	refreshes int
	failures  int
	lastErr   error
}

// Manager keeps one token per role fresh for the life of a scan.
type Manager struct {
	provider *Provider
	client   *Client
	hooks    Hooks
	roles    []*roleState

	cancel context.CancelFunc
	wg     sync.WaitGroup
	// backoff is the delay schedule after failures (overridable in tests).
	backoff []time.Duration
	// minWait bounds how often the background loop can refresh.
	minWait time.Duration
}

// NewManager builds a manager for roles (role name -> profile name).
func NewManager(p *Provider, client *Client, roles map[string]string, hooks Hooks) (*Manager, error) {
	if p == nil {
		return nil, errors.New("nil provider")
	}
	if len(roles) == 0 {
		return nil, errors.New("no roles selected")
	}
	if client == nil {
		client = NewClient(p)
	}
	m := &Manager{
		provider: p,
		client:   client,
		hooks:    hooks,
		backoff:  []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second, 2 * time.Minute},
		minWait:  5 * time.Second,
	}
	names := make([]string, 0, len(roles))
	for r := range roles {
		names = append(names, r)
	}
	sort.Strings(names)
	for _, r := range names {
		prof := roles[r]
		if prof != "" {
			if _, ok := p.Profiles[prof]; !ok {
				return nil, fmt.Errorf("role %s: profile %q not found in provider %q", r, prof, p.ID)
			}
		}
		m.roles = append(m.roles, &roleState{role: r, profile: prof})
	}
	return m, nil
}

// Start fetches every role's token synchronously (so a scan never starts with
// broken auth) and then launches the background refresh loops. It returns the
// first fetch error, in which case no loops are started.
func (m *Manager) Start(ctx context.Context) error {
	for _, rs := range m.roles {
		tok, err := m.client.Fetch(ctx, m.provider, rs.profile)
		if err != nil {
			return fmt.Errorf("role %s (profile %q): %w", rs.role, rs.profile, err)
		}
		rs.mu.Lock()
		rs.tok = tok
		rs.mu.Unlock()
		if m.hooks.OnToken != nil {
			m.hooks.OnToken(rs.role, tok)
		}
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	for _, rs := range m.roles {
		m.wg.Add(1)
		go m.loop(loopCtx, rs)
	}
	return nil
}

// Stop ends the refresh loops and waits for them.
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

func (m *Manager) role(name string) *roleState {
	for _, rs := range m.roles {
		if rs.role == name {
			return rs
		}
	}
	return nil
}

// Current returns the role's current token (nil if unknown role).
func (m *Manager) Current(role string) *Token {
	rs := m.role(role)
	if rs == nil {
		return nil
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.tok
}

// RefreshOn reports whether a target response status should force a refresh.
func (m *Manager) RefreshOn(status int) bool {
	for _, s := range m.provider.Refresh.OnStatus {
		if s == status {
			return true
		}
	}
	return false
}

// ForceRefresh renews role's token after the target rejected staleHeader.
// Concurrent callers that saw the same stale token trigger one refresh; a
// caller whose stale value was already replaced returns true immediately.
// Returns whether a usable newer token is now in place.
func (m *Manager) ForceRefresh(ctx context.Context, role, staleHeader string) bool {
	rs := m.role(role)
	if rs == nil {
		return false
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.tok != nil && staleHeader != "" && rs.tok.HeaderValue != staleHeader {
		return true // someone else already refreshed
	}
	return m.refreshLocked(ctx, rs) == nil
}

// refreshLocked performs one refresh; rs.mu must be held.
func (m *Manager) refreshLocked(ctx context.Context, rs *roleState) error {
	tok, err := m.client.Refresh(ctx, m.provider, rs.profile, rs.tok)
	if err != nil {
		rs.failures++
		rs.lastErr = err
		if m.hooks.OnError != nil {
			m.hooks.OnError(rs.role, err, rs.failures >= MaxFailures)
		}
		return err
	}
	rs.tok = tok
	rs.refreshes++
	rs.failures = 0
	rs.lastErr = nil
	if m.hooks.OnToken != nil {
		m.hooks.OnToken(rs.role, tok)
	}
	return nil
}

func (m *Manager) nextWait(rs *roleState) time.Duration {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.failures > 0 {
		i := rs.failures - 1
		if i >= len(m.backoff) {
			i = len(m.backoff) - 1
		}
		return m.backoff[i]
	}
	if rs.tok == nil {
		return m.minWait
	}
	now := m.client.now()
	lifetime := rs.tok.Expiry.Sub(rs.tok.ObtainedAt)
	before := time.Duration(m.provider.Refresh.BeforeExpirySeconds) * time.Second
	if before >= lifetime { // very short-lived tokens: refresh at half-life
		before = lifetime / 2
	}
	wait := rs.tok.Expiry.Add(-before).Sub(now)
	if wait < m.minWait {
		wait = m.minWait
	}
	return wait
}

func (m *Manager) loop(ctx context.Context, rs *roleState) {
	defer m.wg.Done()
	for {
		t := time.NewTimer(m.nextWait(rs))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		rs.mu.Lock()
		rctx, cancel := context.WithTimeout(ctx, 2*requestTimeout)
		_ = m.refreshLocked(rctx, rs)
		cancel()
		rs.mu.Unlock()
	}
}

// Status reports each role's state.
func (m *Manager) Status() []RoleStatus {
	out := make([]RoleStatus, 0, len(m.roles))
	now := m.client.now()
	for _, rs := range m.roles {
		rs.mu.Lock()
		st := RoleStatus{Role: rs.role, Profile: rs.profile, Refreshes: rs.refreshes, Failures: rs.failures}
		if rs.tok != nil {
			st.Expiry = rs.tok.Expiry
			st.ObtainedAt = rs.tok.ObtainedAt
			st.Valid = rs.tok.Expiry.After(now) && rs.failures < MaxFailures
			st.TokenPreview = MaskToken(rs.tok.Value)
		}
		if rs.lastErr != nil {
			st.LastError = rs.lastErr.Error()
		}
		rs.mu.Unlock()
		out = append(out, st)
	}
	return out
}
