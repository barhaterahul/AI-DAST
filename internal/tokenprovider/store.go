package tokenprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store persists providers as a single JSON file (mode 0600, atomic writes).
type Store struct {
	mu        sync.RWMutex
	path      string
	providers map[string]*Provider
}

type storeFile struct {
	Version   int         `json:"version"`
	Providers []*Provider `json:"providers"`
}

// OpenStore loads (or initializes) the store at path.
func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, providers: map[string]*Provider{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("token provider store %s: %w", path, err)
	}
	for _, p := range f.Providers {
		if p == nil || !ValidID(p.ID) {
			continue
		}
		p.Normalize()
		s.providers[p.ID] = p
	}
	return s, nil
}

// List returns copies of all providers sorted by ID.
func (s *Store) List() []Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Provider, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, *clone(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a copy of the provider (nil if absent).
func (s *Store) Get(id string) *Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p := s.providers[id]
	if p == nil {
		return nil
	}
	return clone(p)
}

// Put validates and saves p (masked secrets keep their stored values).
func (s *Store) Put(p Provider) (*Provider, error) {
	p.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	p.MergeSecrets(s.providers[p.ID])
	if err := p.Validate(); err != nil {
		return nil, err
	}
	next := clone(&p)
	prev := s.providers[p.ID]
	s.providers[p.ID] = next
	if err := s.saveLocked(); err != nil {
		if prev != nil {
			s.providers[p.ID] = prev
		} else {
			delete(s.providers, p.ID)
		}
		return nil, err
	}
	return clone(next), nil
}

// Delete removes a provider. Reports whether it existed.
func (s *Store) Delete(id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.providers[id]
	if !ok {
		return false, nil
	}
	delete(s.providers, id)
	if err := s.saveLocked(); err != nil {
		s.providers[id] = prev
		return false, err
	}
	return true, nil
}

func (s *Store) saveLocked() error {
	f := storeFile{Version: 1}
	ids := make([]string, 0, len(s.providers))
	for id := range s.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f.Providers = append(f.Providers, s.providers[id])
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".token_providers-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

// clone deep-copies a provider via JSON (secrets included).
func clone(p *Provider) *Provider {
	b, _ := json.Marshal(p)
	var out Provider
	_ = json.Unmarshal(b, &out)
	return &out
}
