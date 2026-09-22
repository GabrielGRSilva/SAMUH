package analyzer

import (
	"fmt"
	"strings"
	"sync"
)

// Registry manages the available language analyzers.
// It is safe for concurrent use.
type Registry struct {
	mu        sync.RWMutex
	analyzers map[string]Analyzer
	extMap    map[string]string // extension -> analyzer name
}

// NewRegistry creates a new empty analyzer registry.
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[string]Analyzer),
		extMap:    make(map[string]string),
	}
}

// Register adds an analyzer to the registry.
// It returns an error if an analyzer with the same name is already registered.
func (r *Registry) Register(a Analyzer) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := strings.ToLower(a.Name())
	if _, exists := r.analyzers[name]; exists {
		return fmt.Errorf("analyzer %q is already registered", name)
	}

	r.analyzers[name] = a
	for _, ext := range a.Extensions() {
		ext = strings.ToLower(ext)
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		r.extMap[ext] = name
	}
	return nil
}

// GetByName returns the analyzer with the given name.
func (r *Registry) GetByName(name string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	a, ok := r.analyzers[strings.ToLower(name)]
	return a, ok
}

// GetByExtension returns the analyzer registered for the given file extension.
func (r *Registry) GetByExtension(ext string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name, ok := r.extMap[ext]
	if !ok {
		return nil, false
	}
	return r.analyzers[name], true
}

// All returns all registered analyzers.
func (r *Registry) All() []Analyzer {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Analyzer, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		result = append(result, a)
	}
	return result
}

// Names returns the names of all registered analyzers.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]string, 0, len(r.analyzers))
	for name := range r.analyzers {
		result = append(result, name)
	}
	return result
}

// DefaultRegistry creates a registry with all built-in analyzers pre-registered.
// Language-specific analyzers register themselves via this function.
func DefaultRegistry() *Registry {
	r := NewRegistry()
	// Built-in analyzers are registered by their init() functions
	// via RegisterDefault(). See each analyzer package.
	for _, a := range defaultAnalyzers {
		_ = r.Register(a)
	}
	return r
}

var (
	defaultMu        sync.Mutex
	defaultAnalyzers []Analyzer
)

// RegisterDefault adds an analyzer to the list of defaults.
// This is typically called from init() functions in analyzer packages.
func RegisterDefault(a Analyzer) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	defaultAnalyzers = append(defaultAnalyzers, a)
}
