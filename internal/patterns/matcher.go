package patterns

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Matcher provides pattern matching capabilities
type Matcher struct {
	mu         sync.RWMutex
	regexCache map[string]*regexp.Regexp
}

// NewMatcher creates a new pattern matcher
func NewMatcher() *Matcher {
	return &Matcher{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// MatchGlob checks if path matches glob pattern
func (m *Matcher) MatchGlob(pattern, path string) bool {
	matched, err := filepath.Match(pattern, path)
	return err == nil && matched
}

// MatchRegex checks if text matches regex pattern
func (m *Matcher) MatchRegex(pattern, text string) bool {
	m.mu.RLock()
	re, exists := m.regexCache[pattern]
	m.mu.RUnlock()

	if !exists {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}

		m.mu.Lock()
		m.regexCache[pattern] = re
		m.mu.Unlock()
	}

	return re.MatchString(text)
}

// MatchPrefix checks if path has given prefix
func (m *Matcher) MatchPrefix(prefix, path string) bool {
	return strings.HasPrefix(path, prefix)
}

// MatchSuffix checks if path has given suffix
func (m *Matcher) MatchSuffix(suffix, path string) bool {
	return strings.HasSuffix(path, suffix)
}

// MatchAny checks if path matches any pattern
func (m *Matcher) MatchAny(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if m.MatchGlob(pattern, path) {
			return true
		}
	}
	return false
}

// MatchContains checks if path contains substring
func (m *Matcher) MatchContains(substring, path string) bool {
	return strings.Contains(path, substring)
}

// ClearCache clears the regex cache
func (m *Matcher) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regexCache = make(map[string]*regexp.Regexp)
}

// Made with Bob
