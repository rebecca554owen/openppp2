package auth

import (
	"sync"
	"time"
)

type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]time.Time
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]time.Time)}
}

func (s *TokenStore) Validate(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, exp := range s.tokens {
		if !exp.After(now) {
			delete(s.tokens, k)
		}
	}

	expiry, ok := s.tokens[token]
	return ok && expiry.After(now)
}

func (s *TokenStore) Add(token string, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token] = expiry
}

func (s *TokenStore) Remove(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, token)
}

func (s *TokenStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, expiry := range s.tokens {
		if !expiry.After(now) {
			delete(s.tokens, token)
		}
	}
}

func (s *TokenStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = make(map[string]time.Time)
}
