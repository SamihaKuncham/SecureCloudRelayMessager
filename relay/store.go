package main

import (
	"crypto/rsa"
	"sync"
)

type RelayStore struct {
	mu               sync.RWMutex
	publicKeys       map[string]*rsa.PublicKey
	pseudonyms       map[string]string
	bufferedMessages map[string][]string
}

func NewRelayStore() *RelayStore {
	return &RelayStore{
		publicKeys:       make(map[string]*rsa.PublicKey),
		pseudonyms:       make(map[string]string),
		bufferedMessages: make(map[string][]string),
	}
}

func (s *RelayStore) GetPublicKey(username string) (*rsa.PublicKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pub, ok := s.publicKeys[username]
	return pub, ok
}

func (s *RelayStore) SetPublicKey(username string, pub *rsa.PublicKey) {
	if pub == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.publicKeys[username] = pub
}

func (s *RelayStore) SetPseudonym(username, pseudonym string) {
	if pseudonym == "" {
		pseudonym = username
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pseudonyms[username] = pseudonym
}

func (s *RelayStore) GetPseudonym(username string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pseudonym := s.pseudonyms[username]
	if pseudonym == "" {
		return username
	}
	return pseudonym
}

func (s *RelayStore) BufferMessage(recipient, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bufferedMessages[recipient] = append(s.bufferedMessages[recipient], message)
}

func (s *RelayStore) DrainBufferedMessages(recipient string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	messages := s.bufferedMessages[recipient]
	if len(messages) == 0 {
		return nil
	}
	delete(s.bufferedMessages, recipient)
	out := make([]string, len(messages))
	copy(out, messages)
	return out
}