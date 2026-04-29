package main

import (
	"sync"
	"time"
)

// PacketType indicates whether this is a request or response
type PacketType string

const (
	PacketRequest  PacketType = "request"
	PacketResponse PacketType = "response"
)

// CapturedPacket represents a captured HTTP request or response
type CapturedPacket struct {
	ID          int               `json:"id"`
	Type        PacketType        `json:"type"`
	Timestamp   time.Time         `json:"timestamp"`
	Method      string            `json:"method,omitempty"`
	URL         string            `json:"url,omitempty"`
	Host        string            `json:"host,omitempty"`
	Status      string            `json:"status,omitempty"`
	StatusCode  int               `json:"statusCode,omitempty"`
	ContentType string            `json:"contentType"`
	BodySize    int               `json:"bodySize"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	Protocol    string            `json:"protocol"`
	Connection  string            `json:"connection"`
	PairKey     string            `json:"pairKey"`
}

// PacketPair represents a correlated request/response pair
type PacketPair struct {
	ID        int             `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	Request   *CapturedPacket `json:"request,omitempty"`
	Response  *CapturedPacket `json:"response,omitempty"`
}

// PacketStore holds captured packets in memory
type PacketStore struct {
	mu       sync.RWMutex
	packets  []CapturedPacket
	pairs    map[string]*PacketPair
	pairList []*PacketPair
	maxSize  int
	nextID   int
	nextPair int
}

// Global packet store
var Store = NewPacketStore(500)

// NewPacketStore creates a new packet store with a maximum size
func NewPacketStore(maxSize int) *PacketStore {
	return &PacketStore{
		packets:  make([]CapturedPacket, 0),
		pairs:    make(map[string]*PacketPair),
		pairList: make([]*PacketPair, 0),
		maxSize:  maxSize,
		nextID:   1,
		nextPair: 1,
	}
}

// Add adds a new packet to the store
func (s *PacketStore) Add(p CapturedPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.ID = s.nextID
	s.nextID++

	s.packets = append(s.packets, p)

	// Track request/response pairs. A PairKey collision where the matching
	// slot is already filled means we're seeing a new req/res on a reused
	// 4-tuple (e.g. localhost connection churn resets per-stream seq to 0) —
	// start a fresh pair instead of overwriting and losing the prior packet.
	if p.PairKey != "" {
		pair, exists := s.pairs[p.PairKey]
		slotOccupied := exists && ((p.Type == PacketRequest && pair.Request != nil) ||
			(p.Type == PacketResponse && pair.Response != nil))
		if !exists || slotOccupied {
			pair = &PacketPair{
				ID:        s.nextPair,
				Timestamp: p.Timestamp,
			}
			s.nextPair++
			s.pairs[p.PairKey] = pair
			s.pairList = append(s.pairList, pair)
		}
		if p.Type == PacketRequest {
			pair.Request = &p
		} else {
			pair.Response = &p
		}
	}

	// Trim old packets if we exceed maxSize
	if len(s.packets) > s.maxSize {
		s.packets = s.packets[len(s.packets)-s.maxSize:]
	}

	// Trim old pairs
	if len(s.pairList) > s.maxSize {
		// Remove old pairs from map — but only if the map still points to
		// this exact pair. A newer pair with the same PairKey may have
		// replaced it, and we must not evict that newer pair.
		for _, oldPair := range s.pairList[:len(s.pairList)-s.maxSize] {
			var key string
			if oldPair.Request != nil {
				key = oldPair.Request.PairKey
			} else if oldPair.Response != nil {
				key = oldPair.Response.PairKey
			}
			if mapped, ok := s.pairs[key]; ok && mapped == oldPair {
				delete(s.pairs, key)
			}
		}
		s.pairList = s.pairList[len(s.pairList)-s.maxSize:]
	}
}

// GetAll returns all captured packets (newest first)
func (s *PacketStore) GetAll() []CapturedPacket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Return a copy in reverse order (newest first)
	result := make([]CapturedPacket, len(s.packets))
	for i, p := range s.packets {
		result[len(s.packets)-1-i] = p
	}
	return result
}

// GetPairs returns all packet pairs (newest first)
func (s *PacketStore) GetPairs() []PacketPair {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]PacketPair, len(s.pairList))
	for i, p := range s.pairList {
		result[len(s.pairList)-1-i] = *p
	}
	return result
}

// Clear removes all packets from the store
func (s *PacketStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packets = make([]CapturedPacket, 0)
	s.pairs = make(map[string]*PacketPair)
	s.pairList = make([]*PacketPair, 0)
}

// Count returns the number of stored packets
func (s *PacketStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.packets)
}
