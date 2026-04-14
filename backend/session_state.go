package backend

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"
)

// SessionRegistry is process-wide (one per *Backend) and tracks clients +
// sessions across connection drops. It is the authority for clientid
// uniqueness and slot replay protection per RFC 8881 §2.10.6.
type SessionRegistry struct {
	mu        sync.Mutex
	nextClid  uint64
	clients   map[uint64]*ClientRecord
	sessions  map[[16]byte]*SessionRecord
	ownerToId map[string]uint64 // co_ownerid -> clientid for re-exchange
}

// ChannelAttrs mirrors the NFSv4.1 channel_attrs4 negotiated in CREATE_SESSION.
type ChannelAttrs struct {
	HeaderPad    uint32
	MaxReq       uint32
	MaxResp      uint32
	MaxRespCache uint32
	MaxOps       uint32
	MaxReqs      uint32
}

// ClientRecord tracks a single NFSv4.1 client across reconnects.
type ClientRecord struct {
	Id        uint64
	Owner     []byte
	Verifier  [8]byte
	Confirmed bool
	Created   time.Time
	LastSeen  time.Time
}

// SlotState is one entry in a session's slot table. The single-slot
// configuration we advertise means each session has exactly one of these.
type SlotState struct {
	Mu       sync.Mutex
	SeqId    uint32
	Cached   []byte
	CacheHit bool
}

// SessionRecord is the per-session state created by CREATE_SESSION.
type SessionRecord struct {
	Id       [16]byte
	ClientId uint64
	Created  time.Time
	ForeAttr ChannelAttrs
	BackAttr ChannelAttrs
	Slots    []SlotState
}

// NewSessionRegistry constructs an empty registry ready for use.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		nextClid:  0,
		clients:   make(map[uint64]*ClientRecord),
		sessions:  make(map[[16]byte]*SessionRecord),
		ownerToId: make(map[string]uint64),
	}
}

// ExchangeId implements the EXCHANGE_ID identity-establishment semantics.
// Returns (record, reused). If the same owner+verifier is seen, the existing
// record is reused. If the owner is known but the verifier differs, the old
// client is treated as rebooted: its sessions are dropped and a fresh
// clientid is allocated.
func (r *SessionRegistry) ExchangeId(owner []byte, verif [8]byte) (*ClientRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	key := string(owner)
	if existingId, ok := r.ownerToId[key]; ok {
		existing := r.clients[existingId]
		if existing != nil && existing.Verifier == verif {
			existing.LastSeen = now
			return existing, true
		}
		// Reboot: drop old client + cascade sessions.
		r.dropClientLocked(existingId)
	}

	r.nextClid++
	id := r.nextClid
	ownerCopy := make([]byte, len(owner))
	copy(ownerCopy, owner)
	rec := &ClientRecord{
		Id:        id,
		Owner:     ownerCopy,
		Verifier:  verif,
		Confirmed: false,
		Created:   now,
		LastSeen:  now,
	}
	r.clients[id] = rec
	r.ownerToId[key] = id
	return rec, false
}

// ConfirmClient marks a client confirmed (the first CREATE_SESSION call
// confirms it per RFC 8881 §18.36.3).
func (r *SessionRegistry) ConfirmClient(id uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[id]
	if !ok {
		return fmt.Errorf("unknown clientid %d", id)
	}
	c.Confirmed = true
	c.LastSeen = time.Now()
	return nil
}

// CreateSession allocates a fresh session for a confirmed client.
func (r *SessionRegistry) CreateSession(clientId uint64, fore, back ChannelAttrs) (*SessionRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.clients[clientId]
	if !ok {
		return nil, errors.New("stale clientid")
	}
	if !c.Confirmed {
		return nil, errors.New("clientid not confirmed")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	sess := &SessionRecord{
		Id:       id,
		ClientId: clientId,
		Created:  time.Now(),
		ForeAttr: fore,
		BackAttr: back,
		Slots:    make([]SlotState, 1),
	}
	r.sessions[id] = sess
	c.LastSeen = sess.Created
	return sess, nil
}

// LookupSession returns the session record for the given id, if any.
func (r *SessionRegistry) LookupSession(id [16]byte) (*SessionRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[id]
	return s, ok
}

// DestroySession is idempotent: dropping an unknown session is not an error.
func (r *SessionRegistry) DestroySession(id [16]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
	return nil
}

// DestroyClient is idempotent and cascades: every session belonging to the
// client is removed first.
func (r *SessionRegistry) DestroyClient(id uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dropClientLocked(id)
	return nil
}

// dropClientLocked removes the client and all of its sessions. Caller holds r.mu.
func (r *SessionRegistry) dropClientLocked(id uint64) {
	c, ok := r.clients[id]
	if !ok {
		return
	}
	for sid, s := range r.sessions {
		if s.ClientId == id {
			delete(r.sessions, sid)
		}
	}
	delete(r.ownerToId, string(c.Owner))
	delete(r.clients, id)
}
