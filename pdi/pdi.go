package pdi

import (
	"sync"

	plan "github.com/plan-tools/go-plan/plan"
)

// PDI represents the distributed persistent store for this demo.
// Callers in the demo will "connect" to pull an ordered queue of
// entries or push new entries to the same instance of PDI
type PDI struct {
	Entries []*plan.PDIEntryCrypt
	clients map[int]int // map of pnode client IDs to their current position
	mux     sync.RWMutex
}

func NewPDI() *PDI {
	return &PDI{
		Entries: []*plan.PDIEntryCrypt{},
		clients: map[int]int{},
	}
}

// Connect sets up the internal queue we need for the demo. The clientID
// here has to be unique across pnodes, but in the real implementation
// this would be over a unix socket or similar to the local PDI agent.
func (p *PDI) Connect(clientID int) {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.clients[clientID] = 0
}

// Push appends a new entry to the PDI
func (p *PDI) Push(entry *plan.PDIEntryCrypt) uint32 {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.Entries = append(p.Entries, entry)
	return uint32(len(p.Entries) - 1)
}

// Peek gets the next entry that a client hasn't seen and updates
// internal state so that subsequent calls to Peek will get the
// next entry.
func (p *PDI) Peek(clientID int) (*plan.PDIEntryCrypt, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	pos, ok := p.clients[clientID]
	if !ok {
		return nil, plan.Error(-1, "client never called PDI.Connect")
	}
	if len(p.Entries) < pos+1 {
		return nil, plan.Error(-1, "entry out of range")
	}
	p.clients[clientID] = pos + 1
	return p.Entries[pos], nil
}

// Get fetches a specific entry by index
func (p *PDI) Get(pos int) (*plan.PDIEntryCrypt, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	if len(p.Entries) < pos+1 {
		return nil, plan.Error(-1, "entry out of range")
	}
	return p.Entries[pos], nil
}

// SetClientIndex changes the position of the client but
// does not get any new data
func (p *PDI) SetClientIndex(clientID, pos int) error {
	p.mux.Lock()
	defer p.mux.Unlock()
	_, ok := p.clients[clientID]
	if !ok {
		return plan.Error(-1, "client never called PDI.Connect")
	}
	if len(p.Entries) < pos+1 {
		return plan.Error(-1, "position out of range")
	}
	p.clients[clientID] = pos
	return nil
}
