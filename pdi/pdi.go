package pdi

import (
	"sync"

	plan "github.com/plan-tools/permissions-model/plan"
)

// PDI represents the distributed persistent store for this demo.
// Callers in the demo can peek from the ordered queue of entries
// or push new entries to the same instance of PDI
type PDI struct {
	Entries []*plan.PDIEntryCrypt
	mux     sync.RWMutex
}

func NewPDI() *PDI {
	return &PDI{
		Entries: []*plan.PDIEntryCrypt{},
	}
}

// Push appends a new entry to the PDI and returns the index of the
// new entry.
func (p *PDI) Push(entry *plan.PDIEntryCrypt) uint32 {
	p.mux.Lock()
	defer p.mux.Unlock()
	p.Entries = append(p.Entries, entry)
	return uint32(len(p.Entries) - 1)
}

// Peek gets an entry for the client by index; the client is responsible
// for maintaining its own position so that subsequent calls to Peek will
// get the next entry.
func (p *PDI) Peek(pos int) (*plan.PDIEntryCrypt, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	if len(p.Entries) < pos+1 {
		return nil, plan.Error(-1, "entry out of range")
	}
	return p.Entries[pos], nil
}
