package pdi

import (
	"testing"

	plan "github.com/plan-tools/go-plan/plan"
)

// because we're just smoke testing the error handling,
// we'll use the Info field as a hacky unique ID for this test
func entryId(id int8) plan.PDIEntryInfo {
	return plan.PDIEntryInfo([4]byte{0, 0, 0, byte(id)})
}

// quick and dirty smoke test of our PDI dummy behavior
func TestPDI(t *testing.T) {

	// dummy client IDs
	var (
		alice = plan.IdentityAddr{1}
		bob   = plan.IdentityAddr{2}
	)
	pdi := NewPDI()

	// unconnected clients don't work
	entry1 := &plan.PDIEntryCrypt{Info: entryId(1)}
	pdi.Push(entry1)
	_, err := pdi.Peek(alice)
	if err == nil {
		t.Fatal("expected error from unconnected client")
	}
	pdi.Connect(alice)
	pdi.Connect(bob)

	// verify connected clients can see first entry
	entry, err := pdi.Peek(alice)
	if err != nil || entry.Info != entryId(1) {
		t.Fatal(err)
	}
	entry, err = pdi.Peek(bob)
	if err != nil || entry.Info != entryId(1) {
		t.Fatal(err)
	}

	// clients can't go off end of the bounds
	entry, err = pdi.Peek(bob)
	if err == nil {
		t.Fatal("expected error from exceeding bounds")
	}

	// add another entry; both Alice and Bob should see it
	entry2 := &plan.PDIEntryCrypt{Info: entryId(2)}
	pdi.Push(entry2)
	entry, err = pdi.Peek(alice)
	if err != nil || entry.Info != entryId(2) {
		t.Fatal(err)
	}
	entry, err = pdi.Peek(bob)
	if err != nil || entry.Info != entryId(2) {
		t.Fatal(err)
	}

	// resetting client should move next peek
	err = pdi.SetClientIndex(bob, 0)
	if err != nil {
		t.Fatal(err)
	}
	entry, err = pdi.Peek(bob)
	if err != nil || entry.Info != entryId(1) {
		t.Fatal(err)
	}

}
