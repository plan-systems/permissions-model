package user

import (
	"fmt"
	"testing"

	plan "github.com/plan-tools/go-plan/plan"
	channel "github.com/plan-tools/permissions-model/channel"
	pdi "github.com/plan-tools/permissions-model/pdi"
)

func TestBootstrap(t *testing.T) {

	PDI := pdi.NewPDI()

	ch := setUpChannel(t)
	chanId := ch.Properties.OwningAccessChannelID

	alice, alicePubKey := NewUser("alice", PDI)
	fmt.Println(alice)

	aliceEncryptPubKey, aliceVerifyKey, err := alice.SKI.GetIdentity(chanId)
	if err != nil {
		t.Fatal(err)
	}
	if aliceVerifyKey != alicePubKey {
		t.Fatal("wtf")
	}

	err = ch.WriteVouchFor(alice.Addr, alice.SKI, aliceVerifyKey)
	if err == nil {
		t.Fatal("should have failed because community key not created")
	}

	communityKeyID := alice.SKI.NewCommunityKey()
	err = alice.SKI.SetCommunityKey(chanId, communityKeyID)
	if err != nil {
		t.Fatal(err)
	}
	err = ch.WriteVouchFor(alice.Addr, alice.SKI, aliceVerifyKey)
	if err != nil {
		t.Fatal(err)
	}

	bob, _ := NewUser("bob", PDI)
	fmt.Println(bob)

	bobEncryptPubKey, _, _ := bob.SKI.GetIdentity(chanId)

	err = ch.WriteVouchFor(alice.Addr, alice.SKI, bobEncryptPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Bob gets the following out-of-band:
	// - ID of Alice's key
	// - rev of root chan

	err = ch.AcceptVouch(bob.SKI, aliceEncryptPubKey, aliceVerifyKey, 1)
	if err != nil {
		t.Fatal(err)
	}
}

// helper
func setUpChannel(t *testing.T) *channel.Channel {
	ch := &channel.Channel{
		Properties: &plan.ChannelProperties{
			Author:                 plan.IdentityAddr{},
			IsAccessChannel:        true,
			EntriesAreFinal:        false,
			ChannelID:              plan.RootAccessChannel,
			OwningAccessChannelID:  plan.AccessChannelID(plan.RootAccessChannel),
			OwningAccessChannelRev: 0,
		},
	}
	return ch
}
