package channel

import (
	"fmt"
	"testing"

	plan "github.com/plan-tools/go-plan/plan"
	user "github.com/plan-tools/permissions-model/user"
)

func TestBootstrap(t *testing.T) {

	ch := setUpChannel(t)
	chanId := ch.Properties.OwningAccessChannelID

	alice, alicePubKey := user.NewUser("alice", chanId)
	fmt.Println(alice)

	aliceEncryptPubKey, aliceVerifyKey, err := alice.SKI.GetIdentity(chanId)
	if err != nil {
		t.Fatal(err)
	}
	if aliceVerifyKey != alicePubKey {
		t.Fatal("wtf")
	}

	err = ch.WriteVouchFor(alice, aliceVerifyKey)
	if err == nil {
		t.Fatal("should have failed because community key not created")
	}

	communityKeyID := alice.SKI.NewCommunityKey()
	err = alice.SKI.SetCommunityKey(chanId, communityKeyID)
	if err != nil {
		t.Fatal(err)
	}
	err = ch.WriteVouchFor(alice, aliceVerifyKey)
	if err != nil {
		t.Fatal(err)
	}

	bob, _ := user.NewUser("bob", chanId)
	fmt.Println(bob)

	bobEncryptPubKey, _, _ := bob.SKI.GetIdentity(chanId)

	err = ch.WriteVouchFor(alice, bobEncryptPubKey)
	if err != nil {
		t.Fatal(err)
	}

	// Bob gets the following out-of-band:
	// - ID of Alice's key
	// - rev of root chan

	err = ch.AcceptVouch(bob, aliceEncryptPubKey, aliceVerifyKey, 1)
	if err != nil {
		t.Fatal(err)
	}
}

// helper
func setUpChannel(t *testing.T) *Channel {
	ch := &Channel{
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
