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

	alice, aliceEncryptKey, aliceVerifyKey := NewUser("alice")
	alicePnode := NewPnode(1, PDI)
	alice.Login(alicePnode)
	fmt.Println(alice)

	communityKeyID := alice.SKI.NewCommunityKey()

	aliceAuthor := &channel.Author{
		Addr:           alice.Addr,
		SKI:            alice.SKI,
		EncryptKey:     aliceEncryptKey,
		SigningKey:     aliceVerifyKey,
		CommunityKeyID: communityKeyID,
	}
	err := ch.WriteVouchFor(aliceAuthor, aliceEncryptKey)
	if err != nil {
		t.Fatal(err)
	}

	bob, bobEncryptKey, _ := NewUser("bob")
	bobPnode := NewPnode(2, PDI)
	bob.Login(bobPnode)
	fmt.Println(bob)

	err = ch.WriteVouchFor(aliceAuthor, bobEncryptKey)
	if err != nil {
		t.Fatal(err)
	}

	// Bob gets the following out-of-band:
	// - ID of Alice's key
	// - rev of root chan
	vouchPkg := &channel.VouchPackage{
		EncryptKey: aliceEncryptKey,
		SigningKey: aliceVerifyKey,
		EntryID:    1,
	}
	err = ch.AcceptVouch(bob.SKI, bobEncryptKey, vouchPkg)
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
