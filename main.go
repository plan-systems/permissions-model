package main

import (
	"fmt"

	plan "github.com/plan-tools/go-plan/plan"
	channel "github.com/plan-tools/permissions-model/channel"
	pdi "github.com/plan-tools/permissions-model/pdi"
	user "github.com/plan-tools/permissions-model/user"
)

// we need this cast a lot
var rootAccessChannelID = plan.AccessChannelID(plan.RootAccessChannel)

func main() {

	PDI := pdi.NewPDI()

	// Alice bootstraps the community. Note that we need to create
	// at least the root ChannelID before we can create our first user

	// Alice creates herself and generates her own keypairs
	alice, aliceEncryptKey, aliceSigningKey := user.NewUser("alice")
	alicePnode := user.NewPnode(1, PDI)
	alice.Login(alicePnode)
	fmt.Printf("new user: %v\n", alice)

	// Alice creates the first community key
	communityKeyID := alice.SKI.NewCommunityKey()

	// Alice now can create the root access channel
	rootChannel := &channel.Channel{
		Properties: &plan.ChannelProperties{
			Author:                 alice.Addr,
			IsAccessChannel:        true,
			EntriesAreFinal:        false,
			ChannelID:              plan.RootAccessChannel,
			OwningAccessChannelID:  rootAccessChannelID,
			OwningAccessChannelRev: 0,
		},
	}
	fmt.Printf("root channel: %+v\n", rootChannel.Properties)

	// An access channel has 2 entry types:
	// - a KeyEntry, which is a copy of the CommunityKey, encrypted for one
	//   of the users with permissions to the controlled channel
	// - a ReferenceEntry, which includes:
	//   1. the current CommunityKeyID for the access channel
	//   2. a map of addresses / public keys to the KeyEntries. the keys
	//      of this map also act as references into the global membership
	//      registry channel.

	// TODO: not sure this is accurate anymore?

	// START NEEDS WORK

	// Therefore, to bootstrap the root access channel we need a self-signed
	// genesis block. This genesis entry ("rev 0") is a ReferenceEntry which
	// contains only Alice's address/public key and the CommunityKeyID.

	// Note that the genesis entry does not include the community key itself!
	// We only need that once we're ready to add members.

	// When Alice invites new community members she'll include the fingerprint
	// of her public key so that new community members can bootstrap the trust
	// relationship

	// END NEEDS WORK

	aliceAuthor := &channel.Author{
		Addr:           alice.Addr,
		SKI:            alice.SKI,
		EncryptKey:     aliceEncryptKey,
		SigningKey:     aliceSigningKey,
		CommunityKeyID: communityKeyID,
	}

	fmt.Println("* alice writes genesis entry and vouches for herself")
	err := rootChannel.WriteVouchFor(aliceAuthor, aliceEncryptKey)
	if err != nil {
		panic(err) // TODO: this whole thing should be a test suite
	}

	// To bootstrap the rest of the community, Alice needs to:

	// - create the [rev 1] of the root access channel, which includes a
	//   reference to rev0
	// - create a membership registry channel
	// - add an entry for herself to the membership registry (this will use
	//   AccessChannelRev 1)

	// Alice creates a rev entry for the root access channel which includes
	// a references to the previous entry. Note: because Alice has her own
	// copy of the community key already, Alice only needs to do this once she
	// starts adding other members and she can wait to do this until she's
	// added them (but they won't be able to participate until she's done so).

	// rootRev2 := plan.PDIEntry{
	// 	Header: &plan.PDIEntryHeader{
	// 		Nonce:            <-ski.Nonces,
	// 		Time:             plan.Time(time.Now().Unix()),
	// 		Verb:             plan.PDIEntryVerbChannelAdmin,
	// 		ChannelID:        plan.RootAccessChannel,
	// 		Author:           alice.Addr,
	// 		AccessChannelID:  plan.AccessChannelID(plan.RootAccessChannel),
	// 		AccessChannelRev: 0, // need to be *signed* under rev0
	// 	},
	// 	Body: &plan.PDIEntryBody{
	// 		Nonce:     <-ski.Nonces,
	// 		BodyParts: []plan.PDIBodyPart{}, // TODO: need rev2 body here
	// 	},
	// }
	// fmt.Println(rootRev2) // TODO: persist entry

	// // Alice creates a membership registry and adds herself to it

	// memberChannel := &channel.Channel{
	// 	Properties: &plan.ChannelProperties{
	// 		Author:                 alice.Addr,
	// 		IsAccessChannel:        false,
	// 		EntriesAreFinal:        false,
	// 		ChannelID:              plan.MemberRegistryChannel,
	// 		OwningAccessChannelID:  rootAccessChannelID,
	// 		OwningAccessChannelRev: 0,
	// 	},
	// }
	// fmt.Println(memberChannel)

	// // TODO: add entry for Alice

	// // Alice creates the channel catalog. so far it has no entries

	// catalogChannel := &channel.Channel{
	// 	Properties: &plan.ChannelProperties{
	// 		Author:                 alice.Addr,
	// 		IsAccessChannel:        false,
	// 		EntriesAreFinal:        false,
	// 		ChannelID:              plan.ChannelCatalogChannel,
	// 		OwningAccessChannelID:  rootAccessChannelID,
	// 		OwningAccessChannelRev: 0,
	// 	},
	// }
	// fmt.Println(catalogChannel)

	bob, _, _ := user.NewUser("bob")
	bobPnode := user.NewPnode(2, PDI)
	bob.Login(bobPnode)
	fmt.Printf("new user: %v\n", bob)

	eve, _, _ := user.NewUser("eve")
	evePnode := user.NewPnode(3, PDI)
	eve.Login(evePnode)
	fmt.Printf("new user: %v\n", eve)

}
