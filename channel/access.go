package channel

import (
	"encoding/json"

	plan "github.com/plan-tools/go-plan/plan"
)

type AccessChannel struct {
	Channel *Channel
}

func (ac *AccessChannel) GetRev(rev uint32) (*AccessChannelRevEntry, error) {
	entry, err := ac.Channel.Get(rev)
	if err != nil {
		return nil, err
	}
	buf := entry.Body.BodyParts[0].Body
	var revEntry *AccessChannelRevEntry
	err = json.Unmarshal(buf, revEntry)
	if err != nil {
		return nil, err
	}
	return revEntry, nil
}

func (ac *AccessChannel) GetUser(
	rev uint32, addr plan.IdentityAddr) (*AccessChannelKeyEntry, error) {
	revEntry, err := ac.GetRev(rev)
	if err != nil {
		return nil, err
	}
	member, ok := revEntry.Members[addr]
	if !ok {
		return nil, plan.Error(-1, "invalid address for access channel")
	}
	return member, nil
}

// TODO: not wild about the name here
// an AccessChannelRevEntry marks a revision of the access channel.
// other PDIEntry blocks will reference AccessChannelRevEntry to
// tell clients what CommunityKey to use and which identities have what
// authorizations for the channel.
type AccessChannelRevEntry struct {
	CommunityKeyID plan.CommunityKeyID
	Members        map[plan.IdentityAddr]*AccessChannelKeyEntry
}

// an AccessChannelKeyEntry is a user's public keys
type AccessChannelKeyEntry struct {
	SigningPublicKey    plan.IdentityPublicKey `json:"signing_key"`
	EncryptionPublicKey plan.IdentityPublicKey `json:"enc_key"`

	// TODO: this field should be some kind of bitmask to represent
	// the permissions that a user has for a given access channel
	Permissions int
}
