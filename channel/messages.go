package channel

import (
	plan "github.com/plan-tools/permissions-model/plan"
	ski "github.com/plan-tools/permissions-model/ski"
)

// Author is a parameter of information passed to channel operations so that it
// can find the appropriate public keys to pass along to the SKI for encryption
// and signing operations. This is mostly so we're not passing along huge lists
// of parameters.
type Author struct {
	Addr           plan.IdentityAddr
	SKI            *ski.SKI
	EncryptKey     plan.IdentityPublicKey
	SigningKey     plan.IdentityPublicKey
	CommunityKeyID plan.CommunityKeyID
}

// VouchPackage is a parameter of information that would be sent out-of-band to
// new members of the community.
type VouchPackage struct {
	EncryptKey plan.IdentityPublicKey
	SigningKey plan.IdentityPublicKey
	EntryID    int
}
