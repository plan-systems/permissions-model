package user

import (
	"fmt"

	plan "github.com/plan-tools/permissions-model/plan"
	ski "github.com/plan-tools/permissions-model/ski"
)

// User represents the client software
type User struct {
	Name  string
	Addr  plan.IdentityAddr
	SKI   *ski.SKI // the user's out-of-process key store
	Pnode *Pnode   // the local pnode data store
}

// Create a new User and initialize their first keychain. Returns the first
// set of encryption and signing public keys for convenience.
func NewUser(name string) (*User, plan.IdentityPublicKey, plan.IdentityPublicKey) {
	user := &User{
		Name: name,
		SKI:  ski.NewSKI(),
	}
	encryptPubKey, signingPubKey := user.SKI.NewIdentity()
	var arr [20]byte
	copy(arr[:], signingPubKey[:20])
	user.Addr = arr
	return user, encryptPubKey, signingPubKey
}

// implements the Stringer interface for pretty printing
func (u *User) String() string {
	return fmt.Sprintf("%v (%#02x)", u.Name, u.Addr)
}

// Login is a standin for the client software logging into the Pnode,
// which is what allows the Pnode access to the User's SKI.
func (u *User) Login(p *Pnode) {
	u.Pnode = p
	p.Login(u)
}
