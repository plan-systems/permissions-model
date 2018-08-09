package user

import (
	"fmt"

	plan "github.com/plan-tools/go-plan/plan"
	ski "github.com/plan-tools/permissions-model/ski"
)

type User struct {
	Name string
	Addr plan.IdentityAddr
	SKI  *ski.SKI
}

func (u User) String() string {
	return fmt.Sprintf("%v (%#02x)", u.Name, u.Addr)
}

// Create a new User and initialize their first keychain.
func NewUser(name string, chanId plan.AccessChannelID) (*User, plan.IdentityPublicKey) {
	user := &User{Name: name, SKI: ski.NewSKI()}

	encryptPubKey, signingPubKey := user.SKI.NewIdentity()
	err := user.SKI.SetIdentity(chanId, encryptPubKey, signingPubKey)

	if err != nil {
		panic(err) // TODO: handle this
	}
	var arr [20]byte
	copy(arr[:], signingPubKey[:20])
	user.Addr = arr
	return user, signingPubKey
}
