package user

import (
	"encoding/json"
	"fmt"
	"sync"

	plan "github.com/plan-tools/go-plan/plan"
	channel "github.com/plan-tools/permissions-model/channel"
	pdi "github.com/plan-tools/permissions-model/pdi"
	ski "github.com/plan-tools/permissions-model/ski"
)

// User represents the individual pnode (and the client software)
type User struct {
	Name     string
	Addr     plan.IdentityAddr
	Channels map[plan.ChannelID]*channel.Channel // local pnode data stores
	SKI      *ski.SKI                            // the user's out-of-process key store
	PDI      *pdi.PDI                            // out-of-process distributed data store
	mux      sync.RWMutex                        // synchronizes channel access
}

// Create a new User and initialize their first keychain.
func NewUser(name string, pdi *pdi.PDI) (*User, plan.IdentityPublicKey) {
	user := &User{
		Name:     name,
		Channels: map[plan.ChannelID]*channel.Channel{},
		SKI:      ski.NewSKI(),
		PDI:      pdi,
	}
	encryptPubKey, signingPubKey := user.SKI.NewIdentity()
	err := user.SKI.SetIdentity(
		plan.AccessChannelID(plan.RootAccessChannel), encryptPubKey, signingPubKey)
	if err != nil {
		panic(err) // TODO: handle gracefully
	}
	var arr [20]byte
	copy(arr[:], signingPubKey[:20])
	user.Addr = arr
	return user, signingPubKey
}

// implements the Stringer interface for pretty printing
func (u *User) String() string {
	return fmt.Sprintf("%v (%#02x)", u.Name, u.Addr)
}

// Pop fetches the next entry from the PDI, uses the SKI to decrypt the
// header, and dispatches it to the appropriate channel for local storage.
// Returns the channel ID it was dispatched to as well as rev on that
// channel so that the caller can find it later if it wants
func (u *User) Pop() (plan.ChannelID, uint32, error) {
	var (
		chanId  plan.ChannelID
		entryId uint32
	)
	entryCrypt, err := u.PDI.Peek(u.Addr)
	if err != nil {
		return chanId, entryId, err
	}
	header, headerBuf, err := u.unpackHeader(entryCrypt)
	if err != nil {
		return chanId, entryId, err
	}
	err = u.validateHeader(header, *entryCrypt.Hash, entryCrypt.Sig)
	if err != nil {
		return chanId, entryId, err
	}
	// note: BodyBuf and Body are still at their zero-values
	entry := &plan.PDIEntry{
		PDIEntryCrypt: entryCrypt,
		HeaderBuf:     headerBuf,
		Header:        header,
	}
	chanId = header.ChannelID
	ch, ok := u.Channels[chanId]
	if !ok {
		ch = &channel.Channel{}
		u.Channels[chanId] = ch
	}
	entryId = ch.Store(entry)
	return chanId, entryId, nil
}

// internal: unpack header
//   decrypts and deserializes the header
func (u *User) unpackHeader(entryCrypt *plan.PDIEntryCrypt) (
	*plan.PDIEntryHeader, []byte, error) {
	headerBuf, err := u.SKI.XDecrypt(
		entryCrypt.CommunityKeyID,
		entryCrypt.HeaderCrypt)
	if err != nil {
		return nil, []byte{}, err
	}
	var header *plan.PDIEntryHeader
	err = json.Unmarshal(headerBuf, header)
	if err != nil {
		return nil, headerBuf, err
	}
	return header, headerBuf, err
}

// internal: validateHeader
//   before we write to the pnode, we need to verify the author is
//   valid and that they had permissions to write. note that because
//   permissions are immutable at a point in time, it doesn't matter
//   when we check permissions if they're changed later -- they'll
//   always be the same for an entry at a specific point in time
func (u *User) validateHeader(
	header *plan.PDIEntryHeader,
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
) error {
	author, err := u.getAuthor(header)
	if err != nil {
		return err
	}
	err = u.verifySignature(hash, sig, author.SigningPublicKey)
	if err != nil {
		return err
	}
	err = u.checkPermissions(author.Permissions)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) getAuthor(
	header *plan.PDIEntryHeader) (*channel.AccessChannelKeyEntry, error) {
	ch := u.Channels[plan.ChannelID(header.AccessChannelID)]
	ac := &channel.AccessChannel{
		Channel: ch,
	}
	author, err := ac.GetUser(header.AccessChannelRev, header.Author)
	if err != nil {
		return &channel.AccessChannelKeyEntry{}, err
	}
	return author, nil
}

func (u *User) verifySignature(
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
	signingKey plan.IdentityPublicKey) error {
	_, ok := u.SKI.Verify(signingKey, hash, sig)
	if !ok {
		return plan.Error(-1, "invalid signature")
	}
	return nil
}

// TODO
func (u *User) checkPermissions(permissions int) error {
	return nil
}

func (u *User) Push(*plan.PDIEntryCrypt) error {
	return nil
}
