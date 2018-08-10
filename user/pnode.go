package user

import (
	"encoding/json"
	"sync"

	plan "github.com/plan-tools/go-plan/plan"
	channel "github.com/plan-tools/permissions-model/channel"
	pdi "github.com/plan-tools/permissions-model/pdi"
)

// Pnode represents the individual pnode.
// TODO: these will want to be different packages because they're different
// processes entirely, but those processes will communicate over the wire
// and we didn't want to implement that for this demo.
type Pnode struct {
	ID       int                                 // unique ID for the Pnode (1:1 with User?)
	Channels map[plan.ChannelID]*channel.Channel // local pnode data stores
	PDI      *pdi.PDI                            // out-of-process distributed data store
	Session  *User                               // a logged-in client
	mux      sync.RWMutex                        // synchronizes channel access
}

// Create a new Pnode and initialize the empty channels.
func NewPnode(nodeId int, pdi *pdi.PDI) *Pnode {
	node := &Pnode{
		ID:       nodeId,
		Channels: map[plan.ChannelID]*channel.Channel{},
		PDI:      pdi,
	}
	return node
}

// Login is a standin for the client software logging into the Pnode,
// which is what allows the Pnode access to the User's SKI.
func (p *Pnode) Login(u *User) {
	p.Session = u
}

// Pop fetches the next entry from the PDI, uses the SKI to decrypt the
// header, and dispatches it to the appropriate channel for local storage.
// Returns the channel ID it was dispatched to as well as rev on that
// channel so that the caller can find it later if it wants
func (p *Pnode) Pop() (plan.ChannelID, uint32, error) {
	var (
		chanId  plan.ChannelID
		entryId uint32
	)
	entryCrypt, err := p.PDI.Peek(p.ID)
	if err != nil {
		return chanId, entryId, err
	}
	header, headerBuf, err := p.unpackHeader(entryCrypt)
	if err != nil {
		return chanId, entryId, err
	}
	err = p.validateHeader(header, *entryCrypt.Hash, entryCrypt.Sig)
	if err != nil {
		return chanId, entryId, err
	}
	entry := &plan.PDIEntry{
		PDIEntryCrypt: entryCrypt,
		HeaderBuf:     headerBuf,
		Header:        header,
	}
	chanId = header.ChannelID
	ch, ok := p.Channels[chanId]
	if !ok {
		ch = &channel.Channel{}
		p.Channels[chanId] = ch
	}
	entryId = ch.Store(entry)
	return chanId, entryId, nil
}

// Read and decrypt an entry stored on a channel. Note that because the pnode
// has previously decrypted and verified the header, we're only interested in
// decrypting the body and permissions are checked at the time they're popped
// off the PDI, not when they're read for the client.
func (p *Pnode) Read(chanId plan.ChannelID, entryId uint32) (
	*plan.PDIEntryBody, error) {
	if p.Session == nil {
		return nil, plan.Error(-1, "no logged in user")
	}
	ch, ok := p.Channels[chanId]
	if !ok {
		return nil, plan.Error(-1, "invalid channel")
	}
	entry, err := ch.Get(entryId)
	if err != nil {
		return nil, err
	}
	if entry.Body != nil {
		return entry.Body, nil
	}
	bodyBuf, err := p.Session.SKI.Decrypt(
		entry.PDIEntryCrypt.CommunityKeyID,
		entry.PDIEntryCrypt.BodyCrypt)
	if err != nil {
		return nil, err
	}
	var body *plan.PDIEntryBody
	err = json.Unmarshal(bodyBuf, body)
	if err != nil {
		return nil, err
	}
	// This implementation gives us the option of storing cleartext entries
	// on disk after they're initially read but let's assume for now we don't
	// entry.Body = body
	return body, nil
}

// internal: unpack header
//   decrypts and deserializes the header
func (p *Pnode) unpackHeader(entryCrypt *plan.PDIEntryCrypt) (
	*plan.PDIEntryHeader, []byte, error) {
	if p.Session == nil {
		return nil, []byte{}, plan.Error(-1, "no logged in user")
	}
	headerBuf, err := p.Session.SKI.Decrypt(
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
func (p *Pnode) validateHeader(
	header *plan.PDIEntryHeader,
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
) error {
	author, err := p.getAuthor(header)
	if err != nil {
		return err
	}
	err = p.verifySignature(hash, sig, author.SigningPublicKey)
	if err != nil {
		return err
	}
	err = p.checkPermissions(author.Permissions)
	if err != nil {
		return err
	}
	return nil
}

func (p *Pnode) getAuthor(
	header *plan.PDIEntryHeader) (*channel.AccessChannelKeyEntry, error) {
	ch := p.Channels[plan.ChannelID(header.AccessChannelID)]
	ac := &channel.AccessChannel{
		Channel: ch,
	}
	author, err := ac.GetUser(header.AccessChannelRev, header.Author)
	if err != nil {
		return &channel.AccessChannelKeyEntry{}, err
	}
	return author, nil
}

func (p *Pnode) verifySignature(
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
	signingKey plan.IdentityPublicKey) error {
	if p.Session == nil {
		return plan.Error(-1, "no logged in user")
	}
	_, ok := p.Session.SKI.Verify(signingKey, hash, sig)
	if !ok {
		return plan.Error(-1, "invalid signature")
	}
	return nil
}

// TODO
func (p *Pnode) checkPermissions(permissions int) error {
	return nil
}

// Push appends an encrypted PDIEntry to the PDI storage layer.
// Returns the ID of the new entry but does not change the client's
// position pointer in the PDI.
func (p *Pnode) Push(entryCrypt *plan.PDIEntryCrypt) uint32 {
	return p.PDI.Push(entryCrypt)
}
