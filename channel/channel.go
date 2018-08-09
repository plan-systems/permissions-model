package channel

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	plan "github.com/plan-tools/go-plan/plan"
	ski "github.com/plan-tools/permissions-model/ski"
	user "github.com/plan-tools/permissions-model/user"
)

type Channel struct {
	Properties *plan.ChannelProperties
	Entries    []*plan.PDIEntryCrypt
	mux        sync.RWMutex // synchronized changes to entries
}

// TODO: not wild about the name here
// an AccessChannelReferenceEntry marks a revision of the access channel.
// other PDIEntry blocks will reference AccessChannelReferenceEntry to
// tell clients what CommunityKey to use and which identities have what
// authorizations for the channel.
type AccessChannelReferenceEntry struct {
	CommunityKeyID plan.CommunityKeyID

	// TODO: should we break this Members down to Owners, Writers, Readers?
	Members map[plan.IdentityAddr]uint32 // this int32 is a rev ID
}

// an AccessChannelKeyEntry is a user's public key and the community key
// encrypted for that public key
type AccessChannelKeyEntry struct {
	PublicKey         plan.IdentityPublicKey `json:"public_key"`
	CommunityKeyCrypt []byte                 `json:"community_key_enc"`
	communityKey      plan.CommunityKey      // unencrypted key, not serialized
}

// Write takes a slice of cleartext PDIBodyPart, encrypts them
// with the community key, and persists them to the channel using
// community-key encrypted header metadata.
func (c *Channel) Write(
	author *user.User,
	verb plan.PDIEntryVerb,
	parts []*plan.PDIBodyPart,
) error {
	accessChannelID := c.Properties.OwningAccessChannelID
	encryptedBody, err := c.encryptBodyParts(author, accessChannelID, parts)
	if err != nil {
		return err
	}
	return c.writeEncryptedBody(
		author,
		verb,
		accessChannelID,
		encryptedBody,
	)
}

// WriteFor takes a slice of cleartext PDIBodyPart, encrypts them
// with the recipient's public key, and persists them to the channel
// using community-key encrypted header metadata.
func (c *Channel) WriteFor(
	author *user.User,
	verb plan.PDIEntryVerb,
	recipient plan.IdentityPublicKey,
	parts []*plan.PDIBodyPart,
) error {
	accessChannelID := c.Properties.OwningAccessChannelID
	encryptedBody, err := c.encryptBodyPartsFor(
		author, accessChannelID, recipient, parts)
	if err != nil {
		return err
	}
	return c.writeEncryptedBody(
		author,
		verb,
		accessChannelID,
		encryptedBody,
	)
}

// WriteVouchFor encrypts the community key for the recipients public key
// persists it to the channel using community-key encrypted header metadata.
// The recipient can't decrypt the header until the body is decrypted first,
// so the author's public key and channel ID are transmitted out-of-band in
// the invitation.
func (c *Channel) WriteVouchFor(author *user.User,
	recipient plan.IdentityPublicKey) error {
	accessChannelID := c.Properties.OwningAccessChannelID

	// note that the cleartext key never leaves the SKI!
	encryptedBody, err := author.SKI.Vouch(accessChannelID, recipient)
	if err != nil {
		return err
	}
	return c.writeEncryptedBody(
		author,
		plan.PDIEntryVerbChannelAdmin,
		accessChannelID,
		encryptedBody,
	)
}

// AcceptVouch reads a "vouch" entry and asks the SKI to decrypt the contents
// as a new community key using the receiver's keypair. Note that the recipient
// can't decrypt the header until the body is decrypted first, so the author's
// public keys and channel ID are transmitted out-of-band in the invitation.
// TODO: I don't like this name
// TODO: is there any need to mess with the header at all once we've
//       read the vouch entry?
func (c *Channel) AcceptVouch(
	recv *user.User,
	vouchEncryptKey plan.IdentityPublicKey,
	vouchSigningKey plan.IdentityPublicKey,
	entryID int,
) error {
	if len(c.Entries) < entryID+1 {
		return plan.Error(-1, "entry out of range")
	}
	encryptedEntry := c.Entries[entryID]
	chanID := c.Properties.OwningAccessChannelID

	_, ok := recv.SKI.Verify(
		vouchSigningKey, *encryptedEntry.Hash, encryptedEntry.Sig)
	if !ok {
		return plan.Error(-1, "invalid signature")
	}

	// note: if we were just reading the message we could call
	// DecryptFrom here but we don't want the key to leak out of
	// the SKI
	return recv.SKI.AcceptVouch(
		chanID, encryptedEntry.BodyCrypt, vouchEncryptKey)
}

// Read is the high-level method for reading an entry, where
// the caller doesn't already know what keys or access channels
// are involved and so has to pull it out from the entry header.
func (c *Channel) Read(recv *user.User, entryID int) (*plan.PDIEntry, error) {
	if len(c.Entries) < entryID+1 {
		return nil, plan.Error(-1, "entry out of range")
	}
	encryptedEntry := c.Entries[entryID]

	// 1. need to decrypt header to get signing key ID
	// 2. need to get signing key from access channel
	// 3. need to verify entry
	// 4. need to decrypt body

	// TODO: this is being read under Channel but in reality
	// the Channel is multiplexed over a PDI and we need to
	// represent that correctly in this demo
	chanID := c.Properties.OwningAccessChannelID
	// communityKeyID := encryptedEntry.CommunityKeyID

	// decrypt the header so we can get the author and access
	// channel info

	clearHeaderBuf, err := recv.SKI.Decrypt(chanID, encryptedEntry.HeaderCrypt)
	if err != nil {
		return nil, err
	}
	var header *plan.PDIEntryHeader
	err = json.Unmarshal(clearHeaderBuf, header)
	if err != nil {
		return nil, err
	}

	// verify the entry author

	// _, ok := recv.SKI.Verify(
	// 	vouchSigningKey, *encryptedEntry.Hash, encryptedEntry.Sig)
	// if !ok {
	// 	return plan.Error(-1, "invalid signature")
	// }

	// encryptedEntry := c.Entries[entryID]

	// sig := encryptedEntry.Sig
	// hash := encryptedEntry.Hash

	// if !ok {
	// 	return nil, plan.Error(-1, "channel has no entry at that index")
	// }

	// entry := plan.PDIEntry{
	// 	Header: &plan.PDIEntryHeader{
	// 		Time:             plan.Time(time.Now().Unix()),
	// 		Verb:             verb,
	// 		ChannelID:        c.Properties.ChannelID,
	// 		Author:           author.Addr,
	// 		AccessChannelID:  accessChannelID,
	// 		AccessChannelRev: c.Properties.OwningAccessChannelRev,
	// 	},
	// 	Body: &plan.PDIEntryBody{
	// 		BodyParts: parts,
	// 	},
	// }
	return nil, nil
}

// ---------------------------------------------------------
// helpers
//

// internal: writes a previously-encrypted body to the PDI, with
// the header encrypted with the community key
func (c *Channel) writeEncryptedBody(
	author *user.User,
	verb plan.PDIEntryVerb,
	accessChannelID plan.AccessChannelID,
	encryptedBody []byte,
) error {
	communityKeyID, err := author.SKI.GetCommunityKeyID(accessChannelID)
	if err != nil {
		return err
	}
	encryptedHeader, err := c.encryptHeader(author, accessChannelID, verb)
	if err != nil {
		return err
	}
	entryCrypt := &plan.PDIEntryCrypt{
		// Info: , // TODO: we don't have any flags established for this
		CommunityKeyID: communityKeyID,
		HeaderCrypt:    encryptedHeader,
		BodyCrypt:      encryptedBody,
	}
	err = c.hashAndSign(author, accessChannelID, entryCrypt)
	if err != nil {
		return err
	}
	err = c.append(entryCrypt)
	if err != nil {
		return err
	}
	return nil

}

// internal: serializes the parts and creates the encrypted body
func (c *Channel) encryptBodyParts(
	author *user.User,
	accessChannelID plan.AccessChannelID,
	parts []*plan.PDIBodyPart,
) ([]byte, error) {
	bodyClear, err := json.Marshal(parts)
	if err != nil {
		return nil, err
	}
	encryptedBody, err := author.SKI.Encrypt(accessChannelID, bodyClear)
	if err != nil {
		return nil, err
	}
	return encryptedBody, nil
}

// internal: serializes the parts and creates the body encrypted for
// a specific public key.
func (c *Channel) encryptBodyPartsFor(
	author *user.User,
	accessChannelID plan.AccessChannelID,
	recipient plan.IdentityPublicKey,
	parts []*plan.PDIBodyPart,
) ([]byte, error) {
	bodyClear, err := json.Marshal(parts)
	if err != nil {
		return nil, err
	}
	encryptedBody, err := author.SKI.EncryptFor(
		accessChannelID, bodyClear, recipient)
	if err != nil {
		return nil, err
	}
	return encryptedBody, nil
}

// internal: creates and serializes the header and then encrypts it.
func (c *Channel) encryptHeader(
	author *user.User,
	accessChannelID plan.AccessChannelID,
	verb plan.PDIEntryVerb,
) ([]byte, error) {
	// create the encrypted header
	header := &plan.PDIEntryHeader{
		Time:             plan.Time(time.Now().Unix()),
		Verb:             verb,
		ChannelID:        c.Properties.ChannelID,
		Author:           author.Addr,
		AccessChannelID:  accessChannelID,
		AccessChannelRev: c.Properties.OwningAccessChannelRev,
	}
	headerClear, err := json.Marshal(header)
	if err != nil {
		return []byte{}, err
	}
	encryptedHeader, err := author.SKI.Encrypt(accessChannelID, headerClear)
	if err != nil {
		return []byte{}, err
	}
	return encryptedHeader, nil
}

// internal: computes the entry hash and signs it
func (c *Channel) hashAndSign(
	author *user.User,
	accessChannelID plan.AccessChannelID,
	entryCrypt *plan.PDIEntryCrypt) error {

	hash := &plan.PDIEntryHash{}
	entryCrypt.ComputeHash(hash)
	entryCrypt.Hash = hash

	sig, err := author.SKI.Sign(accessChannelID, *hash)
	if err != nil {
		return err
	}
	entryCrypt.Sig = ski.NewSig(sig)
	return nil
}

// Appends the encrypted PDIEntry to the channel (this is
// where we'd be writing to disk)
func (c *Channel) append(entryCrypt *plan.PDIEntryCrypt) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	entryCryptBuf, err := json.Marshal(entryCrypt)
	if err != nil {
		return err
	}
	c.Entries = append(c.Entries, entryCrypt)

	// TODO: how do we want to persist to disk for this demo?
	fmt.Printf("encrypted entry: %x...\n", entryCryptBuf[:30])
	return nil
}
