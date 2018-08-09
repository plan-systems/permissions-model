package ski

import (
	"encoding/json"

	plan "github.com/plan-tools/go-plan/plan"
	box "golang.org/x/crypto/nacl/box"
	secretbox "golang.org/x/crypto/nacl/secretbox"
	sign "golang.org/x/crypto/nacl/sign"
)

// SKI represents the external SKI process
type SKI struct {
	keyring *keyring
}

func NewSKI() *SKI {
	ski := &SKI{keyring: newKeyring()}
	return ski
}

// ---------------------------------------------------------
//
// Top-level functions of the SKI. Because these APIs are intended to
// stand-in for the ones we'll have used across process boundaries, they
// are designed to minimize the amount of serialization and wire traffic
// required, and reduce the knowledge the SKI has about what's being done
// with these values.

// given a user's encryption public key, Vouch encrypts the channel's
// CommunityKey for that user's public key, and returns the encrypted
// buffer (or an error)
func (ski *SKI) Vouch(chanId plan.AccessChannelID, pubKey plan.IdentityPublicKey,
) ([]byte, error) {

	communityKey, communityKeyID, err := ski.keyring.GetCommunityKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	keyMsgBody := vouchMessage{KeyID: communityKeyID, Key: communityKey}
	serializedBody, err := json.Marshal(keyMsgBody)
	if err != nil {
		return []byte{}, err
	}

	pdiMsgBody := &plan.PDIEntryBody{
		BodyParts: []plan.PDIBodyPart{
			plan.PDIBodyPart{
				// TODO: presumably we want some kind of codec here
				Header: "/plan/key",
				Body:   serializedBody,
			},
		},
	}
	// TODO: is there a 2nd codec here we need to somehow specify?
	msg, err := json.Marshal(pdiMsgBody)
	if err != nil {
		return []byte{}, err
	}
	return ski.EncryptFor(chanId, msg, pubKey)
}

func (ski *SKI) AcceptVouch(
	chanID plan.AccessChannelID,
	bodyCrypt []byte,
	senderPubKey plan.IdentityPublicKey,
) error {

	msg, err := ski.DecryptFrom(chanID, bodyCrypt, senderPubKey)
	if err != nil {
		return err
	}
	pdiMsgBody := &plan.PDIEntryBody{}
	err = json.Unmarshal(msg, pdiMsgBody)
	if err != nil {
		return err
	}
	keyMsgBody := &vouchMessage{}
	err = json.Unmarshal(pdiMsgBody.BodyParts[0].Body, keyMsgBody)
	if err != nil {
		return err
	}
	ski.keyring.setCommunityKeyFrom(chanID, keyMsgBody.KeyID, keyMsgBody.Key)
	return nil
}

type vouchMessage struct {
	KeyID plan.CommunityKeyID
	Key   plan.CommunityKey
}

// given the hash of a message, Sign signs the hash and returns the
// signature
func (ski *SKI) Sign(chanId plan.AccessChannelID, hash plan.PDIEntryHash,
) ([]byte, error) {
	privateKey, _, err := ski.keyring.GetSigningKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	signed := sign.Sign([]byte{}, hash[:], privateKey)
	return signed[:64], nil
}

// given a buffer, Encrypt encrypts it with the community key and
// returns the encrypted buffer (or an error). Typically the msg buffer
// will be a serialized PDIEntryBody or PDIEntryHeader. This is
// authenticated encryption but the caller will follow this call with a
// call to Sign the PDIEntryHash for validation
func (ski *SKI) Encrypt(chanId plan.AccessChannelID, msg []byte,
) ([]byte, error) {
	nonce := <-Nonces
	communityKey, _, err := ski.keyring.GetCommunityKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	encrypted := secretbox.Seal(nonceToArray(nonce)[:], msg,
		nonceToArray(nonce), communityKeyToArray(communityKey))
	return encrypted, nil
}

// given a buffer, EncryptFor encrypts it for the public key of the
// intended recipient and returns the encrypted buffer. Typically the
// msg buffer will be a serialized PDIEntryBody or PDIEntryHeader.
// Note: this is how the Vouch operation works under the hood except
// that the Vouch caller doesn't know what goes in the message body.
// Outside of Vouch operations, this is the basis of private messages
// between users. The caller will follow this call with a call to Sign
// the PDIEntryHash
func (ski *SKI) EncryptFor(
	chanId plan.AccessChannelID,
	msg []byte,
	recvPubKey plan.IdentityPublicKey,
) ([]byte, error) {
	nonce := <-Nonces
	privateKey, _, err := ski.keyring.GetEncryptKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	encrypted := box.Seal(nonceToArray(nonce)[:], msg,
		nonceToArray(nonce), pubKeyToArray(recvPubKey), privateKey)
	return encrypted, nil
}

// TODO: this probably doesn't need to be in the SKI because it doesn't
//       require any private key material?
// given a public key and a PDIEntrySig, verify the signature. returns
// the verified buffer (so it can be compared by the caller) and a bool
// indicating success.
func (ski *SKI) Verify(
	pubKey plan.IdentityPublicKey,
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
) ([]byte, bool) {
	// need to re-combine the sig and hash to produce the
	// signed message that Open expects
	var signedMsg []byte
	signedMsg = append(signedMsg, sig[:]...)
	signedMsg = append(signedMsg, hash[:]...)
	verified, ok := sign.Open([]byte{}, signedMsg[:], pubKeyToArray(pubKey))
	return verified, ok
}

// given an encrypted buffer, Decrypt decrypts it using
// the community key for the channel and returns the cleartext buffer
func (ski *SKI) Decrypt(
	chanId plan.AccessChannelID,
	encrypted []byte,
) ([]byte, error) {
	communityKey, _, err := ski.keyring.GetCommunityKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:],
		&nonce, communityKeyToArray(communityKey))
	if !ok {
		return nil, plan.Error(
			-1, "secretbox.Open failed but doesn't produce an error")
	}
	return decrypted, nil
}

// given an encrypted buffer, DecryptFrom decrypts it using
// the user's private key and returns the decrypted buffer
func (ski *SKI) DecryptFrom(
	chanId plan.AccessChannelID,
	encrypted []byte,
	senderPubKey plan.IdentityPublicKey,
) ([]byte, error) {
	privateKey, _, err := ski.keyring.GetEncryptKey(chanId)
	if err != nil {
		return []byte{}, err
	}
	var nonce [24]byte
	copy(nonce[:], encrypted[:24])
	decrypted, ok := box.Open(nil, encrypted[24:],
		&nonce, pubKeyToArray(senderPubKey), privateKey)
	if !ok {
		return nil, plan.Error(
			-1, "box.Open failed but doesn't produce an error")
	}
	return decrypted, nil
}

// ---------------------------------------------------------
// Key and identity management functions
// These mostly wrap the underlying keying.

// NewIdentity generates encryption and signing keys, adds them to the
// keyring, and returns the public keys associated with those private
// keys as (encryption, signing). The caller will want to call SetIdentity
// to associated these keys with a specific channel.
// TODO: I don't like the return signature here. too easy to screw up
func (ski *SKI) NewIdentity() (
	plan.IdentityPublicKey, plan.IdentityPublicKey) {
	return ski.keyring.NewIdentity()
}

// SetIdentity assigns existing public keys to a specific existing channel.
// Creates the channel keychain references if it doesn't exist, but returns
// an error if either public key does not exist.
func (ski *SKI) SetIdentity(
	id plan.AccessChannelID,
	encryptKey plan.IdentityPublicKey,
	signingKey plan.IdentityPublicKey) error {
	return ski.keyring.SetIdentity(id, encryptKey, signingKey)
}

// GetIdentity fetches the user's public keys from the keychain for a
// specific channel, or an error if either the channel or key doesn't exist.
func (ski *SKI) GetIdentity(chanId plan.AccessChannelID) (
	plan.IdentityPublicKey, plan.IdentityPublicKey, error) {
	var (
		encryptPubKey plan.IdentityPublicKey
		signingPubKey plan.IdentityPublicKey
	)
	_, encryptPubKey, err := ski.keyring.GetEncryptKey(chanId)
	if err != nil {
		return encryptPubKey, signingPubKey, err
	}
	_, signingPubKey, err = ski.keyring.GetSigningKey(chanId)
	if err != nil {
		return encryptPubKey, signingPubKey, err
	}
	return encryptPubKey, signingPubKey, nil
}

// NewCommunityKey generates a new community key, adds it to the keyring,
// and returns the CommunityKeyID associated with that key. The caller will
// want to call SetCommunityKey to associate the key with a specific channel.
func (ski *SKI) NewCommunityKey() plan.CommunityKeyID {
	return ski.keyring.NewCommunityKey()
}

// SetCommunityKey assigns an existing community key to a specific existing
// channel. Returns an error if either the channel keychain reference or the
// community key don't already exist.
func (ski *SKI) SetCommunityKey(
	chanId plan.AccessChannelID, keyId plan.CommunityKeyID) error {
	return ski.keyring.SetCommunityKey(chanId, keyId)
}

// GetCommunityKeyID fetches the community key ID from the keychain for a
// specific channel, or an error if either the channel or key doesn't exist.
func (ski *SKI) GetCommunityKeyID(chanId plan.AccessChannelID) (
	plan.CommunityKeyID, error) {
	return ski.keyring.GetCommunityKeyID(chanId)
}

// ---------------------------------------------------------
//
// Helper functions
// some of these will want to stay in the SKI, whereas others
// make more sense to land in the plan.go types. Lots of making
// up for golang's embarassing type system here
//

// TODO: we'll want to make this a method on plan.PDIEntrySig
func NewSig(arr []byte) plan.PDIEntrySig {
	sig := plan.PDIEntrySig{}
	copy(sig[:], arr[:64])
	return sig
}

// TODO: we'll want to make this a method on plan.IdentityPublicKey
func NewPubKey(arr *[32]byte) plan.IdentityPublicKey {
	k := plan.IdentityPublicKey{}
	copy(k[:], arr[:32])
	return k
}

// TODO: we'll want to make this a method on plan.IdentityPublicKey
func pubKeyToArray(k plan.IdentityPublicKey) *[32]byte {
	var arr [32]byte
	copy(arr[:], k[:32])
	return &arr
}

// TODO: we'll want to make this a method on plan.CommunityKey
func communityKeyToArray(k plan.CommunityKey) *[32]byte {
	var arr [32]byte
	copy(arr[:], k[:32])
	return &arr
}
