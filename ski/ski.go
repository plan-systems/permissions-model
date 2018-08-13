// Package ski is a demonstration of the SKI plugin, implemented in go.
// With some additional work and review this package could be wrapped in a
// binary that communicates over a socket to serve as a reference for
// other SKI implementers.
package ski // import "github.com/plan-tools/permissions-model/ski"

import (
	"encoding/json"

	plan "github.com/plan-tools/go-plan/plan"
	box "golang.org/x/crypto/nacl/box"
	secretbox "golang.org/x/crypto/nacl/secretbox"
	sign "golang.org/x/crypto/nacl/sign"
)

// SKI represents the external SKI process and holds the keyring.
type SKI struct {
	keyring *keyring
}

// NewSKI initializes the SKI's keying.
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

// Vouch encrypts a CommunityKey for the recipients public encryption key,
// and returns the encrypted buffer (or error)
func (ski *SKI) Vouch(
	communityKeyID plan.CommunityKeyID,
	senderPubKey plan.IdentityPublicKey,
	recvPubKey plan.IdentityPublicKey,
) ([]byte, error) {
	communityKey, err := ski.keyring.GetCommunityKeyByID(communityKeyID)
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
	return ski.EncryptFor(senderPubKey, msg, recvPubKey)
}

// AcceptVouch decrypts the encrypted buffer written by Vouch and decrypts
// it for the recipient.
func (ski *SKI) AcceptVouch(
	recvPubKey plan.IdentityPublicKey,
	bodyCrypt []byte,
	senderPubKey plan.IdentityPublicKey,
) error {
	msg, err := ski.DecryptFrom(recvPubKey, bodyCrypt, senderPubKey)
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
	ski.keyring.InstallCommunityKey(keyMsgBody.KeyID, keyMsgBody.Key)
	return nil
}

// internal: the message sent by the Vouch process
type vouchMessage struct {
	KeyID plan.CommunityKeyID
	Key   plan.CommunityKey
}

// Sign accepts a message hash and returns a signature.
func (ski *SKI) Sign(signer plan.IdentityPublicKey, hash plan.PDIEntryHash,
) (plan.PDIEntrySig, error) {
	privateKey, err := ski.keyring.GetSigningKey(signer)
	if err != nil {
		return plan.PDIEntrySig{}, err
	}
	signed := sign.Sign([]byte{}, hash[:], privateKey)
	return newSig(signed[:64]), nil
}

// Encrypt accepts a buffer and encrypts it with the community key and returns
// the encrypted buffer (or an error). Typically the msg buffer will be a
// serialized PDIEntryBody or PDIEntryHeader. This is authenticated encryption
// but the caller will follow this call with a call to Verify the PDIEntryHash
// for validation.
func (ski *SKI) Encrypt(keyId plan.CommunityKeyID, msg []byte,
) ([]byte, error) {
	nonce := <-nonces
	communityKey, err := ski.keyring.GetCommunityKeyByID(keyId)
	if err != nil {
		return []byte{}, err
	}

	encrypted := secretbox.Seal(nonceToArray(nonce)[:], msg,
		nonceToArray(nonce), communityKeyToArray(communityKey))
	return encrypted, nil
}

// EncryptFor accepts a buffer and encrypts it for the public key of the
// intended recipient and returns the encrypted buffer. Typically the msg
// buffer will be a serialized PDIEntryBody or PDIEntryHeader. Note: this
// is how the Vouch operation works under the hood except that the Vouch
// caller doesn't know what goes in the message body. Outside of Vouch
// operations, this is the basis of private messages between users. The
// caller will follow this call with a call to Sign the PDIEntryHash
func (ski *SKI) EncryptFor(
	senderPubKey plan.IdentityPublicKey,
	msg []byte,
	recvPubKey plan.IdentityPublicKey,
) ([]byte, error) {
	nonce := <-nonces
	privateKey, err := ski.keyring.GetEncryptKey(senderPubKey)
	if err != nil {
		return []byte{}, err
	}
	encrypted := box.Seal(nonceToArray(nonce)[:], msg,
		nonceToArray(nonce), pubKeyToArray(recvPubKey), privateKey)
	return encrypted, nil
}

// Verify accepts a signature and verfies it against the public key of the
// sender. Returns the verified buffer (so it can be compared by the caller)
// and a bool indicating success.
func (ski *SKI) Verify(
	pubKey plan.IdentityPublicKey,
	hash plan.PDIEntryHash,
	sig plan.PDIEntrySig,
) ([]byte, bool) {
	// TODO: this probably doesn't need to be in the SKI because it doesn't
	//       require any private key material?

	// need to re-combine the sig and hash to produce the
	// signed message that Open expects
	var signedMsg []byte
	signedMsg = append(signedMsg, sig[:]...)
	signedMsg = append(signedMsg, hash[:]...)
	verified, ok := sign.Open([]byte{}, signedMsg[:], pubKeyToArray(pubKey))
	return verified, ok
}

// Decrypt takes an encrypted buffer and decrypts it using the community key
// and returns the cleartext buffer (or an error).
func (ski *SKI) Decrypt(
	keyID plan.CommunityKeyID,
	encrypted []byte,
) ([]byte, error) {
	communityKey, err := ski.keyring.GetCommunityKeyByID(keyID)
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

// DecryptFrom takes an encrypted buffer and a public key, and decrypts the
// message using the recipients private key. It returns the decrypted buffer
// (or an error).
func (ski *SKI) DecryptFrom(
	recvPubKey plan.IdentityPublicKey,
	encrypted []byte,
	senderPubKey plan.IdentityPublicKey,
) ([]byte, error) {
	privateKey, err := ski.keyring.GetEncryptKey(recvPubKey)
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
// keys as (encryption, signing).
func (ski *SKI) NewIdentity() (
	plan.IdentityPublicKey, plan.IdentityPublicKey) {
	// TODO: I don't like the return signature here. too easy to screw up
	return ski.keyring.NewIdentity()
}

// NewCommunityKey generates a new community key, adds it to the keyring,
// and returns the CommunityKeyID associated with that key.
func (ski *SKI) NewCommunityKey() plan.CommunityKeyID {
	return ski.keyring.NewCommunityKey()
}

// ---------------------------------------------------------
//
// Helper functions
// some of these will want to stay in the SKI, whereas others
// make more sense to land in the plan.go types. Lots of making
// up for golang's embarassing type system here
//

// TODO: we'll want to make this a method on plan.PDIEntrySig
func newSig(arr []byte) plan.PDIEntrySig {
	sig := plan.PDIEntrySig{}
	copy(sig[:], arr[:64])
	return sig
}

// TODO: we'll want to make this a method on plan.IdentityPublicKey
func newPubKey(arr *[32]byte) plan.IdentityPublicKey {
	k := plan.IdentityPublicKey(*arr)
	return k
}

// TODO: we'll want to make this a method on plan.IdentityPublicKey
func pubKeyToArray(k plan.IdentityPublicKey) *[32]byte {
	arr := [32]byte(k)
	return &arr
}

// TODO: we'll want to make this a method on plan.CommunityKey
func communityKeyToArray(k plan.CommunityKey) *[32]byte {
	arr := [32]byte(k)
	return &arr
}
