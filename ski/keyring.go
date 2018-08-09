package ski

import (
	crypto_rand "crypto/rand"
	"sync"

	plan "github.com/plan-tools/go-plan/plan"
	box "golang.org/x/crypto/nacl/box"
	sign "golang.org/x/crypto/nacl/sign"
)

// keyring represents the storage of keys
type keyring struct {
	communityKeys map[plan.CommunityKeyID]plan.CommunityKey
	signingKeys   map[plan.IdentityPublicKey]*[64]byte
	encryptKeys   map[plan.IdentityPublicKey]*[32]byte
	channels      map[plan.AccessChannelID]*channelKeygroup
	mux           sync.RWMutex // synchronized changes to the keyring
}

func newKeyring() *keyring {
	return &keyring{
		communityKeys: map[plan.CommunityKeyID]plan.CommunityKey{},
		signingKeys:   map[plan.IdentityPublicKey]*[64]byte{},
		encryptKeys:   map[plan.IdentityPublicKey]*[32]byte{},
		channels:      map[plan.AccessChannelID]*channelKeygroup{},
	}
}

// channelKeygroup represents the set of community and public keys that a
// user has associated with a particular Channel, typically mapped by
// AccessChannelID.
type channelKeygroup struct {
	CommunityKeyID   plan.CommunityKeyID
	SigningPublicKey plan.IdentityPublicKey
	EncryptPublicKey plan.IdentityPublicKey
}

// ---------------------------------------------------------
// self identity functions
//

// NewIdentity generates encryption and signing keys, adds them to the
// keyring, and returns the public keys associated with those private
// keys. The caller will want to call SetIdentity to associate these
// keys with a specific channel.
func (kr *keyring) NewIdentity() (plan.IdentityPublicKey, plan.IdentityPublicKey) {

	// generate new key material
	encryptPubKey, encryptPrivateKey := generateEncryptionKey()
	signingPubKey, signingPrivateKey := generateSigningKey()

	// store it in the keyring and return the public keys
	kr.mux.Lock()
	defer kr.mux.Unlock()
	kr.signingKeys[signingPubKey] = signingPrivateKey
	kr.encryptKeys[encryptPubKey] = encryptPrivateKey
	return encryptPubKey, signingPubKey
}

// SetIdentity assigns existing public keys to a specific existing channel.
// Creates the channel keychain references if it doesn't exist, but returns
// an error if either public key does not exist.
func (kr *keyring) SetIdentity(
	id plan.AccessChannelID,
	encryptKey plan.IdentityPublicKey,
	signingKey plan.IdentityPublicKey) error {

	kr.mux.Lock()
	defer kr.mux.Unlock()
	channel, ok := kr.channels[id] // creates a new channel if needed
	if !ok {
		channel = &channelKeygroup{}
		kr.channels[id] = channel
	}

	// assert these are real keys we've previously created
	_, ok = kr.signingKeys[signingKey]
	if !ok {
		return plan.Errorf(-1,
			"SetIdentity: signing key %v does not exist", signingKey)
	}
	_, ok = kr.encryptKeys[encryptKey]
	if !ok {
		return plan.Errorf(-1,
			"SetIdentity: encryption key %v does not exist", encryptKey)
	}
	channel.SigningPublicKey = signingKey
	channel.EncryptPublicKey = encryptKey
	return nil
}

// GetSigningKey fetches the user's private signing key from the keychain for a
// specific channel, or an error if either the channel or key doesn't exist.
func (kr *keyring) GetSigningKey(chanId plan.AccessChannelID) (
	*[64]byte, plan.IdentityPublicKey, error) {
	var (
		key    *[64]byte
		pubKey plan.IdentityPublicKey
	)
	kr.mux.RLock()
	defer kr.mux.RUnlock()
	channel, ok := kr.channels[chanId]
	if !ok {
		return key, pubKey, plan.Errorf(-1,
			"GetSigningKey: channel %v does not exist", chanId)
	}
	pubKey = channel.SigningPublicKey
	key, ok = kr.signingKeys[pubKey]
	if !ok {
		return key, pubKey, plan.Errorf(-1,
			"GetSigningKey: signing key %v does not exist", pubKey)
	}
	return key, pubKey, nil
}

// GetEncryptKey fetches the user's private encrypt key from the keychain for a
// specific channel, or an error if either the channel or key doesn't exist.
func (kr *keyring) GetEncryptKey(chanId plan.AccessChannelID) (
	*[32]byte, plan.IdentityPublicKey, error) {
	var (
		key    *[32]byte
		pubKey plan.IdentityPublicKey
	)
	kr.mux.RLock()
	defer kr.mux.RUnlock()
	channel, ok := kr.channels[chanId]
	if !ok {
		return key, pubKey, plan.Errorf(-1,
			"GetEncryptKey: channel %v does not exist", chanId)
	}
	pubKey = channel.EncryptPublicKey
	key, ok = kr.encryptKeys[pubKey]
	if !ok {
		return key, pubKey, plan.Errorf(-1,
			"GetEncryptKey: encrypt key %v does not exist", pubKey)
	}
	return key, pubKey, nil
}

// Removes any instance of a key associated with the public key provided
// from the keyring
func (kr *keyring) InvalidateIdentity(key plan.IdentityPublicKey) {
	kr.mux.Lock()
	defer kr.mux.Unlock()
	delete(kr.signingKeys, key)
	delete(kr.encryptKeys, key)
	for _, group := range kr.channels {
		if group.SigningPublicKey == key {
			group.SigningPublicKey = plan.IdentityPublicKey{}
		}
		if group.EncryptPublicKey == key {
			group.EncryptPublicKey = plan.IdentityPublicKey{}
		}
	}
}

func generateEncryptionKey() (plan.IdentityPublicKey, *[32]byte) {
	publicKey, privateKey, err := box.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}
	return NewPubKey(publicKey), privateKey
}

func generateSigningKey() (plan.IdentityPublicKey, *[64]byte) {
	publicKey, privateKey, err := sign.GenerateKey(crypto_rand.Reader)
	if err != nil {
		panic(err)
	}
	return NewPubKey(publicKey), privateKey
}

// ---------------------------------------------------------
// community key functions
//

// NewCommunityKey generates a new community key, adds it to the keyring,
// and returns the CommunityKeyID associated with that key. The caller will
// want to call SetCommunityKey to associate the key with a specific channel.
func (kr *keyring) NewCommunityKey() plan.CommunityKeyID {
	kr.mux.Lock()
	defer kr.mux.Unlock()
	key, keyId := generateSymmetricKey()
	kr.communityKeys[keyId] = key
	return keyId
}

// SetCommunityKey assigns an existing community key to a specific existing
// channel. Returns an error if either the channel keychain reference or the
// community key don't already exist.
func (kr *keyring) SetCommunityKey(
	chanId plan.AccessChannelID, keyId plan.CommunityKeyID) error {
	kr.mux.Lock()
	defer kr.mux.Unlock()
	return kr.setKeyId(chanId, keyId)
}

// internal: setCommunityKeyFrom assigns a new community key to a specific
// existing channel. Returns an error if either the channel keychain reference
// or the community key don't already exist.
func (kr *keyring) setCommunityKeyFrom(
	chanId plan.AccessChannelID, keyId plan.CommunityKeyID, key plan.CommunityKey) error {
	kr.mux.Lock()
	defer kr.mux.Unlock()
	kr.communityKeys[keyId] = key
	return kr.setKeyId(chanId, keyId)
}

// internal: setKeyId assigns an existing community key ID to a specific existing
// channel. Returns an error if either the channel keychain reference or the
// community key don't already exist. *IMPORTANT: caller must lock the keyring.*
func (kr *keyring) setKeyId(
	chanId plan.AccessChannelID, keyId plan.CommunityKeyID) error {
	channel, ok := kr.channels[chanId]
	if !ok {
		return plan.Errorf(-1,
			"SetCommunityKey: channel %v does not exist", chanId)
	}
	_, ok = kr.communityKeys[keyId]
	if !ok {
		return plan.Errorf(-1,
			"SetCommunityKey: community key %v does not exist", keyId)
	}
	channel.CommunityKeyID = keyId
	return nil
}

// GetCommunityKey fetches the community key from the keychain for a
// specific channel, or an error if either the channel or key doesn't exist.
func (kr *keyring) GetCommunityKey(chanId plan.AccessChannelID) (
	plan.CommunityKey, plan.CommunityKeyID, error) {
	var (
		key   plan.CommunityKey
		keyId plan.CommunityKeyID
	)
	keyId, err := kr.GetCommunityKeyID(chanId)
	if err != nil {
		return key, keyId, err
	}
	kr.mux.RLock()
	defer kr.mux.RUnlock()
	key, ok := kr.communityKeys[keyId]
	if !ok {
		return key, keyId, plan.Errorf(-1,
			"GetCommunityKey: community key %v does not exist", keyId)
	}
	return key, keyId, nil
}

// GetCommunityKeyID fetches the ID of the community key from the
// key chain for a specific channel, or an error if either the channel
// or key doesn't exist.
func (kr *keyring) GetCommunityKeyID(chanId plan.AccessChannelID) (
	plan.CommunityKeyID, error) {
	kr.mux.RLock()
	defer kr.mux.RUnlock()
	var keyId plan.CommunityKeyID
	channel, ok := kr.channels[chanId]
	if !ok {
		return keyId, plan.Errorf(-1,
			"SetCommunityKey: channel %v does not exist", chanId)
	}
	keyId = channel.CommunityKeyID
	return keyId, nil
}

func generateSymmetricKey() ([32]byte, plan.CommunityKeyID) {
	secret := make([]byte, 32)
	_, err := crypto_rand.Read(secret)
	if err != nil {
		panic(err) // TODO: unclear when we'd ever hit this?
	}
	var key [32]byte
	copy(key[:32], secret[:])

	keyId := make([]byte, 16) // TODO: is this enough for uniqueness?
	_, err = crypto_rand.Read(keyId)
	if err != nil {
		panic(err) // TODO: unclear when we'd ever hit this?
	}
	var communityId plan.CommunityKeyID
	copy(communityId[:16], keyId[:])

	return key, communityId
}
