package ski

import (
	"bytes"
	"testing"

	plan "github.com/plan-tools/go-plan/plan"
)

func TestSymmetricEncrypion(t *testing.T) {

	chanId := plan.AccessChannelID(plan.RootAccessChannel)

	ski, _, _ := setUpSKI(t, chanId)

	keyId := ski.NewCommunityKey()
	err := ski.SetCommunityKey(chanId, keyId)
	if err != nil {
		t.Fatal(err)
	}
	clearIn := []byte("hello, world!")
	encryptOut, err := ski.Encrypt(chanId, clearIn)
	if err != nil {
		t.Fatal(err)
	}
	clearOut, err := ski.Decrypt(chanId, encryptOut)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clearIn, clearOut) {
		t.Fatalf("got %v after decryption, expected %v", clearOut, clearIn)
	}
}

func TestPublicKeyEncrypion(t *testing.T) {

	chanId := plan.AccessChannelID(plan.RootAccessChannel)
	senderSki, senderEncryptPubKey, _ := setUpSKI(t, chanId)
	recvSki, recvEncryptPubKey, _ := setUpSKI(t, chanId)

	clearIn := []byte("hello, world!")
	encryptOut, err := senderSki.EncryptFor(chanId, clearIn, recvEncryptPubKey)
	if err != nil {
		t.Fatal(err)
	}
	clearOut, err := recvSki.DecryptFrom(
		chanId, encryptOut, senderEncryptPubKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clearIn, clearOut) {
		t.Fatalf("got %v after decryption, expected %v", clearOut, clearIn)
	}
}

func TestSigning(t *testing.T) {

	chanId := plan.AccessChannelID(plan.RootAccessChannel)
	senderSki, _, senderSignPubKey := setUpSKI(t, chanId)
	recvSki, _, _ := setUpSKI(t, chanId)

	entry := &plan.PDIEntryCrypt{
		HeaderCrypt: []byte("encryptedtestheader"),
		BodyCrypt:   []byte("encryptedtestbody"),
	}
	hash := &plan.PDIEntryHash{}
	entry.ComputeHash(hash)

	sig, err := senderSki.Sign(chanId, *hash)
	if err != nil {
		t.Fatal(err)
	}
	verified, ok := recvSki.Verify(senderSignPubKey, *hash, NewSig(sig))
	if !ok {
		t.Fatalf("signature verification failed: %x", verified)
	}
}

func TestVouching(t *testing.T) {
	chanId := plan.AccessChannelID(plan.RootAccessChannel)
	senderSki, senderEncryptPubKey, _ := setUpSKI(t, chanId)
	recvSki, recvEncryptKey, _ := setUpSKI(t, chanId)
	keyId := senderSki.NewCommunityKey()
	err := senderSki.SetCommunityKey(chanId, keyId)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := senderSki.Vouch(chanId, recvEncryptKey)
	if err != nil {
		t.Fatal(err)
	}
	err = recvSki.AcceptVouch(chanId, msg, senderEncryptPubKey)
	if err != nil {
		t.Fatal(err)
	}
}

// test setup helper
func setUpSKI(t *testing.T, chanId plan.AccessChannelID) (
	*SKI, plan.IdentityPublicKey, plan.IdentityPublicKey,
) {
	ski := NewSKI()

	encryptPubKey, signPubKey := ski.NewIdentity()
	err := ski.SetIdentity(chanId, encryptPubKey, signPubKey)
	if err != nil {
		t.Fatal(err)
	}
	return ski, encryptPubKey, signPubKey
}
