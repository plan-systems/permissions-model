package ski

import (
	crypto_rand "crypto/rand"

	plan "github.com/plan-tools/go-plan/plan"
)

// TODO: this Nonce generation doesn't work as an implementation without
// some way to coordinate between clients. It's unclear to me at this
// point whether we need the nonces to be both unique and *unpredictable*
// for our security properties to hold.
// Let's circle back to this in the real implementation.

var Nonces = NonceGenerator()

// needed by the SKI to cast our typedef
func nonceToArray(n plan.Nonce) *[24]byte {
	var arr [24]byte
	copy(n[:], arr[:24])
	return &arr
}

func NonceGenerator() <-chan plan.Nonce {
	nonceChan := make(chan plan.Nonce) // note: *must* be a blocking chan!
	go func() {
		for {
			currentNonce := make([]byte, 24)
			_, err := crypto_rand.Read(currentNonce)
			if err != nil {
				panic(err) // TODO: unclear when we'd ever hit this?
			}
			var nonce plan.Nonce
			copy(nonce[:24], currentNonce[:])
			nonceChan <- nonce
		}
	}()
	return nonceChan
}
