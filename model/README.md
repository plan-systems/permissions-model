# Proof-of-Concept Model

This directory contains a proof-of-concept model of the relationship between the SKI and the various other components of PLAN. It also includes a demo that walks through the process described in the README at the top of this repo.

## Setup

The demo is written in Python3 and requires Python 3.5 or above. The only third-party dependency are the `libsodium` bindings for Python: `pynacl`. The Makefile at the root of this repo includes a `make setup` target that will create a virtualenv with all dependencies, assuming Python 3.5 is available on the host.

## Run

The demo shows a workflow between three users (Alice, Bob, and Eve). Alice sets up the initial key channel and vouches for both Bob and Eve. After they exchange messages, Eve is expelled and the channel is re-keyed. Running `make run` should result in something like the following:

```
$ make run
cd model && /home/tim/lib/virtualenvs/plan-permissions-model/bin/python ./demo.py
* Initializing PDI
* Creating users Alice, Bob, and Eve

* Alice initializes the keyring for channel "cats"
  - Alice has public key: 57068778517c4b37da6648d22dbcee7025a42f69fb36309d8e4dd8abc4234b2e
  - Alice has verify key: 22cd4416326826dfe2dfe44fe90edb69a72c562be6f19bbef2610bbb604290cf
  - Alice publishes her public encryption key and signing verification key
  - Alice vouches for herself

* Alice publishes messages
  - Alice can read her own messages...
b'once upon a time there was a cat and he was smelly'

* Bob wants to read about cats too!
  - Bob has public key: 60763cf3176e3c1bf6e817d266e4290acc18267cec9ef500dd04fe2c63c3a24a
  - Bob has verify key: 4cf93d58d37abde24fab3988b294f8af943cdd29c05c48674eb53f74cfe9b2e5
  - Bob publishes his public encryption key and signing verification key

* Bob tries to read messages...
  ... but he can't

* Bob asks Alice to vouch for him (out-of-band)
  - Alice vouches for Bob
  - Bob loads master key
  - Bob can read messages now
b'once upon a time there was a cat and he was smelly'

* Eve wants to join
  - Eve has public key: bdc0efd14e3a6a9a5b92a5755418402e6a58ae4df1a5813ca03af90efd700d00
  - Eve has verify key: d91097be414d15deb618589a6e335351e044054523218f36b4c2db111d128c0f
  - Eve publishes her public encryption key and signing verification key
  - Alice vouches for Eve
  - Eve loads master key
  - Eve can read messages now
b'once upon a time there was a cat and he was smelly'

* Eve writes messages about dogs! Oh no!
  - Alice and Bob can read this message
b'my dog is better than your cat'
b'my dog is better than your cat'

* Alice and Bob decide to expel Eve by rekeying

* Alice re-initializes the keyring for channel "cats"
  - Alice has public key: a598797d6c23405a3f6433115c53bc818eb96789c8b96e7343724591049c2a21
  - Alice has verify key: 4e5997fd5697a85f4de7969301abf96ffe171b04e3a9259616c78e92871462ea
  - Alice publishes her public encryption key and signing verification key
  - Alice vouches for herself

* Bob re-initializes his keyring
  - Bob has public key: 56c892b47cb805dd6200465c16881213fee50a6c1ad39b74a5e0d2887315183b
  - Bob has verify key: b2c4d6fc4b9a0a8eb013b43754de15085dc474a2af4161db39a1f6e22af2d886
  - Bob publishes his public encryption key and signing verification key
  - Alice vouches for Bob
  - Bob loads master key
  - Alice and Bob can still read old messages
b'my dog is better than your cat'
b'my dog is better than your cat'
  - Alice publishes a new message
  - Alice and Bob can read the new messages
b'cats rule, dogs drool'
b'cats rule, dogs drool'
  - Eve has no key ring for the new message
KeyError:  '/key/cats/v1'
  - Eve tries using a hacked client...
Block(id='36c067ebf0594a7492ae7af71096753e', author='alice', data=b'\x11\xb8\xc2R\xcb"\xd8\xb3}k\x11\xf8y\xb9\x03d\xfd\x16\x96\xee?\xb7\xcf\xb9\xbf\xe8X\xcc\x95\xf5\xa8!7\xceD\x84^\x11\x0c8\x97C_\xa9\xf7\x93\x14\xa0\x9dP\xf3\xb9\x01e\xd7\xfe\x8b\xee>\x16l\xa0X\x02\x15\x9e\x10\x9f\x16\x03\t\xa1\xe4\xd6\x86\xa4[,\xf0\x97G@FZ2\x83\xdb\x7f!\x1d\xf2\xa5\xb3f\xc5\xc8D\xef\xff\xf6\xf4<tI\xdaJ\x1f\xc7>\xc1\xc4n`\x01\xa4X\xdbc%\x9d\xd3%\xd2\xbe\x7f', key_channel='/key/cats/v1')
CryptoError:  Decryption failed. Ciphertext failed verification
... but fails!
```
