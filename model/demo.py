"""
demo.py - shows the workflows for the SKI
"""
import os

import nacl.exceptions

from pdi import PDI
from plan import User


DIR = './data'    # default output directory for demo
if not os.path.exists(DIR):
    os.makedirs(DIR)

DATA_CHANNEL = '/cats'
KEY_CHANNEL = '/key/cats/v0'
NEW_KEY_CHANNEL = '/key/cats/v1'


def run_demo():
    """ our main loop """
    print('* Initializing PDI')
    pdi = PDI()

    print('* Creating users Alice, Bob, and Eve')
    alice = User('alice', pdi)
    bob = User('bob', pdi)
    eve = User('eve', pdi)

    print('\n* Alice initializes the keyring for channel "cats"')
    alice.ski.new_keyring(KEY_CHANNEL)
    alice.ski.new_masterkey(KEY_CHANNEL)

    print('  - Alice has public key:', alice.ski.keyrings[KEY_CHANNEL].public_key)
    print('  - Alice has verify key:', alice.ski.keyrings[KEY_CHANNEL].verify_key)
    print('  - Alice publishes her public encryption key and signing verification key')
    alice.publish_keys(KEY_CHANNEL)

    print('  - Alice vouches for herself')
    alice.vouch('alice', KEY_CHANNEL)

    print('\n* Alice publishes messages')
    msg = b'once upon a time there was a cat and he was smelly'
    alice.publish_message(DATA_CHANNEL, 'my-cat', msg, KEY_CHANNEL)

    print('  - Alice can read her own messages...')
    print(alice.read_message(DATA_CHANNEL, 'my-cat'))

    print('\n* Bob wants to read about cats too!')
    bob.ski.new_keyring(KEY_CHANNEL)

    print('  - Bob has public key:', bob.ski.keyrings[KEY_CHANNEL].public_key)
    print('  - Bob has verify key:', bob.ski.keyrings[KEY_CHANNEL].verify_key)
    print('  - Bob publishes his public encryption key and signing verification key')
    bob.publish_keys(KEY_CHANNEL)

    try:
        print('\n* Bob tries to read messages...')
        print(bob.read_message(DATA_CHANNEL, 'my-cat'))
    except AssertionError:
        print("  ... but he can't")
    except:
        raise # shouldn't see this

    print('\n* Bob asks Alice to vouch for him (out-of-band)')

    print('  - Alice vouches for Bob')
    alice.vouch('bob', KEY_CHANNEL)

    print('  - Bob loads master key')
    bob.load_master_key(KEY_CHANNEL)
    print('  - Bob can read messages now')
    print(bob.read_message(DATA_CHANNEL, 'my-cat'))

    print('\n* Eve wants to join')
    eve.ski.new_keyring(KEY_CHANNEL)

    print('  - Eve has public key:', eve.ski.keyrings[KEY_CHANNEL].public_key)
    print('  - Eve has verify key:', eve.ski.keyrings[KEY_CHANNEL].verify_key)
    print('  - Eve publishes her public encryption key and signing verification key')
    eve.publish_keys(KEY_CHANNEL)
    print('  - Alice vouches for Eve')
    alice.vouch('eve', KEY_CHANNEL)

    print('  - Eve loads master key')
    eve.load_master_key(KEY_CHANNEL)

    print('  - Eve can read messages now')
    print(eve.read_message(DATA_CHANNEL, 'my-cat'))

    print('\n* Eve writes messages about dogs! Oh no!')
    msg = b'my dog is better than your cat'
    eve.publish_message(DATA_CHANNEL, 'my-cat', msg, KEY_CHANNEL)

    print('  - Alice and Bob can read this message')
    print(alice.read_message(DATA_CHANNEL, 'my-cat'))
    print(bob.read_message(DATA_CHANNEL, 'my-cat'))

    print('\n* Alice and Bob decide to expel Eve by rekeying')

    print('\n* Alice re-initializes the keyring for channel "cats"')
    alice.ski.new_keyring(NEW_KEY_CHANNEL)
    alice.ski.new_masterkey(NEW_KEY_CHANNEL)

    print('  - Alice has public key:', alice.ski.keyrings[NEW_KEY_CHANNEL].public_key)
    print('  - Alice has verify key:', alice.ski.keyrings[NEW_KEY_CHANNEL].verify_key)
    print('  - Alice publishes her public encryption key and signing verification key')
    alice.publish_keys(NEW_KEY_CHANNEL)
    print('  - Alice vouches for herself')
    alice.vouch('alice', NEW_KEY_CHANNEL)

    print('\n* Bob re-initializes his keyring')
    bob.ski.new_keyring(NEW_KEY_CHANNEL)
    print('  - Bob has public key:', bob.ski.keyrings[NEW_KEY_CHANNEL].public_key)
    print('  - Bob has verify key:', bob.ski.keyrings[NEW_KEY_CHANNEL].verify_key)
    print('  - Bob publishes his public encryption key and signing verification key')
    bob.publish_keys(NEW_KEY_CHANNEL)
    print('  - Alice vouches for Bob')
    alice.vouch('bob', NEW_KEY_CHANNEL)
    print('  - Bob loads master key')
    bob.load_master_key(NEW_KEY_CHANNEL)

    print('  - Alice and Bob can still read old messages')
    print(alice.read_message(DATA_CHANNEL, 'my-cat'))
    print(bob.read_message(DATA_CHANNEL, 'my-cat'))
    print('  - Alice publishes a new message')
    msg = b'cats rule, dogs drool'
    alice.publish_message(DATA_CHANNEL, 'my-cat', msg, NEW_KEY_CHANNEL)
    print('  - Alice and Bob can read the new messages')
    print(alice.read_message(DATA_CHANNEL, 'my-cat'))
    print(bob.read_message(DATA_CHANNEL, 'my-cat'))

    print('  - Eve has no key ring for the new message')
    try:
        print(eve.read_message(DATA_CHANNEL, 'my-cat'))
    except KeyError as exc:
        print('KeyError: ', exc)

    print('  - Eve tries using a hacked client...')
    block = eve.pdi.read(DATA_CHANNEL, 'my-cat')
    print(block)
    try:
        eve.ski.keyrings[KEY_CHANNEL].decrypt(block.data)
    except nacl.exceptions.CryptoError as exc:
        print('CryptoError: ', exc)
        print('... but fails!')



if __name__ == '__main__':
    run_demo()
