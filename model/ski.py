"""
ski.py - represents the Secure Key Interface module
"""
import binascii
import json
import os
import sys
import uuid

import nacl.encoding
from nacl.public import PublicKey, PrivateKey, Box
import nacl.secret
import nacl.signing
import nacl.utils

DIR = './data'    # default output directory for demo
if not os.path.exists(DIR):
    os.makedirs(DIR)


# file schema
VERSION = '0.0.1' # protocol version
CURVE = 'Ed25519'
KEY_TYPE = 'OKP'  # not super sure about this field value but our
                  # implementation doesn't consume it anyways


class SKI:
    """
    SKI is mostly a proxy object to the various Keyrings. In the real
    implementation the Keyrings will be out-of-process, so the SKI would
    probably be where we do the serialization/deserialization to the
    Keyring.
    """
    user = None
    keyrings = None

    def __init__(self, user):
        self.user = user
        self.keyrings = {}

    def new_keyring(self, keyring_name):
        """
        initializes a new Keyring (including generating keys if not already
        on-disk), but doesn't generate a new master key
        """
        if keyring_name in self.keyrings:
            print('rekeying keyring {}'.format(keyring_name))

        keyring = Keyring(self.user, keyring_name)
        self.keyrings[keyring_name] = keyring

    def new_masterkey(self, keyring_name):
        """ initializes a new Keyring """
        if keyring_name not in self.keyrings:
            self.new_keyring(keyring_name)

        keyring = self.keyrings[keyring_name]
        keyring.generate_master_key()

    def vouch(self, keyring, public_key):
        """ vouch for another user's public key on this keyring """
        return self.keyrings[keyring].vouch(public_key)

    def load_master_key(self, keyring, block, public_key):
        """ load master key for channel keyring """
        return self.keyrings[keyring].load_master_key(block, public_key)

    def encrypt(self, keyring, plaintext):
        """ request encryption (and signing) by channel keyring """
        encrypted = self.keyrings[keyring].encrypt(plaintext)
        signed = self.keyrings[keyring].sign(encrypted)
        return signed

    def decrypt(self, keyring, signed, verify_key_hex):
        """ request decryption (and verification) by channel keyring """
        verified = self.keyrings[keyring].verify(signed, verify_key_hex)
        decrypted = self.keyrings[keyring].decrypt(verified)
        return decrypted

    def sign(self, keyring, data):
        """ request signing by channel keyring """
        return self.keyrings[keyring].sign(data)

    def verify(self, keyring, data, verify_key_hex):
        """ request verification by channel keyring """
        return self.keyrings[keyring].verify(data, verify_key_hex)

    def get_public_keyblock(self, keyring):
        """
        output the signed JSON representation of the asymmetric public
        key for writing to the PDI key channel
        """
        keyring = self.keyrings[keyring]
        unsigned = keyring.to_public_keyblock()
        return keyring.sign(unsigned)

    def get_verify_keyblock(self, keyring):
        """
        output the unsigned JSON representation of the signing
        verification key, for writing to the PDI key channel
        """
        keyring = self.keyrings[keyring]
        unsigned = keyring.to_verify_keyblock()
        return unsigned

    def from_verify_keyblock(self, block):
        """ get the decoded verify key from the a block """
        data = json.loads(block.decode('ascii'))
        return data['key']['x'].encode('ascii')

    def from_public_keyblock(self, keyring, signed, vkey):
        """ get the decoded verify key from the a block """
        verified = self.keyrings[keyring].verify(signed, vkey)
        data = json.loads(verified.decode('ascii'))
        return data['key']['x'].encode('ascii')



class JSONSafeHexEncoder:
    """
    nacl.encoding.HexEncoder returns bytes but JSON serialization
    barfs on that, so this helper takes the encoded bytes and
    safely encodes them to ASCII
    """
    @staticmethod
    def encode(data):
        return binascii.hexlify(data).decode('ascii')

    @staticmethod
    def decode(data):
        return binascii.unhexlify(data).decode('ascii')


class Keyring:

    keyring = '' # versioned keyring name (ex. 'cats/0')

    # for asymmetric encryption
    enc_key = None
    enc_key_id = None

    # for signing
    signing_key = None
    signing_key_id = None

    # for symmetric encryption
    _master_key = None
    _secret_box = None

    def __init__(self, user, keyring, filename=None):
        """
        we want to keep all the cryptographic functions as side-effect
        free as possible, so when we instantiate a keyring we'll do as
        much of the setup and I/O as possible.
        """
        self.keyring = keyring
        if not filename:
            filename = keyring.lstrip('/key').replace('/', '.')
            filename = os.path.join(DIR, '{}.{}'.format(user, filename))

        try:
            self._load_from_private_keyfile(filename)
        except FileNotFoundError:
            self.enc_key = PrivateKey.generate()
            self.signing_key = nacl.signing.SigningKey.generate()
            self.enc_key_id = uuid.uuid4().hex
            self.signing_key_id = uuid.uuid4().hex
            self._to_private_keyfile(filename)

    def generate_master_key(self):
        """
        create a new master key. the user will want to write this master
        key to the PDI by vouching for themselves and then vouch for any
        other users who want to use the same key.
        """
        self._master_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        self._secret_box = nacl.secret.SecretBox(self._master_key)

    def vouch(self, public_key):
        """
        given the public key of another user, asymmetrically encrypt the
        master key. this encryption inherently includes authentication so
        we don't need to also sign this block.
        """
        assert self._master_key is not None
        pkey = PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
        box = Box(self.enc_key, pkey)
        encrypted = box.encrypt(self._master_key)
        data = {
            'version': VERSION,
            'key': encrypted.hex()
        }
        return json.dumps(data).encode('ascii')

    def load_master_key(self, block, public_key):
        """
        given a master key block from the PDI encrypted for this user,
        and the public key of the user that vouched for them, load the
        master key into memory and set up the symmetric encryption engine.
        Note that we can't do this in the constructor because only the
        first keyring user is going to want to generate a new master key.
        (Note: this is the reverse operation to 'vouch')
        """
        pkey = PublicKey(public_key, encoder=nacl.encoding.HexEncoder)
        block = json.loads(block.decode('ascii'))['key']
        msg = nacl.utils.EncryptedMessage.fromhex(block)
        box = Box(self.enc_key, pkey)
        plaintext = box.decrypt(msg)
        self._master_key = plaintext
        self._secret_box = nacl.secret.SecretBox(self._master_key)

    def encrypt(self, plaintext):
        """
        symmetric encryption of the message body using the master
        key. asserts that we've loaded the master key onto the keyring
        """
        assert self._master_key is not None
        assert self._secret_box is not None
        ciphertext = self._secret_box.encrypt(plaintext)
        return ciphertext

    def decrypt(self, ciphertext):
        """
        symmetric decryption of the message body using the master
        key. asserts that we've loaded the master key onto the keyring
        """
        assert self._master_key is not None
        assert self._secret_box is not None
        plaintext = self._secret_box.decrypt(ciphertext)
        return plaintext

    def sign(self, data):
        """
        given a blob of data, add a message signature
        """
        signed = self.signing_key.sign(data)
        return signed

    def verify(self, block, verify_key_hex):
        """
        given a data block (which should be encrypted) and the encoded
        signing verify key of a user, verify the message signature.
        will raise nacl.exceptions.BadSignatureError if the check fails
        """
        verify_key = nacl.signing.VerifyKey(verify_key_hex,
                                            encoder=nacl.encoding.HexEncoder)
        message = verify_key.verify(block)
        return message

    @property
    def public_key(self):
        return self.enc_key.public_key.encode(JSONSafeHexEncoder())

    def to_public_keyblock(self):
        """
        output the JSON representation of the asymmetric public key
        for writing to the PDI key keyring
        """
        data = {
            'version': VERSION,
            'key': {
                'crv': CURVE,
                'kty': KEY_TYPE,
                'kid': self.enc_key_id,
                'use': 'enc',
                'x': self.enc_key.public_key.encode(JSONSafeHexEncoder())
            }
        }
        return json.dumps(data).encode('ascii')


    @property
    def verify_key(self):
        return self.signing_key.verify_key.encode(JSONSafeHexEncoder())

    def to_verify_keyblock(self):
        """
        output the JSON representation of the signing verify key
        for writing to the PDI key keyring
        """
        data = {
            'version': VERSION,
            'key': {
                'crv': CURVE,
                'kty': KEY_TYPE,
                'kid': self.signing_key_id,
                'use': 'signing',
                'x': self.signing_key.verify_key.encode(JSONSafeHexEncoder())
            }
        }
        return json.dumps(data).encode('ascii')


    def _load_from_private_keyfile(self, filename):
        """
        loads the user's private keys from a local file into memory.
        in a real SKI this will use the secure persistent implementation
        of the SKI's hardware backing
        """
        try:
            with open(filename, 'r') as keyfile:
                data = json.loads(keyfile.read())
                for key in data['keys']:
                    if key['use'] == 'signing':
                        hex_key = key['x']
                        self.signing_key_id = key['kid']
                        self.signing_key = nacl.signing.SigningKey(
                            hex_key,
                            nacl.encoding.HexEncoder())
                    elif key['use'] == 'enc':
                        hex_key = key['x']
                        self.enc_key_id = key['kid']
                        self.enc_key = PrivateKey(
                            hex_key,
                            nacl.encoding.HexEncoder())

        except PermissionError:
            # a keyfile exists but we're not allowed to get it.
            print('tried to access keyfile {} but got PermissionError'.format(filename))
            sys.exit(77)
        except (KeyError, json.decoder.JSONDecodeError):
            print('private keyfile {} was in invalid format'.format(filename))
            sys.exit(1)
        except FileNotFoundError:
            # let this bubble up so that we can create a new keyfile
            raise

    def _to_private_keyfile(self, filename):
        """
        write the user's private keys to local file. in a real SKI
        this will have a secure persistence implementation taking
        advantage of the SKI's hardware backing
        """
        data = {
            'version': VERSION,
            'keys': [
                {
                    'crv': CURVE,
                    'kty': KEY_TYPE,
                    'kid': self.signing_key_id,
                    'use': 'signing',
                    'x': self.signing_key.encode(JSONSafeHexEncoder())
                },
                {
                    'crv': CURVE,
                    'kty': KEY_TYPE,
                    'kid': self.enc_key_id,
                    'use': 'enc',
                    'x': self.enc_key.encode(JSONSafeHexEncoder())
                }
            ]
        }
        try:
            with open(filename, 'w') as keyfile:
                keyfile.write(json.dumps(data))
        except Exception:
            raise # just crash at this point so we can debug this
