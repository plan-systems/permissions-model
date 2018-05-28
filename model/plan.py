"""
plan.py - represents the core plan software from the perspective of the user
"""
from ski import SKI


class User(object):
    """
    a User mostly proxies to the SKI or PDI operations, and represents the
    user and their activities with the core PLAN software that communicates
    with the PDI and SKI plugins
    """
    def __init__(self, user, pdi):
        self.user = user
        self.ski = SKI(user)
        self.pdi = pdi # we just need this as a reference

    def publish_keys(self, key_channel):
        """ publish public key and signing verification key to PDI """
        pkey = self.ski.get_public_keyblock(key_channel)
        self._write(key_channel, '{}/public'.format(self.user), pkey, key_channel)
        vkey = self.ski.get_verify_keyblock(key_channel)
        self._write(key_channel, '{}/verify'.format(self.user), vkey, key_channel)

    def vouch(self, who, key_channel):
        """ vouch for a user on a given key channel """
        who_pkey = self._get_user_public_key(key_channel, who)
        voucher = self.ski.vouch(key_channel, who_pkey)
        self._write(key_channel, '{}/master'.format(who), voucher, key_channel)

    def publish_message(self, channel, path, message, key_channel):
        """ published a message on a channel """
        encrypted_and_signed = self.ski.encrypt(key_channel, message)
        self._write(channel, path, encrypted_and_signed, key_channel)

    def read_message(self, channel, path):
        """ read the most recent message from a channel """
        block = self.pdi.read(channel, path)
        author = block.author
        encrypted = block.data
        key_channel = block.key_channel
        author_vkey = self._get_user_verify_key(key_channel, author)
        message = self.ski.decrypt(key_channel, encrypted, author_vkey)
        return message

    def load_master_key(self, key_channel):
        """ load the master key """
        block = self.pdi.read(key_channel, '{}/master'.format(self.user))
        voucher = block.author
        encrypted = block.data
        voucher_pkey = self._get_user_public_key(key_channel, voucher)
        return self.ski.load_master_key(key_channel, encrypted, voucher_pkey)

    def _write(self, channel, path, block, key_channel):
        """
        write a raw block to the PDI (assumes you've already encrypted
        and/or signed as required)
        """
        block_idx, block_id = self.pdi.write(self.user, channel, path, block, key_channel)
        return block_idx, block_id

    def _get_user_verify_key(self, key_channel, user):
        """ helper to get a user's signature verification key """
        vblock = self.pdi.read(key_channel, '{}/verify'.format(user))
        vkey = self.ski.from_verify_keyblock(vblock.data)
        return vkey

    def _get_user_public_key(self, key_channel, user):
        """ helper to get a user's public key """
        vkey = self._get_user_verify_key(key_channel, user)
        pkblock = self.pdi.read(key_channel, '{}/public'.format(user))
        pkey = self.ski.from_public_keyblock(key_channel, pkblock.data, vkey)
        return pkey
