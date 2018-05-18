# PLAN Permissions Model

*A Unix-style users and permissions model for the [PLAN Persistent Data Interface (PDI)](http://plan.tools), with prototype built on a PDI implementation that uses Ethereum in private proof-of-authority (PoA) mode. See the PLAN Plugin Architecture for more.*

## Unix-style?

Identity and access management has two overarching problems. **Authentication** is identifying a user (or **Principal**) and determining that they really are who they say they are. **Authorization** is the process for deciding whether a given user has access to a given **Resource** in the system.

Calling permissions "Unix-style" is loosely defined, but for our purposes we'll describe this as follows:

- Separation of Read and Write **Permissions**. ("Execute" permission isn't relevant here.)
- Principals can be nested: a "user" can be a member of a "group".
- Resources can be nested: a "file" can be in a "directory."
- Resources have metadata that tags them with a Authorization tuple: `(resource, principal, permissions)`.
- Access by any given Principal to any given Resource is "default deny".
- Whether a given Principal can perform an action on a given Resource is determined by a union of all Authorization tuples that apply to the Principal (and its parent Principals) and the Resource (and its parent Resources).

## Complications of Immutable Data

Data written to the PLAN Persistent Data Interface (PDI) has a number of properties that complicate the creation of the Unix-style permissions model described above.

- The data store is append-only, and blocks appended to the data store are immutable.
- There is no first-class concept of nested data blocks; any nesting can only exist as metadata.
- There is no first-class concept of metadata; any metadata has to be stored on-chain either as part of the data block or as an additional data block.
- The only way to "turn back the clock" on the data store is to make a point-in-time fork of the chain by consensus among peers.
- Blocks on the data store are replicated to all full peers. Even if peers come to consensus to make a point-in-time fork of the chain, any peer can retain the existing replicated data.
- All peers have "physical access" to the replicated data, so any permissions model must take into account out-of-band access to the data blocks.

## Complications of Asymmetric Encryption

The PLAN Secure Key Interface (SKI) provides public/private key management as well as encryption, decryption, and signing services to the rest of PLAN. Asymmetric encryption can be used to implement many of the properties we want, with several caveats.

- A "group" principal can be defined as a set of public keys (including a group with a single user principal).
- Data blocks can be asymmetrically encrypted using the private key of their author, with the public key of all users in the group (up to all users in the community) as recipients.
- When a new Principal joins they cannot decrypt any previous data blocks. Giving a new Principal access to existing data requires it to be re-encrypted for that new Principal and added to the chain.
- Access to existing data can never be revoked. A key can be revoked but this only removes it from the web of trust; all existing data encrypted for that key can still be decrypted.
- Losing or rotating keys makes the user lose access to all data. Even if we provided a way to manage a primary key and subkeys in the SKI, the primary key is unable to decrypt data encrypted for any of the subkeys.

The inability to easily rekey or add members to the group makes implementing the full set of desired Unix-style properties with a simple public/private key exchange impractical.

## Envelope Encryption

Instead of encrypting data via asymmetric encryption, PLAN will use symmetric encryption with a shared key that is distributed on a `/pdi/${pdi}/key` channel (where `$pdi` is one of `eth`, `pswarm`, etc.), which we'll refer to as a **Key Channel** below. The shared key is asymmetrically encrypted for the public key of each user who should have access to the data. Because data for a given PDI is projected onto multiple channels, each channel can have its own associated key channel.

Encryption for a given PDI channel is initialized by a user's SKI as follows:

1. The user creates a named and versioned key channel.
2. The user's SKI generates a public-private key pair for that channel.
3. The user's SKI generates a master symmetric encryption key for that channel.
4. The user's SKI encrypts the master key with their keypair.
5. The user writes their public key to the key channel, under their user namespace.
6. The user writes the encrypted master key to the key channel, under their user namespace. (This step is not strictly necessary for the initial user but making it uniform for all users makes re-keying less complicated).

When a peer wants to write an encrypted block of data:
1. PLAN passes the SKI the data to be encrypted and the encrypted master symmetric key block for the channel.
2. The SKI decrypts the master key using its private key for that channel.
3. The SKI uses the master key to encrypt the data.
4. The SKI uses the user's key to sign the encrypted data.
4. The SKI returns the encrypted/signed data to PLAN.
5. PLAN writes this encrypted/signed data to the PDI.

Note that in this workflow no cleartext keys ever leave the SKI. This means that a given channel depends on a the SKI's encryption model; we can have multiple encryption processes shared on a PDI for different channels, but all peers need to use the same encryption algorithm for a given channel. The SKI itself can use a different storage backend so long as it supports an identical encryption algorithm.

When a peer wants to read a block:
1. PLAN passes the SKI the encrypted/signed data and the encrypted master symmetric key block for that channel.
2. The SKI decrypts the master key using its private key for that channel.
3. The SKI verifies the signature of the data against the public key of the originating user.
3. The SKI uses the master key to decrypt the data.
4. The SKI returns the unencrypted data to PLAN.

When a new member is added to the peer list for a channel, no "rekeying" procedure is required. The new peer's SKI generates a public-private key pair for the channel, and the new peer writes their public key to the key channel, under their user namespace. But at this point, the new peer does not yet have access to the data. Another member must **Vouch** for the new member as follows:

1. The vouching member's PLAN software passes the new member's public key to their SKI, along with the encrypted master key for that channel.
2. The SKI decrypts the master key using its own private key for that channel.
3. The SKI encrypts the master key for the public key of the new member.
4. The SKI returns the encrypted master key to PLAN.
5. PLAN writes the encrypted master key to the key channel, under the new user's namespace.

Because the underlying PDI block for the new member has been written by an existing member, a chain of trust is created between members. Any member that has access to a channel has been vouched by an existing member (except for the first member).

When a member is ejected from the community, a new master key can be created for all new data by creating a new version of the key channel. All existing data can still be decrypted by the ejected member, but as we saw earlier there's no way around this problem in an immutable append-only replicated data store. At best one could create a new master key and rebuild the entire PDI data store, but given that the ejected member has their own offline copy of the data already this extra work doesn't accomplish anything.

## Example

In the example below, Alice wants to create a new encrypted chat channel for cat enthusiasts.

1. Alice creates a new `./key/kitties/1` channel.
2. Alice's SKI generates a new private-public keypair, associated with the `./key/kitties/1` channel.
3. Alice's SKI generates a new symmetric master key associated with the `./key/kitties/1` channel.
4. Alice writes her public key to `./key/kitties/1/alice/public`
5. Alice writes the encrypted master key to `./key/kitties/1/alice/master`

Bob wants to join in the chat.

1. Bob's SKI generates a new private-public keypair, associated with the `./key/kitties/1` channel.
2. Bob writes the the public key to `./key/kitties/1/bob/public`
3. Bob asks Alice to vouch for him, either in a different channel or offline.
4. Alice's PLAN software takes the public key from `./key/kitties/1/bob/public` and the master key from `./key/kitties/1/alice/master`.
4. Alice's SKI re-encrypts the master key with Bob's key and passes it back to PLAN.
5. Alice's PLAN software writes the encrypted master key to `./key/kitties/1/bob/master`.

Now Bob's PLAN and SKI software can use this key to participate in the chat and read all previous discussions.

Later, Eve has joined the chat but soon begins annoying other users by posting dog pictures. The community decides to expel Eve by re-keying the channel.

1. Alice's creates a new `./key/kitties/2` channel.
2. All users who accept the re-key write their public keys to `./key/kitties/2/${name}/public`
3. Alice's PLAN software passes all public keys to the SKI.
4. Alice's SKI generates a new symmetric master key associated with the `./key/kitties/2` channel.
5. Alice's SKI encrypts the master key for each of the public keys and passes the encrypted key(s) back to PLAN.
6. Alice's PLAN software writes the encrypted master key to each `./key/kitties/2/${name}/master`, just as if she'd vouched for all of them.

Note that any peer can initiate a re-key but it requires consensus by the other peers who will add their public keys to the new key channel. It's entirely possible for a given subcommunity for a channel to "split" and use a separate (possibly partially overlapping) set of keys. This is not a problem from a security or integrity perspective but should probably be handled gracefully by PLAN so that we don't show users data that's encrypted for keys they don't have.


## Protocol And Channel Schema

The channel path schema is as follows:

```
/pdi/${pdi_type}/key/${channel_name}/${version}/${user}/${doc_type}

    $pdi_type     = (pswarm|eth|babble)
    $channel_name = String
    $version      = Positive Integer
    $user         = String
    $doc_type     = (public|master)
```

The encryption primitives of the protocol can be specific to each SKI implementation, but a recommended implementation would be as follows:

- **`AES`** in **`CBC`** mode with a 128-bit master key for symmetric encryption, using **`PKCS7`** for padding
- **`ECDSA`** with a 256-bit private key (providing a 128 bit key strength) for asymmetric encryption and signing

The channel document schema for a user's public key is as follows (shown with dummy data):

```json
{
  "version": "1.0.0",
  "key":  {
    "kty": "EC",
    "use": "enc",
    "crv": "P-256",
    "kid": "8c7c909e-5763-4a66-92b5-dc622a448797",
    "x": "mHsfhR-M8QalLEND160idqT-4GaQsg9WG9-kjCe4jeQ",
    "y": "W7anvWHIH14qdQzXJPyQyOpkWiefztwCFG47FxvnM_k",
    "alg": "ES256"
  }
}
```

The fields above are as follows:
- **version**: the schema version, this could include specific SKI versions.
- **key**: the public key of the user, JWK-encoded (fields below are part of the JWK spec).
  - **kty**: key type (typically `EC` for Elliptic Curve).
  - **crv**: elliptic curve used.
  - **kid**: unique key ID.
  - **x**: public key X-value.
  - **y**: public key Y-value.

The channel document schema for the encrypted master key is as follows (shown with dummy data):

```json
{
  "version": "1.0.0",
  "key": "xxxxxx",
  "signature": "xxxxx",
  "signer": "/pdi/eth/key/kitties/1/alice/public"
}
```

The fields above are as follows:
- **version**: the schema version, this could include specific SKI versions.
- **key**: the encrypted master key.
- **signature**: the signature for the `key` field, by the user who wrote this document.
- **signer** a path to the public key of the user who wrote the document.
