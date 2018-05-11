# PLAN Permissions Model

*A Unix-style users and permissions model for the [PLAN Persistent Data Interface (PDI)](http://plan.tools), with prototype built on top of an Ethereum private block chain.*

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

## Shamir Secret Sharing

Enter [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing). In this algorithm, a secret is divided into multiple parts and the parts are distributed to the users. Any "threshold value" _n_ of the parts can be used to decrypt anything encrypted with the secret, where the value of _n_ is configurable at the time the key is generated. This algorithm is often used to require multiple people to collaborate to decrypt something (like having 2 people "turn their keys" to launch the missiles from a submarine). But in our case we can use a threshold value of 1 to allow any single peer to decrypt.

Shamir Secret Sharing has been demonstrated in successful open source commercial products such as [Hashicorp's Vault](https://www.vaultproject.io/). Much like in Vault, we'll rely on Shamir Secret Sharing to perform "envelope encryption" for all data stored on the chain.

Encryption for a PDI is initialized by the SKI as follows:

1. The SKI is passed a list of public keys for users who will be part of the initial peer group (bootstrapping is discussed later).
2. The SKI creates a master symmetric key.
3. The SKI encrypts the master symmetric key using Shamir Secret Sharing, with a number of "unsealing" parts equal to the number of peers and a threshold value of 1.
4. Each unseal part is encrypted with one (1) peer's public key.
5. The encrypted master symmetric key is written as a data block to the PDI.
6. The encrypted unsealing keys are distributed to the peers.
7. Each peer's SKI decrypts the unsealing key and adds it to its key ring.

Note that in this workflow no cleartext keys ever leave the SKI, but this creates an implementation quirk that all PDIs depend on a SKI's encryption model (and in theory we can have multiple versions of the SKI encryption model).

When a peer wants to write a new block:
1. PLAN passes the SKI the data to be encrypted and the encrypted master symmetric key block.
2. The SKI decrypts the master key.
3. The SKI uses the master key to encrypt the data.
4. The SKI returns the encrypted data to PLAN.

When a peer wants to read a block:
1. PLAN passes the SKI the encrypted data and the encrypted master symmetric key block.
2. The SKI decrypts the master key.
3. The SKI uses the master key to decrypt the data.
4. The SKI returns the unencrypted data to PLAN.

When a new member is added to the peer list, a "rekey" procedure is required (similar to how its done in [Vault](https://www.vaultproject.io/docs/internals/rotation.html)).

1. The SKI is passed a list of public keys for users who are part of the new peer group.
2. The SKI is passed a the encrypted master key from the PDI.
3. The SKI decrypts the master key.
4. The SKI re-encrypts the master key using Shamir Secret Sharing, with a number of "unsealing" parts equal to the new number of peers and a threshold value of 1.
5. Each new unseal part is encrypted with one (1) peer's public key.
6. The re-encrypted master symmetric key is written as a data block to the PDI.
7. The new encrypted unsealing keys are distributed to the peers.
8. Each peer's SKI decrypts the new unsealing key and adds it to its key ring.

Note that this rekeying process does not rotate the master key. When a member is ejected from the community, a new master key can be created for all new data. All existing data can still be decrypted by the ejected member, but as we saw earlier there's no way around this problem in an immutable append-only replicated data store. At best one could create a new master key and rebuild the entire PDI data store, but given that the ejected member has their own offline copy of the data already this extra work doesn't accomplish anything.

## Key Distribution

_TODO_

## Protocol And Channel Schema

_TODO_
