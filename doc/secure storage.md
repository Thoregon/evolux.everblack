Secure Storage in gun
=====================

- Basic Secure Store
    - owner 
        - keypair stored in the admins member entry (and as attest at the admins user if it is a user)
        - o: { pub, epub }
    - s : <salt>
    - temp store will not store the admin member entry
    - public store
        - everyone can add, but must encrypt ans sign
    - private store
        - invite identities 
            - write: there is the write keypair stored in the members entry
            - read: write keypair is missing, only write pub keys available for verifying
    
to avoid tracking the key for member entries will be generated:
- build a DH secret with owner.epub & identity.pair ->  await identity.sharedSecret(this.owner.epub)
- hash secret with the sores salt ->   

## Use Cases

Secure stores must not only provide secrecy, but must also prevent tracking.

Secure stores can be used by entities implementing the identity API.
Wrap keypairs with an IdentityShim.

### Private Store

A store for private communication. Only invited members can read, only permitted members can write.
 
todo: enable admins w/o write permission, but how do they permit 'write' for new members?
todo: enable admins w/o read permission, how?

Create private store:
- create owner keypair. all members knowing this pair can manage members.
    - store has its own keypair, its not the pair from the creator
- create write keypair. all members knowing this pair can write to store.
- create a salt for this store
- sharedKey = create random key 
- --> create admin member entry as owner with write permission for the creator (id).
- persist in matter
 
Create a member entry 
- secret = member.sharedSecret(owner.epub)
- member key = work(secret, salt)
- encrypt member entry with the secret
- sign member entry 
- member entry contains
    - alias
    - member.pub & epub
    - ownerpair if admin
    - writepair if write permission

Add member:
- find admin member entry -> build member key
    - secret = admin.sharedSecret(owner.epub)
    - member key = work(secret, salt)
- decrypt member entry
- check owner pair -> missing: no permission
- --> create member entry for new member

Unlock store for member:
- find admin member entry -> build member key
    - secret = admin.sharedSecret(owner.epub)
    - member key = work(secret, salt)
- decrypt member entry

Get/Listen to entries
- find and decrypt member entry
- get items
    - verify with write.epub
    - decrypt with sharedKey

Push entry:
- find and decrypt member entry
- check write pait -> missing: np permission
- encrypt item with sharedKey
- sign item with writePair
- add the items in matter

### Public Store

Owner provides a store for all others, but enable a private
communication no one other can read except owner and requestor.
A public store is much simpler because there is no sharedKey
and no write keypair. Every one can write, but only owner
can read.

Create public store
- create owner keypair
- --> create admin member entry as owner for the creator (id).
- persist in matter

Create a admin entry 
- secret = member.sharedSecret(owner.epub)
- member key = work(secret, salt)
- encrypt member entry with the secret
- sign member entry 
- member entry contains
    - alias
    - member.pub & epub
    - ownerpair if admin

Only owner listens on items

Push request
- reqPair = create keypair
- secret = reqPair.sharedSecret(owner.epub)
- encrypt request with secret
- sign request with reqPair
- persist in matter

Owner reads request
- verify request with req.pub
- secret = owner.sharedSecret(req.epub)
- decrypt with secret

Set response
- secret = owner.sharedSecret(req.epub)
- encrypt request with secret
- sign request with ownerPair
- persist in matter (replace item)
    - requestor should listen on it

