Secure Storage in gun
=====================

- Basic Secure Store
    - o
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
    

## Anti tracking & Authentication    
to avoid tracking the key for member entries will be generated:
- build a DH secret with owner.epub & identity.pair
- hash pub key + secret (the pepper) with the stored salt

this idhash is also used for authentication



## Use Cases

Secure stores must not only provide secrecy, but must also prevent tracking.

Secure stores can be used by entities implementing the identity API.
Wrap keypairs with an IdentityShim, let them act like an identity.

### Public Store
Only the owner can write encrypted and signed content,
all others can verify and decrypt all content.

This is the simplest case

#### Directory
- an owner established a directory
- all others can read and listen to the directory

### Two Attendants
Owned by a single keypair. 
Can be public, everyone can write, post can be only decrypted by the client or the owner, no one else can read/modify.
Owner can optionally publish the object with a name (KARTE - thoregon directory)
The items are encrypted asymmetric, only owner and attendant can encrypt and decrypt the entries.

#### Service Queue
- a owner (service) establishes a service queue
- the queue can be accessible by all or only by invited members
- the client (member) pushes a request to the queue and awaits the response
- service processes the request and responds with a result or an error
a service queue is similar to a micro service

#### Message Store
- an identity establishes a message store
- the message store can be accessable by all or only by invited members
- the client (member) pushes a message to the message store
- no Response necessary, but with 'ctrl' and 'sctrl' the status can be published
- the client can specify an address for an answer message store 
a message store is similar to email 


### Multiple Attendants
A store for private communication.
An item is typically encrypted with a symmetric shared key. Everyone who has the key can encrypt and decrypt.
Every item is signed with the write pair. Only who has the write pair can sign, others can only verify. 
Only invited members can read. 
Only permitted members can write.
Only owners can invite members and grant permissions.

the identity which creates the object is also owner (admin) -> will get the owner keypair in its member entry
admin can invite others and grant/revoke write permission
admin can grant ownership to others

#### Channel
- an owner (admin) establishes a channel and invites others 
- all invited (and also all owners) can push items to the channel
- an item can refer to another
a channel is similar to a chat 

#### Topic
- everyone can read items
- public accessible, items can be read by all, but modified only by the publisher
- an item can refer to another
a topic is similar to a whiteboard

#### Event Queue
- an owner (service) establishes an event queue
- The queue can be accessable by all or only by invited members
- the client (member) pushes a listener to the queue, eventually with a filter
- past events will be filtered with the universe time (universe.now) 
- the service publishes events to the queue

#### Collection
- an owner (admin) establishes a collection and invites others 
- all invited (and also all owners) can add/drop/modify items in the collection

#### Key Value Store
- an owner (admin) establishes a key value store and invites others 
- all invited (and also all owners) can get/put/delete items in the collection with a key
- reference will be 

#### Entities
- a owner (admin) establishes a key value store and invites others
- owner grants write permissions to properties
- an entity can be teh content on a property, possibly having other owner and permissions

## Firewall Adapter
To protect secure stores, there is an adpater acting as firewall.
Is also does the encryption/sign and verify/decryption.

It distinguishes between items for two attendents, which uses just a shared secret (async with DH). 
This secret can only be built by one of the two attendents. All items of this kind have the same structure.
the payload from both (member and admin) is encrypted and signed 

The other case is multiple attendents. This requires a (synchronous) shared key for encryption
and a write pair to sign. 

authentication is done with the idhash. 



### Multi Attendants Store

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

### Owner Store

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

