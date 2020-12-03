everblack
=========

This is the encryption of thoregon. It enables privacy.
If you share information, it can never be taken back.

Requires and identity (user). This identity should be secured with 2 factor authentication.

in a distributed system there are potential security threats,
which we encounter with everblack:

- unauthorized access
- unauthorized tampering
- denial of service

security            -> https://xkcd.com/538/
password strength   -> https://xkcd.com/936/
sql injects         -> https://xkcd.com/327/

everblack provides attribute encryption

## Freedom of algorithms
Basic algorithms used for encryption/decryption, key generation, also
for the management and processing of the stored data must be freely selectable by the user.

Everblack defines APIs for the different use cases. Users can choose those implementations
they trust. There is no forced installation, users can always  always reject it.

The everblack components offer a special shop where components are 
registered, tested and evaluated.

## BlackObject structure

Each black object grants access to its 'direct' attributes.
References to other objects may also be a black object.

the permission metadata stored in the attribute 't͛eb' (thoregon everblack).

## Scenarios

### Private use
Encryption/decryption only for the user, no shared data 

### Public use, share encrypted data

User sends a command to a public bounded context
- share encrypted data
- between
    - users
    - bounded contexts and roles

Process for A and B. A and B  can be users, roles, bounded contexts and other entities - mixed together - supporting encryption
- through the wormhole (to other side)
    - A generates a shared key using its pair (private key) and the public key from B
    - A ecrypts the data with the shared key
    - A signs the encrypted data with its pair (private key)
    - encrypted and signed data stored in specified property

- out of the wormhole (to this side)
    - B generates a shared key using its pair (private key) and the public key from A
    - B verifies the data from the specified property with the public key from A -> exit if it fails
    - B decrypts the encrypted data with its pair (private key)
    - stores decrypted data in the specified property

## Role based encryption 
Used to implement role based access control to stored data. a permissions spec is stored 
in the everblack control property.




### Permissions

Permissions are granted by attesting a verifiable claim to an identity

the list of properties specifies the data you can decrypt with the shared key for this role.
if the access is 'W' for write, you are also allowed to store encrypted data in the property.
well technically you can write locally to a property you are not allowed, but the firewall adapters
on other peers and also your local storage engine will reject it. 
it will also be overwritten by the original value. 

this applies also to changes to the permissions itself. only changes which can be verified with
the pub key of the admin (role) will be accepted by other peers. 
an exchange of the admin role will only accepted if the 'proof' can be verified with the previous pub key.
initially the 'proof' is empty.

``` javascript
permissions: {
    pub: <public key of the admin (role) to grant/revoke permissions>,
    proof: <a proof which can be verified with the previous admin pub key>,
    roles: {
        <rolename>: <encrypted control data>
    }
}

// the decrypted control contains  
control: {
    key: <shared key to decrypt the entry>
    properties: {
        <propertyname>: {
            pub: <public key of the last writer for verify>
        }
    },
    access: 'R' | 'W'
}
```

Process for R(ole):
- prepare for use
    - get the control data for R
    - verify the control data with the admin pub key -> exit if it fails
    - decrypt the control data with priv key from R
    - get the shared key from control data

Process for A(dmin):
- prepare for create

- change admin pub key

## Shared secrets

Shared secrets generation

- procedure

``` javascript
    const shared = async () => {
        let alice = await SEA.pair();
        let bob = await SEA.pair();
        let shared1 =  await SEA.secret(bob.epub, alice);
        let enc = await SEA.encrypt('This can only be read by alice & bob', shared1);
        let shared2 = await SEA.secret(alice.epub, bob);    // .secret is Elliptic-curve Diffie–Hellman
        let dec = await SEA.decrypt(enc, shared2);
        universe.logger.info('[everblack]',dec);
    };
```

Gun Security:
- https://gun.eco/docs/SEA
- https://gun.eco/docs/User
- https://gun.eco/docs/Auth
- https://gun.eco/docs/FAQ#acl
- https://gun.eco/docs/Security
- https://gun.eco/docs/Privacy-What-You-Need-To-Know
- https://gun.eco/docs/Security%2C-Authentication%2C-Authorization

## Persistence

Encode/Sign -> Verify/Decode/



### Create Identity



### Request Attest

An Attest/Verifiable Claim/Permission can now be requested.

### Attestation



## Registries

### Identities

- universal available

### Bounded Contexts

- private registry
- public registry for domain events and commands

## Procedure

- create key pair for bounded context
- store in matter encoded and signed (like user): matter.ddd.ctx.<publickey>
- the key for encoding the key pair is stored on the sovereign node
- reliant node create their onw key pair
    - stores its public key in the reliant list of the bc
    - a shared secret is created on both sides: SEA.secret()
    - the shared secret is now used for processing
 
## 2FA (two factor authentication)


### FIDO

- FIDO device
- handshake procedure
- authentication procedure


### Secure SMS

Version 1

- additional app (client)
    - auto-fill secret code in web form elems
- permissions 
    - read SMS
    - ? fill form elems
- handshake procedure
    - provider sends SMS with public key and a mnemonic
    - client creates salted derived secret key (pow) with provider pub key and own keypair (--> shared secrets)
    - encodes menmonic with  shared secret
    - sends encoded menmonic with salt and own public key to provider
    - provider decodes and stores public key if menmonic is OK
- authentication procedure
    - provider creates salted secret key (pow) with clients pub key and own keypair
    - provider genrates a 5 digit/char secret code
    - provider encodes secret code and sends it with the salt to the client
    - client app received SMS and decodes the secret code
 
Version 2
- provider publishes public key
- 
