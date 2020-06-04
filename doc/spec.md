everblack
=========

This is the encryption of thoregon. It enables privacy.
If you share information, it can never be taken back.

Requires and identity (user). This identity should be secured with 2 factor authentication.

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

Encode/Sign -> Decode/Verify

- 

## Permissions

Permissions are granted by attesting a verifiable claim to an identity

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
