Firewall
========

@see also thoregon.truCloud/firewall.md

A distributed replicated storage needs a firewall to avoid spam, denial of service, counterfeits, tamper and fraud.

Network
- number of writes (updates) comming from another peer
    - take PoW time to guess 
- network traffic comming from another peer
-> disconnect peer
- size of message
-> reject message

Payload
- check PoW 
    - everything we PoW in javascript is cute, but if someone uses another programming language, CUDA or ASIC then this is not a hurdle. we will need additional checks -> Network no writes or trafic  
    - there may be another PoW like [kaPoW](https://github.com/Steve132/mod_kapow), but we need it also in JS
- check signature
    - write signature (permission), can be written by everyone owning the write keypair
    - double signature, lock ownership, avoid overwrite by someone else having the write keypair
        - write_sig(identity_sig(payload))
        - update can only be done by 'identity' 
-> reject payload

- check parent (collection) type
    - e.g. a set must only contain one element signed from the same identity

PoW Examples

- https://www.savjee.be/2017/09/Implementing-proof-of-work-javascript-blockchain/
- https://github.com/Steve132/mod_kapow
- http://www.bennolan.com/2011/04/28/proof-of-work-in-js.html
- https://gist.github.com/othiym23/5639370

