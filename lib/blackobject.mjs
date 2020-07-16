/**
 * The black object serves encryption/decryption functions for the following uses:
 *  - private use
 *      - non shared data
 *      - data is only available for the user
 *  - shared use
 *      -
 *
------
 permissions: {
    pub: <public key of the admin (role) to grant/revoke permissions>,
    proof: <a proof which can be verified with the previous admin pub key>,
    roles: [
        {
            role: <role for permission>,
            control: <encrypted control data>
        }
    ],
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
------
 * @author: Bernhard Lukassen
 */

export default class BlackObject {

    constructor() {
    }


    forRole(rolename, rolepair, permissions) {
        Object.assign(this, { role: rolename, rolepair, permissions });
        this.pubkey = permissions.pub;
        return this;
    }

    /*
     * private use, no shared data
     */

    /*
     * shared use
     * through the use of a wormhole, no one unauthorized can learn anything
     */

    throughTheWormhole(container, property) {

    }

    outOfTheWormhole(container, property) {

    }

    /*
     * internals for encryption and decryption
     */

    toWormhole(data, pubkey, pair) {
        let
    }
}
