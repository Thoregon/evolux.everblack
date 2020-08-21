/**
 *
 *
 * @author: Bernhard Lukassen
 */

import Channel      from "./matter/channel.mjs";
import Queue        from "./matter/queue.mjs";
import Entity       from "./matter/entity.mjs";
import IdentityShim from "./identity/identityshim.mjs";

const rnd = universe.Gun.text.random;
const SEA = universe.Gun.SEA;

const BaseEverblack = base => class extends base {

    /*
     * utils
     */

    rnd(len) {
        return rnd(len);
    }

    /**
     * get a random salt to work hashes
     * @return {*|number}
     */
    get salt() {
        return rnd(16);
    }

    /*
     * wrap SEA
     */

    /**
     * generate a double key pair
     * contains:
     *  pub  - priv         (for signing/verifying)
     *  epub - epriv        (for encryption/decryption)
     *
     * @return {Promise<*>}
     */
    async pair() {
        // register a key pair for a node
        return SEA.pair();
    }

    /**
     * build a secret key with a public key and a keypair
     * DH (Diffie-Hellman)
     *
     * @param epub
     * @param pair
     * @return {Promise<*>}
     */
    async secret(epub, pair) {
        // register a sync key for a node
        return SEA.secret(epub, pair);
    }

    /**
     * encrypt data with a key or a pair
     * @param data
     * @param pair or key
     * @return string with a hash
     */
    async encrypt(data, pair) {
        return SEA.encrypt(data, pair);
    }

    /**
     * decrypt data with a key or a pair
     * @param data
     * @param pair or key
     * @return string with a hash
     */
    async decrypt(data, pair) {
        return SEA.decrypt(data, pair);
    }

    /**
     * sign data with a key or a pair
     * @param data
     * @param pair or key
     * @return string with a hash
     */
    async sign(data, pair) {
        return SEA.sign(data, pair);
    }

    /**
     * verify data with a key or a pair
     * @param data
     * @param pair or key (epub)
     * @return string with a hash
     */
    async verify(data, pair) {
        return SEA.verify(data, pair);
    }

    /**
     * work a hash with data and a salt or a pair
     * @param data
     * @param pair or key
     * @return string with a hash
     */
    async work(data, pair) {
        return SEA.work(data, pair);
    }

    /*
     * Setup
     */

    setupOnStart() {
        universe.Everblack = this;   // publish identity controller
        universe.everblack = {
            Channel     : Channel,
            Queue       : Queue,
            Entity      : Entity,
            IdentityShim: IdentityShim,
        }
    }

}

export default BaseEverblack;
