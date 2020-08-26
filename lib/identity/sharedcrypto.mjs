/**
 *
 *
 * @author: Bernhard Lukassen
 */

const rnd       = universe.random;
const everblack = () => universe.Gun.SEA;

let SharedCrypto =  base => class extends base {

    /**
     * Salt'n'Pepper a key for an identity.
     * the key can only be generates by either this identity or the other keypair.
     *
     * builds a 'pepper' only both attendees can know. The pepper is combined
     * with the key and then worked (HMAC hashed) with the salt.
     * use to avoid tracking of members over multiple encrypted entries
     *
     *  - Pepper: https://en.wikipedia.org/wiki/Pepper_(cryptography)
     *  - Salt:   https://en.wikipedia.org/wiki/Salt_(cryptography)
     *
     * @param {String}   key ... a key to identify the entry, mostly 'identity.pub' is used
     * @param {Identity} identity
     * @param {String}   salt
     * @return {Promise<string>}    secret hash
     */
    async sharedIdHashWith(key, identity, salt) {
        let pepper = await this.sharedSecret(identity.epub);    // generate 'pepper', can only be done by one of the keypairs
        let hash = await everblack().work(`${key}|${pepper}`, salt);    // combine key with pepper, then work it with salt to get a hash
        hash = `@${hash.replace(/[=]/g, '')}`;
        return hash;
    }

    async sharedEncryptAndSign(identity, payload) {
        let secret = await this.sharedSecret(identity.epub),
            enc    = await everblack().encrypt(payload, secret),
            signed = await everblack().sign(enc, this.keypair);
        return `@${signed}`;
    }

    /**
     *
     * @param {String}  spub ... public keyto verify signature
     * @param identity
     * @param payload
     * @return {Promise<*|ArrayBuffer>}
     */
    async sharedVerifyAndDecrypt(spub, identity, payload) {
        if (payload.startsWith('@')) payload = payload.substr(1);   // remove the '@' at the beginning
        let secret   = await this.sharedSecret(identity.epub),
            verified = await everblack().verify(payload, spub),
            dec      = await everblack().decrypt(verified, secret);
        return dec;
    }

};

export default SharedCrypto;
