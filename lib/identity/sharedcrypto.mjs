/**
 *
 *
 * @author: Bernhard Lukassen
 */

const rnd       = universe.random;
const everblack = () => universe.Gun.SEA;

let SharedCrypto =  base => class extends base {

    /**
     * get a key for a member (the identity) which can only
     * be generates by either this identity or the owner (of the other keypair).
     *
     * use to avoid tracking of members
     *
     * @param {String}   key ... a key to identify the entry, mostly 'identity.pub' is used
     * @param {Identity} identity
     * @param {String}   salt
     * @return {Promise<string>}    secret hash
     */
    async sharedIdHashWith(key, identity, salt) {
        let secret = await this.sharedSecret(identity.epub);
        let hash = await everblack().work(`${key}|${secret}`, salt);
        hash = `@${hash.replace(/[=]/g, '')}`;
        return hash;
    }

    async sharedEncryptAndSign(identity, payload) {
        let secret = await this.sharedSecret(identity.epub),
            enc    = await everblack().encrypt(payload, secret),
            signed = await everblack().sign(enc, this.keypair);
        return signed;
    }

    /**
     *
     * @param {String}  spub ... public keyto verify signature
     * @param identity
     * @param payload
     * @return {Promise<*|ArrayBuffer>}
     */
    async sharedVerifyAndDecrypt(spub, identity, payload) {
        let secret   = await this.sharedSecret(identity.epub),
            verified = await everblack().verify(payload, spub),
            dec      = await everblack().decrypt(verified, secret);
        return dec;
    }

};

export default SharedCrypto;
