/**
 *
 *
 * @author: Bernhard Lukassen
 */

const rnd       = universe.random;
const everblack = universe.Gun.SEA;

const features = ['matter'];

export default class IdentityShim {

    constructor(keypair) {
        this.keypair = keypair;
        this._matter = {
            attests: {}
        };
    }

    get isIdentity() {
        return true;
    }

    get pub() {
        return this.keypair.pub;
    }

    get epub() {
        return this.keypair.epub;
    }

    get is() {
        return true;
    }

    get alias() {
        return this.pub;
    }

    get matter() {
        return this._matter;
    }

    async leave() {
        delete this.keypair;
    }

    supports(feature) {
        return !!features.find(item => item === feature);
    }

    /**
     * provide a public key to get a shared secret with this identity
     * @param epub - encryption public key
     */
    async sharedSecret(epub) {
        return everblack.secret(epub, this.keypair);
    }

    /**
     * get a key for a member (the identity) which can only
     * be generates by either this identity or the owner (of the other keypair).
     *
     * use to avoid tracking of members
     *
     * @param identity
     * @param salt
     * @return {Promise<string>}    secret hash
     */
    async sharedIdHashWith(identity, salt) {
        let secret = await this.sharedSecret(identity.epub);
        let hash = await everblack.work(`${this.pub}|${secret}`, salt);
        hash = `@${hash.replace(/[=]/g, '')}`;
        return hash;
    }

    async sharedEncryptAndSign(identity, payload) {
        let secret = await this.sharedSecret(identity.epub),
            enc    = await everblack().encrypt(payload, secret),
            signed = await everblack().sign(enc, this.keypair);
        return signed;
    }

    async sharedVerifyAndDecrypt(identity, payload) {
        let secret   = await this.sharedSecret(identity.epub),
            verified = await everblack().verify(data, this.pub),
            dec      = await everblack().decrypt(verified, secret);
        return dec;
    }

    async sign(payload) {
        let signed = await everblack().sign(enc, this.keypair);
        return signed;
    }

    async verify(payload) {
        let verified = await everblack().verify(data, this.pub);
        return verified;
    }
}
