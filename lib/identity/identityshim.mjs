/**
 *
 *
 * DH shared encryption : epub & eprov
 * Sign & verify        : pub & priv
 *
 * @author: Bernhard Lukassen
 */

import SharedCrypto from "./sharedcrypto.mjs";

const rnd       = universe.random;
const everblack = () => universe.Gun.SEA;

const features = ['matter'];

export default class IdentityShim extends SharedCrypto(Object) {

    constructor(keypair) {
        super();
        this.keypair = keypair;
        this._matter = {
            attests: {}
        };
    }

    static async fromUserRef(userref$) {
        let userref = await userref$.full;
        let shim = new this({ pub: userref.pub, epub: userref.epub });
        shim._alias = userref.alias;
        return shim;
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
        return this._alias || this.pub;
    }

    set alias(alias) {
        this._alias = alias;
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
        if (!this.keypair.epriv) throw ErrNoPermission('no private key available');
        return everblack().secret(epub, this.keypair);
    }

    async sign(payload) {
        let signed = await everblack().sign(payload, this.keypair);
        return signed;
    }

    async verify(payload) {
        let verified = await everblack().verify(payload, this.pub);
        return verified;
    }
}
