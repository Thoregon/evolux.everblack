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

}
