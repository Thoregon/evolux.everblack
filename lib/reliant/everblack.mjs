/**
 *
 *
 * @author: Bernhard Lukassen
 */

import { EventEmitter}              from "/evolux.pubsub";
import { Reporter }                 from "/evolux.supervise";

import BaseEverblack                from "../baseeverblack.mjs";
// import Vault                        from "../vault/vault.mjs";
// todo: VaultLocalStore for browsers
// import VaultFileStore               from "./vault/storage/vaultfilestore.mjs";

export default class Everblack extends BaseEverblack(Reporter(EventEmitter)) {

    /**
     * Get a key pair from a vault
     * This method is primarily intended to be used in setup of the node (universe.config)
     * Doesn't throw if vault is invalid or pair not found.
     *
     * @param {String}  id          - id of the pair
     * @param {String}  key         - passphrase to unlock the vault
     * @param {String}  filename    - filename of the vault
     * @return {Promise<KeyPair>}   the key pair if found, undefined otherwise
     */
    async getPair(id, key, filename) {
/*
        try {
            let store = new VaultFileStore(filename);
            let vault = new Vault();

            vault.useStore(store);
            await vault.unlock(key);
            let pair = await vault.get(id);
            await vault.seal(key);

            return pair;
        } catch (e) {
            this.logger.error('vault, get pair', e);
            // don't throw, answer undefined
            return undefined;
        }
*/
    }

    /**
     * Created a key pair in a vault and returns it. Throws if vault
     * can't be created.
     *
     * @param {String}  id          - id of the pair
     * @param {String}  key         - passphrase to unlock the vault
     * @param {String}  filename    - filename of the vault
     * @return {Promise<KeyPair>}   the key pair if created
     */
    async createPair(id, key, filename) {
/*
        let store = new VaultFileStore(filename);
        let vault = new Vault();

        vault.useStore(store);
        await vault.unlock(key);
        await vault.createPair(id);
        let pair = await vault.get(id);
        await vault.save();
        await vault.seal(key);

        return pair;
*/
    }

    /*
     * EventEmitter implementation
     */

    get publishes() {
        return {
            ready:          'Everblack ready',
            exit:           'Everblack exit',
        };
    }
    /*
     * service implementation
     */

    install() {}
    uninstall() {}
    resolve() {}
    start() {
        universe.Everblack = this;   // publish identity controller
        this.emit('ready', { everblack: this });
    }
    stop() {
        delete universe.Everblack;
        this.emit('exit', { everblack: this });
    }

    update() {}

}
