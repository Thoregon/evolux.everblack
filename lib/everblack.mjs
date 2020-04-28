/**
 *
 *
 * @author: Bernhard Lukassen
 */

import { EventEmitter}              from "/evolux.pubsub";
import { Reporter }                 from "/evolux.supervise";

import Vault                        from "./vault/vault.mjs";
import VaultFileStore               from "./vault/storage/vaultfilestore.mjs";
import GunAdapter                   from "./gunadapter.mjs";

export default class Everblack extends Reporter(EventEmitter) {

    constructor() {
        super();
        this._plugins = [];     // cache plugins if gun adapter will be engaged later
    }

    /*
     * Key and secrets generation
     */

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
        let store = new VaultFileStore(filename);
        let vault = new Vault();

        vault.useStore(store);
        await vault.unlock(key);
        await vault.createPair(id);
        let pair = await vault.get(id);
        await vault.save();
        await vault.seal(key);

        return pair;
    }

    /*
     * Plugins. use to provide key pairs and secrets to the underlying gun adapter to enable encyrption and signing
     */


    use(plugin) {
        if (this.gunadapter) this.gunadapter.use(plugin);
        this._plugins.push(plugin);
    }

    pair(node, pair) {
        // register a key pair for a node
    }

    secret(node, pair) {
        // register a sync key for a node
    }

    async _engageGunAdapter() {
        if (this.gunadapter) return;        // already done
        this.gunadapter = GunAdapter; // todo: use install event of 'terra.gun'
        this._plugins.forEach(plugin => this.gunadapter.use(plugin));
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
    async start() {
        universe.Everblack = this;   // publish identity controller
        await this._engageGunAdapter();
        this.emit('ready', { everblack: this });
    }
    stop() {
        delete universe.Everblack;
        // caution: don't release the gunadapter!! it works as a firewall against deletes from unauthorized
        this.emit('exit', { everblack: this });
    }

    update() {}

}
