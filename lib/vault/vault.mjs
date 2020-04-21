/**
 * The key/secret store, which enables the storage and retrival of secure information.
 * A store is secured by a passphrase. It does not provide additional access control,
 * for multiple secret owners use multiple vaults.
 *
 * - create pairs and secrets
 * - simple encode/decode
 * - secret storage
 *
 * For a more sophisticated vault use [Hashicorp Vault](https://www.vaultproject.io/)
 *
 * Arbitrary key/value secrets can be stored in this vault
 *  - key pairs
 *  - shared secrets (but they can be built when needed)
 *  - other keys
 *  - information which should just be secured
 *
 * Store structure JSON:
 *   {
 *       salt: '<salt for the proof>',
 *       content: '<encoded content of the whole vault>'
 *   }
 *
 *
 * todo:
 *  - certs (X.509)
 *  - leases for temporarily access
 *  - implement with 'dynlayers', remove store interface
 *
 * @author: Bernhard Lukassen
 */

import { Gun }          from "/terra.gun";
import { ErrVaultSealed, ErrVaultStoreMissing } from "../errors.mjs";

const rnd = Gun.text.random;
const SEA = Gun.SEA;

export default class Vault {

    constructor() {
    }

    /*
     * management
     */

    /**
     * set the store engine
     * @param store
     */
    useStore(store) {
        this.store = store
    }

    /**
     * decode the content
     * @param {String}  key
     * @return {boolean} successful
     */
    async unlock(key) {
        if (this.kv) return true;   // already unlocked
        if (!this.payload) await this.read();

        this._key = key;            // todo: this is for convenience, better get rid of it, may be stolen from memory
        if (!this.payload) {
            this.kv = {};           // new vault w/o content, just init
        } else {
            // decode and verify payload
            await this._decode(key);
            if (!this.kv) return false;
        }
        return true;
    }

    /**
     * seal the vault
     * @param {String}  [key] - use memorized key of stored
     * @return {boolean} successful
     */
    async seal(key) {
        // encode 'kv'
        await this._encode(key || this._key);   // todo: possibly dangerous holding key in memory
        // remove decoded data and key
        delete this.kv;
        delete this._key;

        return !!this.payload;
    }

    /**
     * encode the content
     * @param {String}  key
     * @return {boolean} successful
     */
    async _encode(key) {
        if (!this.salt) this.salt = rnd(64)     // generate a salt for the encoding

        // encode 'kv'
        let proof = await SEA.work(key, this.salt);
        let enc = await SEA.encrypt(this.kv, proof);
        this.payload = JSON.stringify({ content: enc, salt: this.salt});
    }

    /**
     * encode the content
     * @param {String}  key
     * @return {boolean} successful
     */
    async _decode(key) {
        // encode 'kv'
        if (!this.payload) return false;
        let r = JSON.parse(this.payload);
        if (!r) return false;
        let proof = await SEA.work(key, r.salt);
        this.salt = r.salt;
        let content = r.content;
        this.kv = await SEA.decrypt(content, proof);
        return true;
    }

    /**
     * check if the vault is valid.
     * can only be
     * @return {boolean} is valid
     */
    status() {
        return !!this.kv;
    }

    /**
     * list all id's with metainformation in this vault
     *
     * metainformation is
     * - created time
     * - modified time
     * - revision (num modifications)
     * @return {Object<String, String>} all id's
     */
    list() {
        if (!this.kv) throw ErrVaultSealed();
        return this.kv;
    }

    /**
     * get a secret with an id as object
     * @param {String}  id
     * @return {boolean} entry exists
     */
    has(id) {
        if (!this.kv) throw ErrVaultSealed();
        return !!this.kv[id];
    }

    /**
     * get a secret with an id as object
     * @param {String}  id
     * @return {Object} data
     */
    get(id) {
        if (!this.kv) throw ErrVaultSealed();
        return this.kv[id];
    }

    /**
     * put a secret to the vault with an id
     * @param id
     * @param data
     */
    put(id, data) {
        if (!this.kv) throw ErrVaultSealed();

        let kv = this.kv[id];
        if (!kv) {
            kv = { created: new Date().getTime(), revision: 1 };
            this.kv[id] = kv;
        } else {
            kv.modified = new Date().getTime();
            kv.revision++;
        }
        kv.data = data;
    }

    /**
     * remove a secret from the vault
     * @param id
     */
    del(id) {
        if (!this.kv) throw ErrVaultSealed();
        delete this.kv[id];
    }

    /*
     * create
     */

    /**
     * create a key pair and store it with the id in the vault
     * convenience for: new pair, put
     * @param pairid
     */
    async createPair(id) {
        if (!this.kv) throw ErrVaultSealed();
        let pair = await SEA.pair();
        this.put(id, pair);
    }

    /**
     * Create a random string 128 characters to be used as a secret
     * @param id
     */
    async createSecret(id) {
        if (!this.kv) throw ErrVaultSealed();
        let secret = rnd(128);
        this.put(id, secret);
    }

    /*
     * storeage
     */

    /**
     *
     * @return {Promise<void>}
     */
    async read() {
        if (!this.store) throw ErrVaultStoreMissing();
        this.payload = await this.store.read();
    }

    /**
     * store vault and seal it
     * @return {Promise<void>}
     */
    async save(key) {
        if (!this.store) throw ErrVaultStoreMissing();
        await this._encode(key || this._key);     // todo: possibly dangerous holding key in memory
        await this.store.write(this.payload);
    }

}
