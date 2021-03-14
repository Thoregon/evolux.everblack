/**
 * A SecretObject is a secure store where all invited users can read and write properties.
 * Only the owner(s) can invite others
 *
 * The keys will be derived as hash from property names.
 *
 * An additional meta property 'p' is maintained, containing the original property names with it's hash
 * encrypted with the shared secret, signed with the write key
 *
 * todo [OPEN]: introduce filter for old messages
 * todo [OPEN]: remove for old messages
 * todo [OPEN]: enable listeners for non existing sub properties (in deeper secret objects)
 *
 * todo [REFACTOR]: change encrypted property name to a hash, store name in the item (wrap item!)
 *
 * @author: Bernhard Lukassen
 */

import { forEach }     from "/evolux.util";
import { doAsync }     from "/evolux.universe";

import SharedStore     from "./sharedstore.mjs";
import ObjectReference from "./objectreference.mjs";

import { ErrStoreExistsNot, ErrNoPermission } from "./errors.mjs";
import { ErrNoKey }                           from "../errors.mjs";
import IdentityShim                           from "../identity/identityshim.mjs";

const rnd       = (l) => universe.random(l);
const everblack = ()  => universe.Everblack;

export default class SecretObject extends SharedStore {

    constructor(props) {
        super(props);
        this._listeners    = [];
        this._keyListeners = {};
    }

    async _createSupplements() {
        let tnode = this.metanode;
        tnode.p = {};
    }

    async put(key, item) {
        let kenc = await this.keyhash(key);
        let enc = await this.encryptItem(item, key);
        this.contentnode[kenc] = enc;
    }

    async add(item) {
        let key = rnd(32);
        await this.put(key, item);
        return key;
    }

    async setSecretObject(key, inherit = false) {
        if (!key) throw ErrNoKey();
        let member = this.member;
        if (!member.write) throw ErrNoPermission();
        key = key || rnd(32);
        // let kenc = await this.keyhash(key);
        let so = SecretObject.at(rnd(32));
        if (inherit) {
            await so.inheritFrom(this);
        } else {
            await so.createIfMissing();
        }
        await this.put(key, so);
        return so;
    }

    async addSecretObject(key, inherit = true) {
        key = key || rnd(32);
        let item = await this.setSecretObject(key, inherit);
        return { key, item } ;
    }

    /**
     * the value returned may be
     * - a literal value e.g. a string or a number
     * - a matter node, which itself can be a secure store
     * @param key
     * @return {Promise<void>}
     */
    async get(key) {
        let kenc = await this.keyhash(key);
        let itemnode = this.contentnode[kenc];
        if (!await itemnode.is) return null;
        let { item } = await this.decryptItem(await itemnode.val);
        return item;
    }

    // todo [REFACTOR]: the firewall needs to check. replace 'delete' with a write of ecrypted item with delete command (flag)
    async drop(key) {
        let kenc = await this.keyhash(key);
        let enc = await this.encryptItem(null, key);
        this.contentnode[kenc] = enc;

        /* this version works, but doesn't keep the key -> cant send a remove event for a key
                let member = this.member;
                if (!member.write) throw ErrNoPermission();
                let kenc = await this.keyhash(key);
                delete this.contentnode[kenc];
        */
    }

    /*async*/ forEachEntry(fn) {
        return new Promise(((resolve, reject) => {
            this.contentnode.once(async (props) => {
                if (!props) resolve();
                try {
                    await forEach(Object.entries(props), async ([key, item]) => {
                        if (!item || key === '_') return;
                        let entry = await this.decryptItem(item);
                        if (!entry || ! entry.item) return;
                        await fn(entry);
                    });
                } catch (e) { reject(e) }
                resolve();
            });
        }));
    }

    async val() {
        let obj = {};
        await this.forEachEntry(({ item, key }) => obj[key] = item);
        return obj;
    }

    map(fn) {

    }

    /**
     * listen on changes of a single entry
     * the listener will be called with params: item
     * @param key
     * @param fn
     */
    on(key, fn) {
        let listeners = this._keyListeners[key];
        if (!listeners) {
            listeners = [];
            this._keyListeners[key] = listeners;
        }
        listeners.push(fn);
        this.startListen();
    }

    removeOn(key, fn) {
        if (!this._keyListeners[key]) return;
        this._keyListeners[key] = this._keyListeners[key].filter(listener => listener !== fn);
        if (this._keyListeners[key].is_empty) delete this._keyListeners[key];
        if (!this._hasListeners()) this.stopListen();
    }

    /**
     * listen on all changes
     * the listener will be called with params: item, key
     *
     */
    onChange(fn) {
        this._listeners.push(fn);
        this.startListen();
    }

    removeOnChange(fn) {
        this._listeners = this._listeners.filter(listener => listener !== fn);
        if (!this._hasListeners()) this.stopListen();
    }

    _hasListeners() {
        return this._listeners.length > 0 || !this._keyListeners.is_empty;
    }

    /*
     * helpers
     */

    async encryptItem(item, key) {
        let member = this.member;
        if (!member.write) throw ErrNoPermission();
        let sharedkey = member.sharedkey;
        // todo [OPEN]: encode if reference to matter node or to another secure store
        let entry = (item && item.isSecureStore)
            ? { key, ref: item.location }
            : { item, key };
        let enc = await everblack().encrypt( entry, sharedkey);
        let sig = await member.write.sign(enc);
        if (!sig) throw ErrNoPermission();
        return `@${sig}`;
    }

    async decryptItem(item) {
        let sharedkey = this.member.sharedkey;
        if (item.startsWith('@')) item = item.substr(1);
        let ver = await everblack().verify(item, this.write.pub);
        if (!ver) return { item: undefined, key: undefined };
        let dec = await everblack().decrypt(ver, sharedkey);
        if (!dec) return { item: undefined, key: undefined };
        // todo [OPEN]: resolve if reference to matter node or to another secure store
        if (dec.ref) {
            let secretObject = await SecretObject
                .at(dec.ref)    // a random location
                .join(this.identity);
            return { item: secretObject, key: dec.key };
        } else {
            return { item: dec.item, key: dec.key };
        }
    }

    async keyhash(itemkey) {
        return await everblack().work(itemkey, this.salt);
    }


    /*
     *
     */

    async startListen() {
        if (this._changeHandler) return;
        let contentnode = this.contentnode;
        this._changeHandler = async (encitem, enckey) => {
            if (!enckey) return;
            let { item, key } = await this.decryptItem(encitem);
            // if (!item) return;
            // fire change listeners
            forEach(this._listeners, async (listener) => {
                try {
                    await listener(item, key);
                } catch (e) {
                    universe.logger.error('Error in change listener on KV store', e);
                }
            });
            // fires key listeners
            let keyListeners = this._keyListeners[key];
            if (!keyListeners) return;
            forEach(keyListeners, async (listener) => {
                try {
                    await listener(item);
                } catch (e) {
                    universe.logger.error('Error in key listener on KV store', e);
                }
            });
        }
        contentnode.map().on(this._changeHandler);
        await doAsync();
    }

    stopListen() {
        this.contentnode.map().off();
    }

}
