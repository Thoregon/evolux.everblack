/**
 * A Channel is a secure store where all invited users can communicate.
 * Each invited user can read and add messages
 * Only the owner(s) can invite others
 *
 * Structure
  {
       t͛: {     // thoregon metadata
           owner: <owner_pubkey>,   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
           t: <thoregon class metadata>,
           members: {
               <user_pubkey_hash>: { nickname: '', icon: '', sharedkey: ''}, // the content is encrypted, can be decrypted with the owner pub key and the users priv key
           }
       }
       channel: [   // the content is encrypted with the shared secret key available for all members
           ...<content>>
       ]
  }
 *
 * todo [OPEN]: introduce filter for old messages
 * todo [OPEN]: remove for old messages
 *
 * @author: Bernhard Lukassen
 */

import { forEach }     from "/evolux.util";
import { doAsync }     from "/evolux.universe";

import SharedStore     from "./sharedstore.mjs";
import ObjectReference from "./objectreference.mjs";

import { ErrStoreExistsNot, ErrNoPermission } from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = ()  => universe.Everblack;

export default class KeyValueStore extends SharedStore {

    constructor(props) {
        super(props);
        this._listeners    = [];
        this._keyListeners = {};
    }

    async _createSupplements() {
        // initialize salt for key encryption
        let ksalt = rnd(9),     // salt for key encryption
            kiv   = rnd(15),    // initialization vector for key encryption
            tnode = this.metanode;

        // store salt and initialization vector encrypted
        tnode.k   = await this.encryptItem({ ks: ksalt, ki: kiv });

        this.ksalt = ksalt;
        this.kiv   = kiv;
    }

    async put(key, item) {
        let kenc = await this.encryptKey(key);
        // encrypt
        let enc = await this.encryptItem(item);
        // this.model.channel.push(item);
        // store it
        return this.contentnode[kenc] = enc;
    }

    /**
     * the value returned may be
     * - a literal value e.g. a string or a number
     * - a matter node, which itself can be a secure store
     * @param key
     * @return {Promise<void>}
     */
    async get(key) {
        let kenc = await this.encryptKey(key);
        let itemnode = this.contentnode[kenc];
        if (!await itemnode.is) return null;
        let item = this.decryptItem(await itemnode.val);
        return item;
    }

    async drop(key) {
        let kenc = await this.encryptKey(key);
        delete this.contentnode[kenc];
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
    }

    removeOn(key, fn) {
        if (!this._keyListeners[key]) return;
        this._keyListeners[key] = this._keyListeners[key].filter(listener => listener !== fn);
    }

    /**
     * listen on all changes
     * the listener will be called with params: item, key
     *
     */
    onChange(fn) {
        this._listeners.push(fn);
    }

    removeOnChange(fn) {
        this._listeners = this._listeners.filter(listener => listener !== fn);
    }

    /*
     * helpers
     */

    async encryptItem(item) {
        let member = this.member;
        if (!member.write) throw ErrNoPermission();
        let sharedkey = member.sharedkey;
        // todo [OPEN]: encode if reference to matter node or to a secure store
        let enc = await everblack().encrypt(item, sharedkey);
        let sig = await member.write.sign(enc);
        if (!sig) throw ErrNoPermission();
        return `@${sig}`;
    }

    async decryptItem(item) {
        let sharedkey = this.member.sharedkey;
        if (item.startsWith('@')) item = item.substr(1);
        let ver = await everblack().verify(item, this.write.pub);
        let dec = await everblack().decrypt(ver, sharedkey);
        // todo [OPEN]: resolve if reference to matter node or to a secure store
        return dec;
    }

    async encryptKey(itemkey) {
        // todo [OPEN]: check if this encryption is good enough and if a signature is necessary
        let sharedkey = this.member.sharedkey;
        let enc = await everblack().sencrypt(itemkey, sharedkey, this.ksalt, this.kiv);
        return enc;
    }

    async decryptKey(encitemkey) {
        let sharedkey = this.member.sharedkey;
        let dec = await everblack().sdecrypt(encitemkey, sharedkey, this.ksalt, this.kiv);
        return dec;
    }

    /*
     *
     */

    async established() {
        if (this._changeHandler) return;
        let contentnode = this.contentnode;
        this._changeHandler = async (encitem, enckey) => {
            if (!enckey) return;
            let itemkey = await this.decryptKey(enckey);
            let item = encitem ? await this.decryptItem(encitem) : null;  // in case of a drop
            // fire change listeners
            forEach(this._listeners, async (listener) => {
                try {
                    await listener(item, itemkey);
                } catch (e) {
                    universe.logger.error('Error in change listener on KV store', e);
                }
            });
            // fires key listeners
            let keyListeners = this._keyListeners[itemkey];
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

    async unlock() {
        await super.unlock();
        let tnode  = this.metanode;   // get meta data from DB node
        let k = await this.decryptItem(await tnode.k.val);
        this.ksalt = k.ks;
        this.kiv   = k.ki;
        return this;
    }

}
