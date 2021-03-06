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

import { forEach } from "/evolux.util";
import SharedStore from "./sharedstore.mjs";

import { ErrStoreExistsNot, ErrNoPermission, ErrNotPersistent } from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class Channel extends SharedStore {

    constructor(props) {
        super(props);
        this._listeners = [];
    }

    async send(message) {
        let item = {
            pub  : this.member.pub,
            alias: this.member.alias,
            dttm : universe.now,
            message
        }

        // encrypt message
        let enc = await this.encryptMessage(item);  // todo [REFACTOR]: encrypt a structure (not JSON)
        // this.model.channel.push(item);
        // store it
        // todo [REFACTOR]: introduce partitions!
        return this.contentnode.add(enc);
    }

    async modify(message, key) {
        let item = this.channel[key];
        if (!item) throw ErrNotPersistent(JSON.stringify(message));
        item.message = message;
        // encrypt message
        let enc = await this.encryptMessage(item);  // todo [REFACTOR]: encrypt a structure (not JSON)
        // update matter node
        return this.contentnode[key] = enc;
    }

    onMessage(fn) {
        this._listeners.push(fn);
        // send all existing messages
        if (this.channel) {
            (async () => {
                await forEach(Object.entries(this.channel), async ([message, key]) => {
                    try {
                        await fn(message, key);   // its not an update
                    } catch (e) {
                        universe.logger.error('error in message listener', e);
                    }
                })
            })();
        } else {
            // start listening to messages
            (async () => await this._channel())();
        }
    }

    /*
     * helpers
     */

    // todo [OPEN]: there must also be a pubkey and a signature of the sender
    async encryptMessage(message) {
        let member = this.member;
        if (!member.write) throw ErrNoPermission();
        let sharedkey = member.sharedkey;
        let enc = await everblack().encrypt(message, sharedkey);
        let sig = await member.write.sign(enc);
        if (!sig) throw ErrNoPermission();
        return `@${sig}`;
    }

    // todo [OPEN]: verify the signature of the sender
    async decryptMessage(message) {
        let sharedkey = this.member.sharedkey;
        if (message.startsWith('@')) message = message.substr(1);
        let ver = await everblack().verify(message, this.write.pub);
        let dec = await everblack().decrypt(ver, sharedkey);
        return dec;
    }

    async _channel() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.channel) return;
        let channel = {};
        this.channel = channel;
        this.contentnode.map().on(async (item, key) => {       // map() walks all entries
            if (item) {
                let message = await this.decryptMessage(item);
                if (message) {
                    let oldmessage = channel[key];
                    channel[key]   = message;
                    await this._publishMessage(message, key, oldmessage);
                } else {
                    // todo [OPEN]: remove invalid messages (with key)
                    // todo [OPEN]: proper logging
                    universe.logger.warn(`Private Channel: invalid message received: '${item}'`);
                }
            } else {
                // todo [OPEN]: remove invalid messages (with key)
                // todo [OPEN]: proper logging
                universe.logger.warn(`Private Channel: empty message received`);
            }
        });
    }

    async _publishMessage(message, key, oldmessage) {
        // todo: send to all listeners
        await forEach(this._listeners, async (fn) => {
            try {
                await fn(message, key, oldmessage);  // tell it the message was updated
            } catch (e) {
                universe.logger.error('error in message listener', e);
            }
        })
    }
}
