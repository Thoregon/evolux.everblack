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

import { forEach }           from "/evolux.util";

import SharedStore from "./sharedstore.mjs";

import { ErrStoreExistsNot, ErrNoPermission } from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class Channel extends SharedStore {

    constructor(props) {
        super(props);
        this._listeners = [];
    }


    async send(message) {
        let item = {
            pub: this.member.pub,
            alias: this.member.alias,
            dttm: universe.now,
            message
        }

        // encrypt message
        let enc = await this.encryptMessage(item);
        // this.model.channel.push(item);
        // store it
        return this.contentnode.add(enc);
    }

    onMessage(fn) {
        this._listeners.push(fn);
        // send all existing messages
        if (this.channel) {
            (async () => {
                await forEach(this.channel, async (message) => {
                    try {
                        await fn(message);
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

    async encryptMessage(message) {
        let member = this.member;
        if (!member.write) throw ErrNoPermission();
        let sharedkey = member.sharedkey;
        let enc = await everblack().encrypt(message, sharedkey);
        let sig = await member.write.sign(enc);
        if (!sig) throw ErrNoPermission();
        return `@${sig}`;
    }

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
        let channel = [];
        this.channel = channel;
        this.contentnode.map().on(async (item, key) => {       // map() walks all entries
            if (item) {
                let message = await this.decryptMessage(item);
                if (message) {
                    channel.push(message);
                    await this._publishMessage(message);
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

    async _publishMessage(message) {
        // todo: send to all listeners
        await forEach(this._listeners, async (fn) => {
            try {
                await fn(message);
            } catch (e) {
                universe.logger.error('error in message listener', e);
            }
        })
    }
}
