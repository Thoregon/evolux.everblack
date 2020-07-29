/**
 * A Channel is a secure store where all invited users can communicate.
 * Each invited user can read and add messages
 * Only the owner(s) can invite others
 *
 * Structure
  {
       t͛: {     // thoregon metadata
           owner: <owner_pubkey>,   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
           salt: <salt>,
           members: {
               <user_pubkey_hash>: { nickname: '', icon: '', sharedkey: ''}, // the content is encrypted, can be decrypted with the owner pub key and the users priv key
           }
       }
       channel: [   // the content is encrypted with the shared secret key available for all members
           ...<content>>
       ]
  }
 *
 * @author: Bernhard Lukassen
 */

import { forEach }         from "/evolux.util";

import PrivateStore        from "./privatestore.mjs";
import {ErrStoreExistsNot} from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class Channel extends PrivateStore {

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
        this.node.channel.add(enc);
    }

    onMessage(fn) {
        this._listeners.push(fn);
        // send all existing messages
        if (this._messages) {
            (async () => {
                await forEach(this._messages, async (message) => {
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

    // todo [OPEN]: encrypted messages needs to be signed. do without exposing pub keys of members
    async encryptMessage(message) {
        let sharedkey = this.member.sharedkey;
        let enc = await everblack().encrypt(message, sharedkey);
        return `@${enc}`;
    }

    async decryptMessage(message) {
        let sharedkey = this.member.sharedkey;
        if (message.startsWith('@')) message = message.substr(1);
        let dec = await everblack().decrypt(message, sharedkey);
        return dec;
    }

    async _channel() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.model && this.model.channel) return;
        let channel = [];
        this.model.channel = channel;
        this.node.channel.map().on(async (item, key) => {       // map() walks all entries
            let message = await this.decryptMessage(item);
            channel.push(message);
            await this._publishMessage(message);
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
