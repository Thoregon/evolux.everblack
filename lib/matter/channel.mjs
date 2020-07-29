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
            id: this.identity.pub,
            message
        }

        // encrypt message
        let enc = this.encyptMessage(item);
        // this.model.channel.push(item);
        // store it
        this.node.channel.add(enc);
    }

    onMessage(fn) {
        this._listeners.push(fn);
        // send all existing messages

    }

    /*
     * helpers
     */

    initModel(model) {
        // model.channel = {};
    }

    async encryptMessage(message) {
        let enc = message;
        return enc;
    }

    async decryptMessage(message) {
        let dec = message;
        return dec;
    }

    async _channel() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.model && this.model.channel) return;
        let channel = [];
        this.model.channel = channel;
        this.node.channel.on(async (item, key) => {
            let message = await this.decryptMessage(item);
            channel.push(message);
            this._publishMessage()
        });
    }

    _publishMessage(message) {
        // todo: send to all listeners
    }
}
