/**
 * A queue is a secure store where the owner can communicate
 * with any user. Only this parties can read the entries
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
       queue: [   // the content is encrypted with another shared secret key between user and owner; available for all users
           ...<content>>
       ]
  }
 *
 * @author: Bernhard Lukassen
 */

import PublicStore         from "./publicstore.mjs";
import {ErrStoreExistsNot} from "./errors.mjs";
import IdentityShim        from "../identity/identityshim.mjs";

const T = universe.T;     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class Queue extends PublicStore {


    request(payload) {
        this._tmeta();
        let pair = new IdentityShim(everblack().pair());  // a new pair for each request! prevent tracking
        let req = new Request(this, pair, payload);
        req.reqnode = this.node.queue.add(enc);

        return req;
    }

    onRequest(fn) {
        this._tmeta();
        if (!this._listener) {
            this.node.queue.map().on()
        }
    }

    /*
     *
     */

    async _queue() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.model && this.model.queue) return;
        this.model.queue = [];
    }

    /*
     * util
     */

    purge() {
        // todo: [OPEN]: cleanup
    }
}

/**
 * provide
 */
class Request {

    constructor(queue, pair, payload) {
        Object.assign(this, { queue, pair, payload });
        // this.reqnode
    }

    onResponse(fn) {
        this._listener = fn;
        this.reqnode.on(async (item, key) => {       // listen only on this entry
        });
        return this;
    }

    /*
     * secret
     */

    async encrypt(request, ) {
        let secret = await request.pair.sharedSecret(this.queue.epub);
        let enc = await everblack().encrypt(message, secret);
        return `@${enc}`;
    }

    async decrypt(enc, ownerpair, epub) {
        let secret = await everblack().secret(epub, ownerpair);
        if (message.startsWith('@')) message = message.substr(1);
        let dec = await everblack().decrypt(message, secret);
        return dec;
    }

    /**
     * cancle the request for whatever reason
     */
    cancel() {

    }

    /**
     * respond to the request
     * @param response
     */
    respond(response) {

    }

    onRequest(request) {
        // todo: remove this request. can only be done by the owner. mark as received
    }
}
