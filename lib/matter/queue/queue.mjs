/**
 * A queue is a secure store where the owner can communicate
 * with any user. Only this parties can read the entries
 *
 * Structure
 {
       t͛: {     // thoregon metadata
           o: <owner_pubkey>,   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
       }
       queue: [   // the content is encrypted with another shared secret key between user and owner; available for all users
           ...<content>>
       ]
  }
 *
 * todo [REFACTOR]:
 *  - split into client and service classes
 *      - client
 *          - Service, Request, Response
 *      - service
 *          - ServiceProvider, ServiceRequest, ServiceResponse
 *
 * @author: Bernhard Lukassen
 */

import PublicStore                           from "../publicstore.mjs";
import IdentityShim                          from "../../identity/identityshim.mjs";

import { ErrCantDecrypt, ErrStoreExistsNot } from "../errors.mjs";

const T = universe.T;     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class Queue extends PublicStore {

    request(payload, timeout) {
        return new Promise(async (resolve, reject) => {
            await this._restoreMeta();
            let req     = await Request.create(payload, this);
            let enc     = await req.encryptRequest();
            req.reqnode = await this.node.queue.add(enc);

            if (timeout) {
                // todo [OPEN]: implement timeout
            }
            // listen on 'req.reqnode' for modifications
            req.reqnode.on(async (item, key) => {
                // check if there is a request or error, then resolve or reject
                if (!item) return;
                await this._restoreMeta();
                let sreq = await Request.fromResponse(item, this, key, req.pair);   // todo [REFACTOR]?: reuse orig request
                if (!sreq) {
                    // reject(ErrCantDecrypt());
                } else if (sreq.err) {
                    reject(sreq.err);
                } else if (sreq.response) {
                    // maybe an old entry to purge
                } else {
                    await resolve(sreq.payload);
                    // todo: [OPEN]: purge the resolved request
                }
            })
        });
    }

    async handle(fn) {
        await this._restoreMeta();
        // listen to requests
        // todo [OPEN]: check if the signedon identity can decrypt the requests, otherwise throw
        this.node.queue.map().on(async (item, key) => {
            if (!item) return; // purged or removed request
            // handle request
            await this._restoreMeta();
            let request = await Request.fromRequest(item, this, key);
            if (!request) {
                universe.logger.warn('request could not be decrpted');
                return;
            }
            if (request.response) return;    // request already done
            if (request.ctrl && request.ctrl.canceled) return;     // request canceled
            if (request.ctrl && request.ctrl.cancel) {
                // todo [OPEN]: implement
                //  - notify fn to stop work
                //  - mark request as canceled and store it again
                return;
            }
            let response = new Response(request, this);
            try {
                // service fn must actively send the response (or an error)
                await fn(request, response);
            } catch (e) {
                await response.error(e).send();  // respond an error
            }
        })
    }

    /*
     * util
     */

    purge() {
        // todo: [OPEN]: cleanup resolved and canceled requests
    }
}

/**
 * distingish request and response for client and service side
 * needs other secret generation and verification
 *
 * Structure:
 *  {
 *      keys: { pub, epub },                // public keys from request
 *      ctrl: { member, cancel, pause },    // encrypted with shared secret, signed with req.pub
 *      payload: { ... },                   // encrypted with shared secret, signed with req.pub
 *      response: { ... }                   // encrypted with shared secret, signed with owner.pub
 *  }
 *
 */
class Request {

    constructor({ payload, queue, key, pair } = {}) {
        Object.assign(this, { queue, pair, key, payload });
        // this.reqnode
    }

    static async create(payload, queue) {
        let pair = new IdentityShim(await everblack().pair());  // a new pair for each request! prevent tracking
        let req = new this({ payload, queue, pair });
        return req;
    }

    /**
     * decode request entry from client
     * @param item
     */
    static fromRequest(item, queue, key) {
        let req = new this({ queue, key });
        return req.decryptRequest(item);
    }

    /**
     * decode request entry from service
     * @param item
     */
    static fromResponse(item, queue, key, pair) {
        let req = new this({ queue, key, pair });
        return req.decryptResponse(item);
    }

    get owner() {
        return this.queue.owner;
    }

    get admin() {
        return this.queue.identity;
    }

    /*
     * secret request
     */

    /**
     * client side will encrypt with a secret
     *  request pair - service epub
     *
     * sign with request pair
     *
     * @return {Promise<string>}
     */
    async encryptRequest() {
        let pair   = this.pair;
        let sig    = await pair.sharedEncryptAndSign(this.owner, this.payload);
        // let secret = await pair.sharedSecret(this.owner.epub);
        // let enc    = await everblack().encrypt(this.payload, secret);
        // let sig2    = await pair.sign(enc);
        let req    = {
            keys   : { pub: pair.pub, epub: pair.epub },
            ctrl   : '',            // todo [OPEN]: implement control data (encrypted)
            payload: sig
        }
        return JSON.stringify(req);
    }

    /**
     * service side will decode with a secret
     *  service pair (admin) - request epub
     *
     * verify with request pub
     *
     * @return {Promise<*|ArrayBuffer>}
     */
    async decryptRequest(item) {
        let req     = JSON.parse(item);
        let payload = req.payload;
        // let secret = await this.admin.sharedSecret(req.keys.epub);
        // if (payload.startsWith('@')) payload = payload.substr(1);
        // let ver       = await everblack().verify(payload, req.keys.pub);
        // let dec2       = await everblack().decrypt(ver, secret);
        let dec       = await this.admin.sharedVerifyAndDecrypt(req.keys.pub, req.keys, payload)
        this.payload  = dec;
        this.keys     = req.keys;
        this.ctrl     = req.ctrl ? await this.admin.sharedVerifyAndDecrypt(req.keys.pub, req.keys, req.ctrl) : '';
        this.response = req.response;   // there may be a response already
        this.req      = req;            // keep the encrypted data
        // todo [OPEN]: implement cancel; must also be encrypted
        return this;
    }


    /*
     * secret request
     */

    /**
     * service side will encrypt with a secret
     *  service pair - request epbu
     *
     * sign with service pair
     *
     * @return {Promise<void>}
     */
    async encryptResponse() {
        // let secret = await this.admin.sharedSecret(this.keys.epub);
        // let enc    = await everblack().encrypt(this.response.payload, secret);
        // let sig    = await this.admin.sign(enc);

        let sig = await this.admin.sharedEncryptAndSign(this.keys, this.response.payload);
        let req    = {
            keys    : this.keys,
            ctrl    : this.req.ctrl,            // use encrypted data
            payload : this.req.payload,         // use encrypted data
            response: sig
        }
        return JSON.stringify(req);

    }

    /**
     * client side will decrypt with a secret
     *  request pair - service epub
     *
     * verify with service pub
     *
     * @return {Promise<void>}
     */
    async decryptResponse(item) {
        let req = JSON.parse(item);
        if (!req.response) return;
        let pair = this.pair;
        let secret = await pair.sharedSecret(this.owner.epub);
        let enc = req.response;
        if (enc.startsWith('@')) enc = enc.substr(1);
        let ver = await everblack().verify(enc, this.owner.pub);
        let dec2 = await everblack().decrypt(ver, secret);

        let dec = await pair.sharedVerifyAndDecrypt(this.owner.pub, this.owner, req.response);
        this.res = Response.fromResponse(dec, this.queue);
        return this.res;
    }

    async respond(response) {
        this.response = response;
        let enc = await this.encryptResponse();
        this.queue.node.queue[this.key].put(enc);
    }

    /**
     * cancel the request for whatever reason
     */
    cancel() {
        // todo [OPEN]: implement
        //  - sent 'cancel' on request and store it again
    }
}

class Response {

    constructor(request, queue) {
        Object.assign(this, { request, queue });
    }

    static fromResponse(payload, queue) {
        let res = new this(null, queue);
        res.payload = payload;
        return res;
    }

    error(err) {
        this.err = err;
        return this;
    }

    async send() {
        return this.request.respond(this);
    }

}
