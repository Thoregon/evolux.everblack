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

import { ErrCantDecrypt, ErrNoPermission, ErrStoreExistsNot } from "../errors.mjs";

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
                try {
                    await this._restoreMeta();
                    let sreq = await Request.fromResponse(item, this, key, req.pair);   // todo [REFACTOR]?: reuse orig request
                    if (!sreq) {
                        // reject(ErrCantDecrypt());
                    } else if (sreq.err) {
                        reject(sreq.err);
                        req.reqnode.off();  // remove modification listener
                    } else {
                        await resolve(sreq.payload);
                        // todo: [OPEN]: purge the resolved request
                        req.reqnode.off();  // remove modification listener
                    }
                } catch (e) {
                    reject(e instanceof ErrNoPermission ? e : ErrInternalError());
                    req.reqnode.off();  // remove modification listener
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
            try {
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
            } catch (e) {
                universe.logger.error('ServiceQueue', e)
                await Response.sendError(this, item, (e instanceof ErrNoPermission ? e : ErrInternalError()), key);  // respond an error
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

    get identity() {
        return this.queue.identity;
    }

    get salt() {
        return this.queue.salt;
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
        let member = this.identity;
        let sig    = await pair.sharedEncryptAndSign(this.owner, this.payload);
        let req    = {
            keys   : { pub: pair.pub, epub: pair.epub },
            ctrl   : member ? await pair.sharedEncryptAndSign(this.owner, { member: { pub: member.pub, epub: member.epub } }) : '',            // todo [OPEN]: implement control data (encrypted)
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
        let req       = JSON.parse(item);
        let payload   = req.payload;
        let admin     = this.admin;
        let dec       = await admin.sharedVerifyAndDecrypt(req.keys.pub, req.keys, payload)
        this.payload  = dec;
        this.keys     = req.keys;
        this.ctrl     = req.ctrl ? await admin.sharedVerifyAndDecrypt(req.keys.pub, req.keys, req.ctrl) : '';
        this.response = req.response;   // there may be a response already
        this.req      = req;            // keep the encrypted data
        // todo [OPEN]: implement cancel; must also be encrypted
        if (this.queue.onlyMembers) {
            if (!this.ctrl.member) throw ErrNoPermission();
            let memberkeys = this.ctrl.member;
            // get the member entry; build id hash, get entry, decrypt, compare pub
            let idhash = await this.getSharedIdHash(memberkeys);
            let memberentry = await this.queue._getMemberEntry(idhash);
            let member = await admin.sharedVerifyAndDecrypt(admin.pub, memberkeys, memberentry);
            if (!member || (member.pub !== memberkeys.pub)) throw ErrNoPermission();
        }
        return this;
    }

    async getSharedIdHash(memberkeys, pub) {
        let admin  = this.admin;
        let idhash = await admin.sharedIdHashWith(memberkeys.pub, memberkeys, this.salt);
        return idhash;
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
        let dec = await pair.sharedVerifyAndDecrypt(this.owner.pub, this.owner, req.response);
        this.res = Response.fromResponse(dec, this.queue);
        return this.res;
    }

    async respond(response) {
        this.response = response;
        let enc = await this.encryptResponse();
        this.queue.node.queue[this.key].put(enc);
    }

    async respondError(queue, reqitem, key, res) {
        let sig = await queue.identity.sharedEncryptAndSign(reqitem.keys, res);
        let req    = {
            keys    : reqitem.keys,
            ctrl    : reqitem.req.ctrl,            // use encrypted data
            payload : reqitem.req.payload,         // use encrypted data
            response: sig
        }
        queue.node.queue[key].put(JSON.stringify(req));
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

    static sendError(queue, reqitem, err, key) {
        // todo: [OPEN]
        return Request.respondError(queue, reqitem, key, err);
    }

    error(err) {
        this.err = err;
        return this;
    }

    async send() {
        return this.request.respond(this);
    }

}
