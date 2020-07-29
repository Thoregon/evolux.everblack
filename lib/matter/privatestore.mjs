/**
 * a private store can be used only by invited users
 *
 *
 * Structure
 {
       t͛: {     // thoregon metadata
           owner: { pub, epub },   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
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

import { doAsync }  from '/evolux.universe';

import Store        from "./store.mjs";
import IdentityShim from "../identityshim.mjs";

import {ErrStoreExists, ErrNotAuthenticated, ErrNoPermission, ErrStoreExistsNot} from "./errors.mjs";

const T = 't͛';     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PrivateStore extends Store {

    async createIfMissing() {
        if (await this.is()) {
            if (!this.identity) this.signon();
            await this.unlock();
            return this;
        } else {
            return this.create();
        }
    }

    /**
     * creates a private store for invited members
     * create does join automatically as an owner
     * @return {Promise<void>}
     */
    async create() {
        if (await this.is()) throw ErrStoreExists(this.location);
        if (!this.identity) this.signon();
        if (!this.identity) throw ErrNotAuthenticated();

        let ownerpair = await everblack().pair(),
            sharedkey = rnd(64);    // this shared key gets encrypted with a shared secret between owner and invited
        let admin = await this.buildMember(ownerpair, this.identity, sharedkey, true);
        let owner = { pub: ownerpair.pub, epub: ownerpair.epub };

        let tmeta = {
            owner   : { pub: ownerpair.pub, epub: ownerpair.epub },
            // salt    : everblack().salt,
            members : {},
        }
        tmeta.members[admin.idhash] = admin.member;
        this._ensureModel();
        this.model[T]  = tmeta;

        // persist
        let tmetanode = this.node[T];
        tmetanode.owner   = owner;
        tmetanode.members[admin.idhash] = admin.member;

        // let members = { a: 'A' };
        // members[admin.idhash] = admin.member;
        // await doAsync();
        // tmetanode.members = members;

        return this;
    }

    async invite(pubOrAlias) {
        // decrypt own member entry and get the shared key
        await this.unlock();
        let admin = this.member;
        if (!admin || !admin.ownerpair) throw ErrNoPermission(this.location);
        let identity = await universe.Identity.find(pubOrAlias);
        if (!identity) throw ErrIdentityNotFound(pubOrAlias);
        // identity = new IdentityShim(identity);
        let ownerpair = admin.ownerpair;
        let sharedkey = admin.sharedkey;
        // create a member entry in meta/members
        let member = await this.buildMember(ownerpair, identity, sharedkey, false);
        // todo [OPEN]: check if invited
        if (!this.model) this.model = {};
        this.model[T].members[member.idhash] = member.member;
        this.node[T].members[member.idhash] = member.member;    // persist

        return this;
    }

    async join(keypair) {
        this.signon(keypair);
        // decrypt own member entry and get the shared key
        await this.unlock();
        // todo [OPEN]: create an attest in identity store if missing
        return this;
    }

    revoke(user) {

        return this;
    }

    leave() {

    }


    /*
     * helpers
     */

    initModel(model) {}

    /**
     * build a member entry.
     * can only be used by an owner knowing the ower keypair
     *
     * @param ownerpair
     * @param identity
     * @return {String} member entry
     */
    async buildMember(ownerpair, identity, sharedkey, asowner) {
        let owner = new IdentityShim(ownerpair);
        // encrypt the entry with the channel pubkey and the users pair
        let secret = await owner.sharedSecret(identity.epub),
            idhash = await this.getIdhash(identity, secret),    // user can only identify himself
            memberdef = {
                alias: identity.alias,
                pub  : identity.pub,
                sharedkey
            };
        if (asowner) memberdef.ownerpair = ownerpair;       // todo [REFACTOR]: store the ownerkey as an identity attest

        // encrypt member
        let enc    = await everblack().encrypt(memberdef, secret);
        let signed = await everblack().sign(enc, ownerpair);

        return { idhash, member: `@${signed}`, def: memberdef };
    }

    async getIdhash(identity, secret) {
        let hash = await everblack().work(identity.pub, secret);
        // hash = `@${hash.replace(/[=\+\/]/g, '')}`;
        hash = `@${hash}`;
        return hash;
    }

    async unlock(identity) {
        if (this.member) return; // already unlocked
        this._ensureModel();
        await this._tmeta();
        identity = identity || this.identity;
        // check if tmeta is available
        let tmeta = this.model[T];
        if (!identity) throw ErrNotAuthenticated();
        let secret = await identity.sharedSecret(tmeta.owner.epub),
            idhash = await this.getIdhash(identity, secret);    // user can only identify himself

        // decrypt member
        let data = tmeta.members && tmeta.members[idhash] ? tmeta.members[idhash] : await this._member(idhash);
        if (!data) throw ErrNoPermission();
        data = data.substr(1);
        let signed = await everblack().verify(data, tmeta.owner.pub);
        let dec = await everblack().decrypt(signed, secret);  // remove the '@' at the beginning
        this.member = dec;
        return this;
    }

    _ensureModel() {
        if (!this.model) this.model = {};
        if (!this.model[T]) this.model[T] = {};
        if (!this.model[T].members) this.model[T].members = {};
    }

    async _tmeta() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.model && this.model[T] && this.model[T].owner) return;
        this._ensureModel();
        let owner = await this.node[T].owner.val;     // get meta data from DB
        this.model[T].owner = owner;
    }

    async _member(idhash) {
        let member = await this.node[T].members[idhash].val;
        if (member) {
            this._ensureModel();
            this.model[T].members[member.idhash] = member;
            return member;
        }
    }
}
