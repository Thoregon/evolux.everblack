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

import Store            from "./store.mjs";


import {ErrStoreExists, ErrNotAuthenticated, ErrNoPermission} from "./errors.mjs";
import IdentityShim                                           from "../identityshim.mjs";

const T = 't͛';     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PrivateStore extends Store {

    /**
     * creates a private store for invited members
     * create does join automatically as an owner
     * @return {Promise<void>}
     */
    async create() {
        if (await this.is()) throw ErrStoreExists();
        if (!this.identity) throw ErrNotAuthenticated();

        let ownerpair = await everblack().pair(),
            sharedkey = rnd(64);    // this shared key gets encrypted with a shared secret between owner and invited
        let admin = await this.buildMember(ownerpair, this.identity, sharedkey, true);
        let tmeta = {
            owner   : { pub: ownerpair.pub, epub: ownerpair.epub },
            // salt    : everblack().salt,
            members : {},
        }
        let model = {};
        model[T] = tmeta;

        tmeta.members[admin.idhash] = admin.member;

        this.model  = model;
        // this.member = admin.def;
        // this.sharedkey  = sharedkey;
        // make persistent
        // this.node   = model;

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

        this.model[T].members[member.idhash] = member.member;

        return this;
    }

    join(keypair) {
        this.signon(keypair);
        // decrypt own member entry and get the shared key
        this.unlock();
        // create an attest in identities store

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
            idhash = await everblack().work(identity.pub, secret),    // user can only identify himself
            memberdef = {
                alias: identity.alias,
                pub  : identity.pub,
                sharedkey
            };
        if (asowner) memberdef.ownerpair = ownerpair;       // todo [REFACTOR]: store the ownerkey as an identity attest

        // encrypt member
        let enc    = await everblack().encrypt(memberdef, secret);
        let signed = await everblack().sign(enc, ownerpair);

        return { idhash, member: signed, def: memberdef };
    }

    async unlock(identity) {
        if (this.member) return; // already unlocked
        identity = identity || this.identity;
        // check if tmeta is available
        let tmeta = this.model[T];
        if (!identity) throw ErrNotAuthenticated();
        let secret = await identity.sharedSecret(tmeta.owner.epub),
            idhash = await everblack().work(identity.pub, secret);    // user can only identify himself

        // decrypt member
        let data = tmeta.members[idhash];
        let signed = await everblack().verify(data, tmeta.owner.pub);
        let dec = await everblack().decrypt(signed, secret);
        this.member = dec;
        return this;
    }
}
