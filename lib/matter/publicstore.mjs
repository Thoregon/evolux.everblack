/**
 * allow secure communication between publisher and any others
 * needs no invitation, but gives encypted communication and
 * prevents tracking
 *
 * requests are signed by the requesting pair
 * responses signed by the owner
 *
 * Structure
 {
       t͛: {     // thoregon metadata
           o: <owner_pubkey>,   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
       }
  }
 *
 * @author: Bernhard Lukassen
 */

const T = universe.T;     // meta data property name

import Store        from "./store.mjs";
import IdentityShim from "../identity/identityshim.mjs";

import { ErrNoLocation, ErrNoPermission, ErrNotAuthenticated, ErrStoreExists, ErrStoreExistsNot } from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PublicStore extends Store {

    async create() {
        if (await this.is()) throw ErrStoreExists(this.location);
        if (!this.location) throw ErrNoLocation();
        if (!this.identity) this.signon();
        if (!this.identity) throw ErrNotAuthenticated();

        let owner = { pub: this.identity.pub, epub: this.identity.epub };
        this.owner = owner;
        this.salt  = rnd(24);

        // persist
        let tnode = this.node[T];
        tnode.o   = owner;
        tnode.s   = this.salt;

        return this;
    }

    get pub() {
        return this.owner.pub;
    }

    get epub() {
        return this.owner.epub;
    }

    async unlock(identity) {
        if (this.owner) return;     // already done
        if (!this.location) throw ErrNoLocation();
        identity = identity || this.identity;
        await this._restoreMeta();
        if (this.owner.pub !== identity.pub) throw ErrNoPermission();
        return this;
    }

    async invite(pubOrAlias) {
        await this._restoreMeta();
        let admin = this.member;
        if (!admin || !admin.ownerpair) throw ErrNoPermission(this.location);   // need the ownerpair to create member entries
        let identity;
        if (pubOrAlias.pub && pubOrAlias.epub) {
            identity = new IdentityShim(pubOrAlias);
        } else {
            identity = this.getIdentity(pubOrAlias);
        }

    }

    /**
     * build a member entry.
     * can only be used by an owner knowing the ower keypair
     *
     * @param ownerpair     ... can create member entries
     * @param identity      ... identity to become a member
     * @param sharedkey     ... shared key to encrypt/decrypt messages
     * @return {String}     ... member entry
     */
    async buildMember(identity, salt) {
        // encrypt the entry with the channel pubkey and the users pair
        let admin = this.identity;
        let idhash = await admin.sharedIdHashWith(identity.pub, identity, salt), // user can only identify himself
            memberdef = {
                alias: identity.alias,
                pub  : identity.pub,
            };

        // encrypt member
        let signed = await admin.sharedEncryptAndSign(identity, memberdef);

        return { idhash, member: signed, def: memberdef };
    }


    async _restoreMeta() {
        if (this.owner) return;     // already done
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        this.owner = await this.node[T].o.val;     // get meta data from DB
        this.salt  = await this.node[T].s.val;

    }

    /**
     * retrieves the member entry from metadata
     * @param idhash
     * @return {Promise}
     * @private
     */
    async _getMemberEntry(idhash) {
        return this.node[T].m[idhash].val;
    }

}
