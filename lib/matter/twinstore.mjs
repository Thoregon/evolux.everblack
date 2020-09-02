/**
 * a twinstore allow secure communication between two attendents
 * one is the owner who creates the store, the other can be everyone
 * or only invited identites
 *
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

import SecureStore  from "./securestore.mjs";
import IdentityShim from "../identity/identityshim.mjs";

import { ErrNoLocation, ErrNoPermission, ErrNotAuthenticated, ErrStoreExists, ErrStoreExistsNot } from "./errors.mjs";
import { doAsync }                                                                                from "/evolux.universe";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class TwinStore extends SecureStore {

    async create() {
        if (await this.is()) throw ErrStoreExists(this.location);
        if (!this.location) throw ErrNoLocation();
        if (!this.identity) this.signon();
        if (!this.identity) throw ErrNotAuthenticated();

        let owner = { pub: this.identity.pub, epub: this.identity.epub };
        this.owner = owner;
        this.salt  = rnd(24);

        // persist
        let tnode = this.metanode;
        tnode.o   = owner;
        tnode.s   = this.salt;

        await this._createSupplements();
        await this.established();
        // just give background DB procs a chance
        await doAsync();

        return this;
    }

    get pub() {
        return this.owner.pub;
    }

    get epub() {
        return this.owner.epub;
    }

    async join(pubOrAlias) {
        this.signon(pubOrAlias);
        await this._restoreMeta();
        await this.established();
        return this;
    }

    async unlock(identity) {
        if (this.owner) return;     // already done
        if (!this.location) throw ErrNoLocation();
        identity = identity || this.identity;
        await this._restoreMeta();
        if (this.owner.pub !== identity.pub) throw ErrNoPermission();
        await this.established();
        return this;
    }

    async invite(pubOrAlias) {
        await this._restoreMeta();
        if (this.identity.pub !== this.owner.pub) throw ErrNoPermission(this.location);   // need the ownerpair to create member entries
        let identity;
        if (pubOrAlias.pub && pubOrAlias.epub) {
            identity = new IdentityShim(pubOrAlias);
        } else {
            identity = await this.getIdentity(pubOrAlias);
        }
        let member = await this.buildMember(identity, this.salt);
        let member$ = await this._getMemberEntry(member.idhash);
        if (member$) {
            universe.logger.info('Secure Store, member already invited');
            return this;
        }
        this.metanode.m[member.idhash] = member.member;    // persist

        return this;

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
        let tmeta        = this.metanode;
        this.owner       = await tmeta.o.val;     // get meta data from DB
        this.salt        = await tmeta.s.val;
        this.onlyMembers = await tmeta.m.is;      // todo [REFACTOR]: define a store for members only w/o having someone invited
    }

    /**
     * retrieves the member entry from metadata
     * @param idhash
     * @return {Promise}
     * @private
     */
    async _getMemberEntry(idhash) {
        return this.metanode.m[idhash].val;
    }

}
