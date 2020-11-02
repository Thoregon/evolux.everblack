/**
 * a private store can be used only by invited users
 *
 *
 * Structure
 {
       t͛: {     // thoregon metadata
           o: { pub, epub },   // this is not a user public key, this key is unique and the keypair is available for the admin in its member entry
           w: { pub, epub },   // pub & epub to verify writes
           s: <salt>,
           m: {
               <user_pubkey_hash>: { nickname: '', icon: '', sharedkey: ''}, // the content is encrypted, can be decrypted with the owner pub key and the users priv key
           }
       }
  }
 *
 * @author: Bernhard Lukassen
 */

import { doAsync, timeout } from '/evolux.universe';

import SecureStore  from "./securestore.mjs";
import IdentityShim from "../identity/identityshim.mjs";

import {
    ErrStoreExists,
    ErrNotAuthenticated,
    ErrNoPermission,
    ErrStoreExistsNot,
    ErrIdentityNotFound,
    ErrNoLocation
} from "./errors.mjs";

const T = universe.T;     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class SharedStore extends SecureStore {


    /**
     * creates a private store for invited members
     * identity which does this create automatically becomes an admin
     * @return {Promise<void>}
     */
    async create() {
        if (!this.location) throw ErrNoLocation();
        if (await this.is()) throw ErrStoreExists(this.location);
        if (!this.identity) this.signon();
        if (!this.identity) throw ErrNotAuthenticated();

        let ownerpair = await everblack().pair(),
            writepair = await everblack().pair(),
            sharedkey = rnd(64),    // this shared key gets encrypted with a shared secret between owner and invited
            salt      = rnd(24);    // a salt for work

        let admin = await this.buildMember(ownerpair, this.identity, sharedkey, true, writepair, salt);
        let owner = { pub: ownerpair.pub, epub: ownerpair.epub };
        let write = { pub: writepair.pub, epub: writepair.epub };

        // persist
        let tnode = this.metanode;
        tnode.o   = owner;
        tnode.w   = write;
        tnode.s   = salt;
        tnode.m[admin.idhash] = admin.member;   // contains the encrypted member entry

        // now unlock; keep meta data for encryption and signing
        this.member = admin.def;        // contains the readable member entry
        this.owner  = owner;
        this.write  = write;
        this.salt   = salt;
        this._completeMember();

        await this._createSupplements();
        await this.established();
        // just give background DB procs a chance
        await doAsync();

        return this;
    }

    /**
     * invite an identity by its alias or public key.
     * Also arbitrary public keys can be invited, it must not be an existing identity.
     * This is services or temporary access.
     *
     * todo [OPEN]: notify identity about invitation
     *
     * @param pubOrAlias    ... can be an alias of an identity, a pub key of an identity or a pub key object { pub, epub }
     * @return {Promise<Sharedstore>}
     */
    async invite(pubOrAlias, grantWrite = true) {
        await this.join();   // restore meta and member data
        let admin = this.member;
        if (!admin || !admin.ownerpair) throw ErrNoPermission(this.location);   // need the ownerpair to create member entries
        let identity;
        if (pubOrAlias.pub && pubOrAlias.epub) {
            identity = new IdentityShim(pubOrAlias);
        } else {
            identity = await this.getIdentity(pubOrAlias);
        }
        // create a member entry in meta/members
        let member = await this.buildMember(admin.ownerpair, identity, admin.sharedkey, false, grantWrite ? admin.writepair : undefined, this.salt);

        let member$ = await this._getMemberEntry(member.idhash);
        if (member$) {
            universe.logger.info('Secure Store, member already invited');
            return this;
        }
        this.metanode.m[member.idhash] = member.member;    // persist

        return this;
    }

    async join(keypair) {
        this.signon(keypair);
        // decrypt own member entry and get the shared key
        await this.unlock();
        // todo [OPEN]: create an attest in identity store if missing
        return this;
    }

    revoke(pubOrAlias) {
        // build id hash and remove member entry
        let idhash = this.getMemberKey(pubOrAlias);
        if (idhash) {
            delete this.metanode.m[idhash];
        }
        return this;
    }

    leave() {
        delete this.member;
        delete this.owner;
        delete this.write;
        delete this.salt;
        return this;
    }

    /**
     * grant an identity write permission by adding the write keypair
     *
     * todo [OPEN]: notify identity about grant
     *
     * @param pubOrAlias
     * @return {Promise<SharedStore>}
     */
    async grantWrite(pubOrAlias) {
        await this.modifyMemberEntry(pubOrAlias, (member) => {
            if (!this.member.write) throw ErrNoPermission();
            member.writepair = this.member.writepair;
        });
        return this;
    }

    async revokeWrite(pubOrAlias) {
        await this.modifyMemberEntry(pubOrAlias, (member) => {
            delete member.writepair;
        });
        return this;
    }

    /*
     * helpers
     */

    async getMemberKey(pubOrAlias) {
        let identity = await this.getIdentity(pubOrAlias);
        let idhash = await this._owner().sharedIdHashWith(identity.pub, identity, this.salt);
        return idhash;
    }

    async modifyMemberEntry(pubOrAlias, workerfn) {
        let identity = await this.getIdentity(pubOrAlias);
        let idhash = await this._owner().sharedIdHashWith(identity.pub, identity, this.salt);

        // decrypt member
        let enc = await this._getMemberEntry(idhash);
        if (!enc) throw ErrIdentityNotFound(pubOrAlias);
        let owner = this.member.owner;
        let member = await owner.sharedVerifyAndDecrypt(owner.pub, identity, enc);

        // do modifications
        await workerfn(member);

        // encrypt and store again
        let signed = await owner.sharedEncryptAndSign(identity, member);
        this.metanode.m[idhash] = signed;
    }

    _owner() {
        let admin = this.member;
        if (!admin || !admin.owner) throw ErrNoPermission(this.location);
        return admin.owner;
    }

    /**
     * build a member entry.
     * can only be used by an owner knowing the ower keypair
     *
     * @param ownerpair     ... can create member entries
     * @param identity      ... identity to become a member
     * @param sharedkey     ... shared key to encrypt/decrypt messages
     * @param [asowner]     ... make the identity an admin
     * @param [writepair]   ... grant write, use to sign the encrypted message
     * @return {String}     ... member entry
     */
    async buildMember(ownerpair, identity, sharedkey, asowner, writepair, salt) {
        let owner = new IdentityShim(ownerpair);
        // encrypt the entry with the channel pubkey and the users pair
        let idhash = await owner.sharedIdHashWith(identity.pub, identity, salt), // user can only identify himself
            memberdef = {
                alias: identity.alias,
                pub  : identity.pub,
                sharedkey
            };
        if (asowner) memberdef.ownerpair = ownerpair;       // todo [REFACTOR]: store the ownerkey as an identity attest
        if (writepair) memberdef.writepair = writepair;         // use to sign messages

        // encrypt member
        let signed = await owner.sharedEncryptAndSign(identity, memberdef);
        // let enc = everblack().encrypt(memberdef, secret);
        // let signed = await everblack().sign(enc, ownerpair);

        return { idhash, member: signed, def: memberdef };
    }

    /**
     * try to get and decrypt the member entry for the given identity
     *
     * @param identity
     */
    async unlock(identity) {
        if (this.member) return; // already unlocked
        if (!this.location) throw ErrNoLocation();
        // this maybe a gun bug,
        if (!await this.is()) {
            await timeout(200);
            await this.is();
        }
        await this._restoreMeta();
        identity = identity || this.identity;
        // check if tmeta is available
        if (!identity) throw ErrNotAuthenticated();
        let ownerpub = new IdentityShim(this.owner);
        let idhash = await identity.sharedIdHashWith(identity.pub, ownerpub, this.salt);

        // decrypt member
        let data = await this._getMemberEntry(idhash);
        if (!data) throw ErrNoPermission();
        this.member = await identity.sharedVerifyAndDecrypt(ownerpub.pub, ownerpub, data);
        if (!this.member) throw ErrNoPermission();
        this._completeMember();
        await this.established();
        return this;
    }

    _completeMember() {
        let member = this.member;
        if (member.ownerpair) member.owner = new IdentityShim(member.ownerpair);
        if (member.writepair) member.write = new IdentityShim(member.writepair);
    }

    /**
     * restores meta information for this store
     * @return {Promise<void>}
     * @private
     */
    async _restoreMeta() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.owner) return;
        let tnode = this.metanode;   // get meta data from DB node
        this.owner = await tnode.o.val;
        this.write = await tnode.w.val;
        this.salt  = await tnode.s.val;
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
