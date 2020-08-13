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

import { ErrStoreExists, ErrNotAuthenticated, ErrNoPermission, ErrStoreExistsNot } from "./errors.mjs";

const T = universe.T;     // meta data property name

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PrivateStore extends Store {


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
            writepair = await everblack().pair(),
            sharedkey = rnd(64),    // this shared key gets encrypted with a shared secret between owner and invited
            salt      = rnd(24);    // a salt for work

        let admin = await this.buildMember(ownerpair, this.identity, sharedkey, true, writepair, salt);
        let owner = { pub: ownerpair.pub, epub: ownerpair.epub };

        let tmeta = {
            o: { pub: ownerpair.pub, epub: ownerpair.epub },        // owner = admin(s); can invite others
            w: { pub: writepair.pub, epub: writepair.epub },        // write; use to verify messages
            s: salt,
            m: {},                                                  // members; can be admins, write permitted users and read permitted users
        }
        tmeta.members[admin.idhash] = admin.member;
        this._ensureModel();
        this.model[T]  = tmeta;

        // persist
        let tmetanode = this.node[T];
        tmetanode.o   = owner;
        tmetanode.m[admin.idhash] = admin.member;

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
        this.node[T].m[member.idhash] = member.member;    // persist

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


    grantWrite() {

    }

    revokeWrite() {

    }

    /*
     * helpers
     */

    initModel(model) {}

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
        let idhash = await owner.sharedIdHashWith(identity, salt), // user can only identify himself
            memberdef = {
                alias: identity.alias,
                pub  : identity.pub,
                sharedkey
            };
        if (asowner) memberdef.ownerpair = ownerpair;       // todo [REFACTOR]: store the ownerkey as an identity attest
        if (writepair) memberdef.write = writepair;         // use to sign messages

        // encrypt member
        let signed = await owner.sharedEncryptAndSign(identity, memberdef);
        // let enc = everblack().encrypt(memberdef, secret);
        // let signed = await everblack().sign(enc, ownerpair);

        return { idhash, member: `@${signed}`, def: memberdef };
    }

    /**
     * try to get and decrypt the member entry for the given identity
     *
     * @param identity
     */
    async unlock(identity) {
        if (this.member) return; // already unlocked
        await this._tmeta();
        identity = identity || this.identity;
        // check if tmeta is available
        if (!identity) throw ErrNotAuthenticated();
        let o = new IdentityShim(this.owner);
        let idhash = await identity.sharedIdHashWith(o);

        // decrypt member
        let data = await this._member(idhash);
        if (!data) throw ErrNoPermission();
        data = data.substr(1);
        let signed = await everblack().verify(data, this.owner.pub);
        let dec = await identity.sharedVerifyAndDecrypt(o, data); // everblack().decrypt(signed, secret);  // remove the '@' at the beginning
        this.member = dec;
        return this;
    }

    async _tmeta() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        if (this.owner) return;
        let owner = await this.node[T].o.val;     // get meta data from DB
        this.owner = owner;
        let write = await this.node[T].w.val;
        if (write) this.write = write;
    }

    async _member(idhash) {
        return await this.node[T].m[idhash].val;
    }
}
