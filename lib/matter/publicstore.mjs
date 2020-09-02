/**
 * just the owner can write to the store
 * all others can verify and decrypt
 *
 * @author: Bernhard Lukassen
 */

import SecureStore  from "./securestore.mjs";
import IdentityShim from "../identity/identityshim.mjs";

import { ErrNoLocation, ErrNoPermission, ErrNotAuthenticated, ErrStoreExists, ErrStoreExistsNot } from "./errors.mjs";
import { doAsync }                                                                                from "../../../evolux.universe";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PublicStore extends SecureStore {

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

        await doAsync();

        return this;
    }


    async unlock() {
        await this.established();
    }

    get pub() {
        return this.owner.pub;
    }

    get epub() {
        return this.owner.epub;
    }

    async _restoreMeta() {
        if (this.owner) return;     // already done
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        let tmeta        = this.metanode;
        this.owner       = await tmeta.o.val;     // get meta data from DB
        this.salt        = await tmeta.s.val;
    }

}
