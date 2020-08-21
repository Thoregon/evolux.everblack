/**
 * allow secure communication between publisher and any others
 * needs no invitation, but gives encypted communication and
 * prevents tracking
 *
 * requests are signed by the requesting pair
 * responses signed by the owner
 *
 * @author: Bernhard Lukassen
 */

import Store                                                                     from "./store.mjs";
import IdentityShim                                                              from "../identity/identityshim.mjs";
import {ErrNoPermission, ErrNotAuthenticated, ErrStoreExists, ErrStoreExistsNot} from "./errors.mjs";

const rnd       = (l) => universe.random(l);
const everblack = () => universe.Everblack;

export default class PublicStore extends Store {

    async create() {
        if (await this.is()) throw ErrStoreExists(this.location);
        if (!this.identity) this.signon();
        if (!this.identity) throw ErrNotAuthenticated();
        this._ensureModel();

        let owner = { pub: this.identity.pub, epub: this.identity.epub };
        this.owner = owner ;

        // persist
        let tmetanode = this.node[T];
        tmetanode.o   = owner;

        return this;
    }

    get pub() {
        return this.owner.pub;
    }

    get epub() {
        return this.owner.epub;
    }

    async unlock(identity) {
        return this;
    }

    async _tmeta() {
        if (!await this.is()) throw ErrStoreExistsNot(this.location);
        let owner = await this.node[T].owner.val;     // get meta data from DB
        this.owner = owner;
    }

}
