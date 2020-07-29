/**
 * Base class for secure stored objects
 *
 * Runtime content:
 * - location   ... path from matter root to the store
 * - node       ... matter node for the store
 * - model      ... copy of persisted data to work with
 *
 * @author: Bernhard Lukassen
 */

import IdentityShim                         from "../identityshim.mjs";
import {ErrNoLocation, ErrNotAuthenticated} from "./errors.mjs";

const T = 't͛';     // meta data property name

export default class Store {

    /**
     * define the location in matter
     * @param node - matter node where the chat is located
     * @return {Store}
     */
    static at(nodelocation) {
        let store = new this();
        store.location = nodelocation;
        store.node = universe.matter.path(nodelocation);
        return store;
    }

    async is() {
        if (this.model) return true;
        if (!this.location) throw ErrNoLocation();
        return await this.node.is;
    }

    /**
     * if the keypair is omitted, the currently signed on identity is used
     * @param keypair
     */
    signon(keypair) {
        this.identity = keypair
                        ? new IdentityShim(keypair)
                        : universe.identity;

        if (!this.identity) throw ErrNotAuthenticated();
        return this;
    }

    /**
     * drop this secure store
     * can only done by owner(s)
     * throws if you are not allowed
     */
    async drop() {

    }
}
