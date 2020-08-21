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

import IdentityShim from "../identity/identityshim.mjs";

import { ErrNoLocation, ErrNotAuthenticated, ErrNotImplemented } from "./errors.mjs";

const T = universe.T;     // meta data property name

export default class Store {

    /**
     * define the location in matter
     *
     * todo [OPEN]: mark whole path with
     * @param node - matter node where the chat is located
     * @return {Store}
     */
    static at(nodelocation) {
        let store = new this();
        store.location = nodelocation;
        store.node = universe.matter.path(nodelocation);
        return store;
    }

    /**
     * create this store if missing.
     * set applied identity or current user as owner
     *
     * @return {Promise<Store|*>}
     */
    async createIfMissing() {
        if (await this.is()) {
            if (!this.identity) this.signon();
            await this.unlock();
            return this;
        } else {
            return this.create();
        }
    }

    async create() {
        throw ErrNotImplemented('create');
    }

    async unlock() {
        throw ErrNotImplemented('unlock');
    }

    /**
     * checks if there is an entry in Matter
     *
     * @return {Promise<boolean|any>}
     */
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
     * get a hash for the member without exhibiting the identity
     * @param identity
     * @param secret
     * @return {Promise<string>}
     */
    async getIdhash(identity, secret) {
        let hash = await everblack().work(identity.pub, secret);
        hash = `@${hash.replace(/[=]/g, '')}`;
        return hash;
    }

    /**
     * drop this secure store
     * can only done by owner(s)
     * throws if you are not allowed
     */
    async drop() {

    }
}
