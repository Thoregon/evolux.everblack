/**
 * Base class for secure stored objects
 *
 * Runtime content:
 * - location   ... path from matter root to the store
 * - node       ... matter node for the store
 * - model      ... copy of persisted data to work with
 *
 * todo [OPEN]: we need purge and oblivion
 *
 * @author: Bernhard Lukassen
 */

import { doAsync, timeout } from '/evolux.universe';
import IdentityShim       from "../identity/identityshim.mjs";

import { ErrIdentityNotFound, ErrNoLocation, ErrNotAuthenticated, ErrNotImplemented } from "./errors.mjs";

const T = universe.T;     // meta data property name

export default class SecureStore {

    /**
     * define the location in matter
     *
     * todo [OPEN]: mark whole path with
     * @param node - matter node where the chat is located
     * @return {SecureStore}
     */
    static at(nodelocation) {
        let store = new this();
        store.location = nodelocation;
        store.node = universe.matter.path(nodelocation);
        return store;
    }

    /**
     * define the location in matter
     *
     * todo [OPEN]: mark whole path with
     * @param node - matter node where the chat is located
     * @return {SecureStore}
     */
/*
    static atNode(node, location) {
        let store = new this();
        store.location = location;
        store.node = node;
        return store;
    }
*/

    get isSecureStore() {
        return true;
    }
    /**
     * all stores use this node to store the metadata
     */
    get metanode() {
        return this.node[T];
    }
    /**
     * all stores use this node to store their content
     */
    get contentnode() {
        return this.node[`${T}c`];
    }

    /**
     * create this store if missing.
     * set applied identity or current user as owner
     *
     * @return {Promise<Securestore|*>}
     */
    async createIfMissing() {
        if (!this.location) throw ErrNoLocation();
        // this may be a bug in gun.
        if (!await this.is()) {
            await timeout(200);
        }
        // now ask again; should be available if it exists
        if (await this.is()) {
            if (!this.identity) this.signon();
            await this.unlock();
            return this;
        } else {
            return await this.create();
        }
    }

    async create() {
        throw ErrNotImplemented('create');
    }

    /**
     * hook method will be called after this secure store is usable (initialised)
     * @return {Promise<void>}
     */
    async established() {
        // implement by subclass if needed
    }

    async _createSupplements() {
        // implement by subclass if needed
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
        if (!this.location) throw ErrNoLocation();
        return await this.node.is;
    }

    /**
     * if the keypair is omitted, the currently signed on identity is used
     * @param keypair
     */
    signon(keypair) {
        // const IdentityReflection = universe.Identity.IdentityReflection;
        this.identity = keypair
                        ? keypair instanceof IdentityShim ? keypair : new IdentityShim(keypair)
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

    async getIdentity(pubOrAlias) {
        await this.unlock();
        let identity = await universe.Identity.find(pubOrAlias);
        if (!identity) throw ErrIdentityNotFound(pubOrAlias);
        return identity;
    }

    /**
     * drop this secure store
     * can only done by owner(s)
     * throws if you are not allowed
     */
    async drop() {

    }
}
