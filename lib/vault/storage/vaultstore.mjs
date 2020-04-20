/**
 * This is an extremely simple interface to
 * store and read arbitrary data
 *
 * @author: Bernhard Lukassen
 */

import { ErrNotImplemented }    from '../../errors.mjs';

export default class VaultStore {

    constructor() {
    }

    /**
     * Read the whole content of the vault. Should be a string containing a JSON
     * @return {Promise<String>} payload - whole content of vault
     */
    async read() {
        throw ErrNotImplemented('VaultStore->read()');
    }

    /**
     * Write the whole content of the vault. Is a string containing a JSON
     * @param {String} payload
     * @return {Promise<void>}
     */
    async write(payload) {
        throw ErrNotImplemented('VaultStore->write()');
    }
}
