/**
 *
 *
 * @author: Bernhard Lukassen
 */

import VaultStore                   from './vaultstore.mjs';

export default class VaultMemStore extends VaultStore {

    constructor() {
        super();
        this.content = '';
    }

    async read() {
        return this.content;
    }

    async write(payload) {
        this.content = payload;
    }
}
