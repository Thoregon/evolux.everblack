/**
 * A vault stored in universe matter.
 * Pass a matter node to store/retrieve
 * the vault
 *
 * @author: Bernhard Lukassen
 */

import VaultStore from "./vaultstore.mjs";

export default class VaultMatterStore extends VaultStore {

    constructor(node) {
        super();
        this.node = node;
    }

    async read() {
        return this.node.val;
    }

    async write(payload) {
        this.node.put(payload);
    }
}
