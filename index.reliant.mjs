/**
 *
 *
 * @author: Bernhard Lukassen
 */

// todo: check what functions from everblack will be needed on reliant nodes
import Everblack                        from "./lib/reliant/everblack.mjs";

/*
export { default as Vault }             from './lib/vault/vault.mjs';
export { default as VaultStore }        from './lib/vault/storage/vaultstore.mjs';
export { default as VaultMemStore }     from './lib/vault/storage/vaultmemstore.mjs';
*/

export const service = new Everblack();
