/**
 *
 *
 * @author: Bernhard Lukassen
 */

import Everblack                        from "./lib/everblack.mjs";

// export { default as GunAdapter }        from './lib/gunadapter.mjs';

export { default as Vault }             from './lib/vault/vault.mjs';
export { default as VaultStore }        from './lib/vault/storage/vaultstore.mjs';
export { default as VaultMemStore }     from './lib/vault/storage/vaultmemstore.mjs';
export { default as VaultFileStore }    from './lib/vault/storage/vaultfilestore.mjs';

export { default as SharedCrypto }      from './lib/identity/sharedcrypto.mjs';
export { default as IdentityShim }      from './lib/identity/identityshim.mjs';

export const service = new Everblack();
