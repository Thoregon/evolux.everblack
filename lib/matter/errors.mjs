/**
 * Messager errors
 *
 * @author: Bernhard Lukassen
 */

import { EError}    from "/evolux.supervise";

export const ErrInternalError    = (msg) => new EError(`Internal Error${msg ? ' ' + msg : ''}`,        "EB:00000");
export const ErrNotImplemented   = (msg) => new EError(`Not implemented: ${msg}`,                      "EB:00001");
export const ErrNotAuthenticated = ()    => new EError(`Not authenticated`,                            "EB:00002");
export const ErrNoPermission     = ()    => new EError(`No permission`,                                "EB:00003");
export const ErrStoreExists      = (msg) => new EError(`Store exists: '${msg}'`,                       "EB:00004");
export const ErrStoreExistsNot   = (msg) => new EError(`Store doesn't exist: '${msg}'`,                "EB:00005");
export const ErrNoLocation       = ()    => new EError(`No location for store`,                        "EB:00006");
export const ErrIdentityNotFound = (msg) => new EError(`No Identity found for: '${msg}'`,              "EB:00007");
export const ErrCantDecrypt      = ()    => new EError(`Can't decrypt`,                                "EB:00008");
export const ErrNotPersistent    = (mag) => new EError(`Entity not persistent: '${msg}'`,              "EB:00009");
export const ErrNoIdentity       = ()    => new EError(`Not an Identity`,                              "EB:00010");
