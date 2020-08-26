/**
 * Messager errors
 *
 * @author: Bernhard Lukassen
 */

import { EError}    from "/evolux.supervise";

export const ErrNotImplemented   = (msg) => new EError(`Not implemented: ${msg}`,                   "EBS:00000");
export const ErrNotAuthenticated = ()    => new EError(`Not authenticated`,                            "EBS:00001");
export const ErrNoPermission     = ()    => new EError(`No permission`,                                "EBS:00002");
export const ErrStoreExists      = (msg) => new EError(`Store exists: '${msg}'`,                       "EBS:00003");
export const ErrStoreExistsNot   = (msg) => new EError(`Store doesn't exist: '${msg}'`,                "EBS:00004");
export const ErrNoLocation       = ()    => new EError(`No location for store`,                        "EBS:00005");
export const ErrIdentityNotFound = (msg) => new EError(`No Identity found for: '${msg}'`,              "EBS:00006");
export const ErrCantDecrypt      = ()    => new EError(`Can't decrypt`,                                "EBS:00007");
