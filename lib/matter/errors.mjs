/**
 * Messager errors
 *
 * @author: Bernhard Lukassen
 */

import { EError}    from "/evolux.supervise";

export const ErrNotAuthenticated = ()    => new EError(`Not authenticated`,                            "EBS:00001");
export const ErrNoPermission     = ()    => new EError(`No permission`,                                "EBS:00002");
export const ErrStoreExists      = (msg) => new EError(`Store exists: '${msg}'`,                       "EBS:00003");
export const ErrStoreExistsNot   = (msg) => new EError(`Store doesn't exist: '${msg}'`,                "EBS:00004");
export const ErrNoLocation       = (msg) => new EError(`No location im Matter for store: '${msg}'`,    "EBS:00005");
export const ErrIdentityNotFound = (msg) => new EError(`No Identity found for: '${msg}'`,              "EBS:00006");
