/**
 *
 *
 * @author: blukassen
 */



import { EError }    from "/evolux.supervise";

export const ErrNotImplemented          = (msg)         => new EError(`Method not implemented: ${msg}`,         "EB:00001");
export const ErrVaultInvalid            = ()            => new EError(`Vault invalid`,                          "EB:00002");
export const ErrVaultStoreMissing       = ()            => new EError(`Store for vault missing`,                "EB:00003");
export const ErrVaultSealed             = ()            => new EError(`Vault sealed`,                           "EB:00004");
