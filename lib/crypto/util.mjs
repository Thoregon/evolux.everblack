/**
 *
 *
 * @author: Bernhard Lukassen
 * @licence: MIT
 * @see: {@link https://github.com/Thoregon}
 */

import SafeBuffer                     from "./safebuffer.mjs";

const CRYPTO = crypto.subtle;

const ENCODE = (msg) => new TextEncoder().encode(msg);
const DECODE = (buf) => new TextDecoder('utf8').decode(buf);

export const CRYPTO_SETTINGS = {
    PBKDF2: { hash: { name: 'SHA-256' }, iter: 100000, ks: 64 },
    ECDSA : {
        pair: { name: 'ECDSA', namedCurve: 'P-256' },
        sign: { name: 'ECDSA', hash: { name: 'SHA-256' } }
    },
    ECDH  : { name: 'ECDH', namedCurve: 'P-256' },
    RSA   : { name: 'RSA-OAEP', modulusLength: 4096, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
}

/**
 * build a SHA-256 hash
 * @param {Object ] String } data to hash
 * @return {Promise<unknown[] | undefined>}
 */
export async function sha256hash(data){
    data = (typeof data == 'string')? data : JSON.stringify(data);
    var hash = await CRYPTO.digest({name: 'SHA-256'}, ENCODE(data));
    return SafeBuffer.from(hash);
}

/**
 * Get a RSA public key from (simplified) jwk export for asymmetric encryption
 *
 * @param {String | CryptoKey} n    ... the public key portion
 * @return {Promise<CryptoKey>}
 */
export async function rsapubkey(n) {
    return n instanceof CryptoKey
        ? n
        : await CRYPTO.importKey('jwk', { n, kty: 'RSA', alg: 'RSA-OAEP-256', e: 'AQAB', ext: true}, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

/**
 * Get a RSA private key from (simplified) jwk export for asymmetric encryption
 *
 * @param {String | CryptoKey} key    ... the public key portion
 * @return {Promise<CryptoKey>}
 */
export async function rsaprivkey(key) {
    if (key instanceof CryptoKey) return key;
    const [ d, dp, dq, n, p, q, qi ] = key.split('.');
    const rsakey = { kty: 'RSA', alg: 'RSA-OAEP-256', e: 'AQAB', ext: true, d, dp, dq, n, p, q, qi };
    return await CRYPTO.importKey('jwk', rsakey, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

export async function aeskey(key, salt) {
    if (key instanceof CryptoKey) return key;
    const combo  = key + (salt || shim.random(8)).toString('utf8');
    const hash   = SafeBuffer.from(await sha256hash(combo), 'binary')
    const jwkKey = keyToJwk(hash)
    return await CRYPTO.importKey('jwk', jwkKey, {name:'AES-GCM'}, false, ['encrypt', 'decrypt'])
}

export function jwk(pub, d){  // d === priv
    let [ x, y ]  = pub.split('.');
    let jwk = { kty: "EC", crv: "P-256", ext: true, x, y };

    jwk.key_ops = d ? ['sign'] : ['verify'];
    if (d) jwk.d = d
    return jwk;
}

export function keyToJwk(keyBytes) {
    const keyB64 = keyBytes.toString('base64');
    const k      = keyB64.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
    return { kty: 'oct', k: k, ext: false, alg: 'A256GCM' };
}

/*
export const recall = {
    validity: 12 * 60 * 60, // internally in seconds : 12 hours
    hook    : (props) => props // { iat, exp, alias, remember } // or return new Promise((resolve, reject) => resolve(props)
};
*/

export const isSEA = (t) => (typeof t == 'string') && t.startsWith('SEA{');

export function parseSEA(t) {
    try {
        let isString = (typeof t == 'string');
        if (isString && t.startsWith('SEA{')) { t = t.slice(3) }
        return isString ? JSON.parse(t) : t;
    } catch (e) {}
    return t;
}
