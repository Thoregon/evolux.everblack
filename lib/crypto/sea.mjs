/**
 * This is an ES6 refactoring of GUN/SEA
 * --> https://gun.eco/docs/SEA, https://github.com/amark/gun/tree/master/sea
 * extended with RSA asymetric encryption (encrypt with pub, decrypt with priv)
 * well RSA needs very long keys, but RSA-OAEP is currently the onyl supported
 * algorithm for public key encryption
 * in the opt for pair() they can be omitted.
 *
 * Differences:
 * - crypto methods throws anyways
 * - the keypair for signing is renamed: pub -> spub, priv -> spriv
 * - pair() adds a keypair for async encryption (RSA)
 * - work() split in to work() with PBKDF2 and hash() with SHA-256
 *
 * todo [OPEN]
 *  - crypto methods should work directly with CryptoKeys to avoid permanent export/import
 *      - add separate serialize/restore for persistent keys
 *      - in future the keys should be moved to a SE (secure element) or a 2FA device
 *  - add certify (like a signature) and proof for software modules and packages
 *  - there may be a chain of certs for developers and certificants
 *
 *  @see
 *  - https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
 *  - https://github.com/diafygi/webcrypto-examples
 *  - https://gist.github.com/deiu/2c3208c89fbc91d23226
 */

import SafeBuffer from "./safebuffer.mjs";

import { CRYPTO_SETTINGS, parseSEA, aeskey, rsapubkey, rsaprivkey, sha256hash } from "./util.mjs"

// shorten
const ENCODE = (msg) => new TextEncoder().encode(msg);
const DECODE = (buf) => new TextDecoder('utf8').decode(buf);
const CRYPTO = crypto.subtle;   // shortcut

// literals
const AESGCM   = 'AES-GCM';             // symmetric encryption:    AES Galois/Counter Mode (Advanced Encryption Standard)
const RSA      = 'RSA-OAEP';            // asymmetric encryption:   RSA Optimal Asymmetric Encryption Padding (Rivest–Shamir–Adleman)
const ECDSA    = 'ECDSA';               // signing and verifying:   Elliptic Curve Digital Signature Algorithm, requires a named curve (P-256)
const ECDH     = 'ECDH';                // secret key exchange:     Elliptic Curve Diffie-Hellman, requires a named curve (P-256)
const P256     = 'P-256';               // named curve for ECDSA
const SHA256   = 'SHA-256';             // hash (HMAC) algorithm
const PBKDF2   = 'PBKDF2';              // derive key from seed:    Password-Based Key Derivation Function 2
const PUBEXP   = new Uint8Array([1, 0, 1]);
const KEYLEN   = 4096;
const BASE64   = 'base64';
const UTF8     = 'utf8';
const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXZabcdefghijklmnopqrstuvwxyz';

// defined settings
const settings = CRYPTO_SETTINGS;

export default class SEA {

    /**
     * expose the SEA options
     * @return {Object}
     */
    static get opt() {
        return settings;
    }

    /**
     * get a random character string with the specified length
     *
     * build long enough strings > 16 characters
     *
     * @param {Number} len ... length of random char string, default 32
     * @param {String} [chars] ... alphabet, optional
     * @return {string}
     */
    static rndstr(len, chars) {
        let s = '';
        len = len || 32; // you are not going to make a 0 length random number, so no need to check type
        chars = chars || ALPHABET;
        let r = crypto.getRandomValues(new Uint32Array(Math.floor(len/4)));
        // ! yes, the operator % reduces randomness!
        while (len > 0) { s += chars.charAt((r[Math.ceil(len/4)-1] >> (len%4) & 255) % chars.length); len-- }
        return s;
    }

    /**
     * get an array with random bytes with the specified length
     *
     * @param {Number} len      if omitted len will be 32
     * @return {unknown[] | undefined}
     */
    static random(len) {
        return SafeBuffer.from(crypto.getRandomValues(new Uint8Array(len || 32)));
    }

    /**
     * generate a set of keypairs to use in
     * - sign/verify            spub, spriv
     * - secret key exchange    epub, epriv
     * - asymmetric encryption  apub, apriv
     *
     * keys will be serialized (to string) unless opt.raw = true
     *
     * @param {{ ecdsa: boolean, ecdh: boolean, rsa:boolean, raw: boolean }} opt
     * @return {Promise<{apub: *, epub: string, epriv: *, spriv: string, apriv: *, spub: string}>}
     */
    static async pair(opt) {
        opt  = { ecdsa: true, ecdh: true, rsa: true, raw: false, ...opt };
        let keys, pub, priv;

        // first ECDSA keys for signing/verifying
        let signingPair;
        if (opt.ecdsa) {
            keys = await CRYPTO.generateKey({ name: ECDSA, namedCurve: P256 }, true, ['sign', 'verify']);
            // pub is UTF8 but filename/URL safe (https://www.ietf.org/rfc/rfc3986.txt)
            // but split on a non-base64 letter.
            pub             = await CRYPTO.exportKey('jwk', keys.publicKey);
            // privateKey scope doesn't leak out from here!
            signingPair = {
                priv: (await CRYPTO.exportKey('jwk', keys.privateKey)).d,
                pub : pub.x + '.' + pub.y
            }
        }

        // now EDHC for shared secrets
        let dhPair;
        if (opt.ecdh) {
            keys   = await CRYPTO.generateKey({ name: ECDH, namedCurve: P256 }, true, ['deriveKey']);
            pub    = await CRYPTO.exportKey('jwk', keys.publicKey);
            dhPair = {
                priv: (await CRYPTO.exportKey('jwk', keys.privateKey)).d,
                pub : pub.x + '.' + pub.y
            }
        }

        // at last RSA-OAEP for async encryption
        let rsaPair;
        if (opt.rsa) {
            keys        = await CRYPTO.generateKey({ name: RSA, modulusLength: KEYLEN, publicExponent: PUBEXP, hash: SHA256 }, true, ['encrypt', 'decrypt']);
            pub         = (await CRYPTO.exportKey('jwk', keys.publicKey)).n;
            let kp = await CRYPTO.exportKey('jwk', keys.privateKey);
            priv = [kp.d, kp.dp, kp.dq, kp.n, kp.p, kp.q, kp.qi].join('.');
            rsaPair = { priv, pub };
        }

        // collect all pairs together
        const pairs = {
            spub : signingPair?.pub,
            spriv: signingPair?.priv,
            epub : dhPair?.pub,
            epriv: dhPair?.priv,
            apub : rsaPair?.pub,
            apriv: rsaPair?.priv
        }
        return pairs;
    }

    async serializePairs(pairs) {
        let serialized = {};
        if (!pairs) return;
        // ECDSA keys for signing/verifying
        if (pairs.spub && pairs.spriv) {

        }
        return serialized;
    }

    async restorePairs(serialized) {
        let pairs = {};
        if (!serialized) return;
        if (serialized.spub && serialized.spriv) {

        }
        return pairs;
    }

    /**
     * AES symmetric encrypt data
     *
     * @param {String | Object} data
     * @param pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param opt
     * @return {Promise<{ct: string, s: string, iv: string}>}   ct ... ciphertext, s ... salt, iv ... initialization vector
     */
    static async encrypt(data, pairsOrKey, opt) {
        opt = { name: AESGCM, encode: BASE64, raw:true, ...opt };
        const key = pairsOrKey.epriv || pairsOrKey;
        let msg = (typeof data == 'string') ? data : JSON.stringify(data);
        let salt = this.random(9);
        let iv = this.random(15);
        let ct = await CRYPTO.encrypt({ name: opt.name, iv: new Uint8Array(iv) },
                                      await aeskey(key, salt, opt), // Keeping the AES key scope as private as possible...
                                      ENCODE(msg));
        let encrypted = {
            ct: SafeBuffer.from(ct, 'binary').toString(opt.encode),
            iv: iv.toString(opt.encode),
            s: salt.toString(opt.encode)
        }
        if(!opt.raw) encrypted = 'SEA'+JSON.stringify(encrypted);
        return encrypted;
    }

    /**
     * AES symmetric decrypt a ciphertext
     *
     * @param data
     * @param pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param opt
     * @return {Promise<Object*>}
     */
    static async decrypt(data, pairsOrKey, opt) {
        opt = { name: AESGCM, encode: BASE64, ...opt };
        const key = pairsOrKey.epriv || pairsOrKey;
        let obj = parseSEA(data);
        let decrypted;
        try {
            let salt  = SafeBuffer.from(obj.s, opt.encode);
            let iv    = new Uint8Array(SafeBuffer.from(obj.iv, opt.encode));
            let ct    = new Uint8Array(SafeBuffer.from(obj.ct, opt.encode));
            decrypted = await CRYPTO.decrypt({
                                       name     : opt.name,
                                       iv       : iv,
                                       tagLength: 128
                                   },
                                   await aeskey(key, salt, opt), // Keeping aesKey scope as private as possible...
                                   ct);
        } catch (e) {
            if (UTF8 === opt.encode) throw "Could not decrypt";
            if (this.opt.fallback) {
                opt.encode = UTF8;
                return await this.decrypt(data, pairsOrKey, opt);
            }
        }
        let r = parseSEA(DECODE(decrypted));
        return r;
    }

    /**
     * derive a shared secret from another's public and my encryption keys (epub/epriv)
     * returns an AES key to be used for symmetric encryption/decryption
     * between me an the other.
     *
     * @param otherPubkey   other's the pub key
     * @param pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param {{ raw: boolean }} opt
     * @return {Promise<void>}
     */
    static async secret(otherPubkey, pairsOrKey, opt) {
        opt = { raw: false, ...opt};
    }

    /**
     *
     *
     *
     * @param data
     * @param pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param opt
     * @return {Promise<void>}
     */
    static async sign(data, pairsOrKey, opt) {

    }

    /**
     *
     *
     *
     * @param data
     * @param pairsOrKey     a set of key pairs or a (simplified JWK) key
     * @param opt
     * @return {Promise<void>}
     */
    static async verify(data, pairsOrKey, opt) {
    }

    /**
     * derive a key from an arbitrary input using PBKDF2 (Password-Based Key Derivation Function 2)
     * use for generating secrets from passwords
     * but also for PoW (proof of work) to slow down brute force attacks
     *
     * hint: if you'r going to store the key, also store the salt!
     *       otherwise you can't proof it again
     *
     * @param {Object | String} data
     * @param {String} salt
     * @param {{ name: string, encode: string, iterarions: int, hash: { name: string }, length: int }} opt
     * @return {Promise<String>}
     */
    static async work(data, salt, opt) {
        opt      = {
            name      : PBKDF2,
            encode    : BASE64,
            iterations: settings.PBKDF2.iter,
            hash      : settings.PBKDF2.hash,
            length    : (settings.PBKDF2.ks * 8)
            , ...opt
        };
        data     = (typeof data == 'string') ? data : JSON.stringify(data);
        salt     = salt || this.random(9);
        var key  = await CRYPTO.importKey('raw', ENCODE(data), { name: PBKDF2 }, false, ['deriveBits']);
        var work = await CRYPTO.deriveBits({
                                               name      : opt.name,
                                               iterations: opt.iterations,
                                               salt      : ENCODE(salt),
                                               hash      : opt.hash,
                                           }, key, opt.length)
        data     = this.random(data.length)  // Erase data in case of passphrase (enable garbage collection)
        var r    = SafeBuffer.from(work, 'binary').toString(opt.encode);
        return r;
    }

    /**
     * get a hash from an arbitrary input using SHA-256
     *
     * hint: if you'r going to store the hash, also store the salt!
     *       otherwise you can't proof it again
     *
     * @param {Object | String} data
     * @param {String} salt
     * @param {{ encode: string }} opt  defaults: encode='BASE64'
     * @return {Promise<String>}
     */
    static async hash(data, salt, opt) {
        opt   = { encode: BASE64, ...opt };
        data  = (typeof data == 'string') ? data : JSON.stringify(data);
        salt  = salt || this.random(9);
        let r = SafeBuffer.from(sha256hash(data + salt), 'binary').toString(opt.encode)
        return r;
    }

    /**
     * asymmetric encrypt with a public key.
     * can only be decrypted with the private key @see asymdecrypt()
     *
*
     * @param data              data to be encrypted
     * @param pairsOrPubkey     a set of key pairs or a (simplified JWK) public key
     * @param opt
     * @return {Promise<ArrayBuffer>}
     */
    static async encryptWithPub(data, pairsOrPubkey, opt) {
        const key = pairsOrPubkey.apub || pairsOrPubkey;
        let msg = (typeof data == 'string')? data : JSON.stringify(data);

        let encrypted = await CRYPTO.encrypt(
            { name: "RSA-OAEP" },
            await rsapubkey(key),
            ENCODE(data)
        );

        return encrypted;

    }

    /**
     * asymetric decrypt with a private key.
     * decrypts a ciphertext encrypted with the matching (simplified JWK) private key
     *
*
     * @param data
     * @param pairsOrPrivkey    a set of key pairs or a private key
     * @param opt
     * @return {Promise<string>}
     */
    static async decryptWithPriv(data, pairsOrPrivkey, opt) {
        const key     = pairsOrPrivkey.apriv || pairsOrPrivkey;
        let decrypted = await CRYPTO.decrypt(
            { name: "RSA-OAEP" },
            await rsaprivkey(key),
            data
        );

        return DECODE(decrypted);
    }

    /**
     * generate an arbitrary key for symetric (AES) encryption
     * to persist this key first export it or
     * serialize it simplified for SEA -> serialKey(), restoreKey()
     *
     * @return {Promise<CryptoKey>}
     */
    static async key() {
        return await aeskey(this.rndstr(32));
    }

    static async serialKey(aeskey) {

    }

    static async restoreKey(serialkey) {

    }
}
