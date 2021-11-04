/**
 * This is an ES6 refactoring of GUN/SEA
 * --> https://gun.eco/docs/SEA, https://github.com/amark/gun/tree/master/sea
 * extended with RSA asymetric encryption (encrypt with pub, decrypt with priv)
 *
 * Well RSA needs very long keys and long ciphertext, but RSA-OAEP is currently
 * the onyl supported algorithm for public key encryption.
 * omit with opt.rsa = false in pair()
 *
 * JWK Key serialisation is done simplified because the algorithms are known.
 * But algorithms can be corrupted or outdated in future. Then we need
 * to serialize full JWK.
 *
 * Hint:
 * - Consider using curve P-384 for ECDSA and ECDH and SHA-384 for hashes.
 * - Always use key length equal or larger than 3072 bit! (384 byte)
 * - this should be sufficient until post quantum cryptographic encryption methods are mature
 *
 * Differences:
 * - no callbacks, all methods async (Promise)
 * - crypto methods throws on error
 * - don't prefix with 'SEA'. this has to be done by the consumer if needed
 * - removed checks if data is already signed or encrypted. the consumer needs to know
 * - the keypair for signing is renamed: pub -> spub, priv -> spriv
 * - pair() adds a keypair for async encryption (RSA)
 * - no implicit key management (known keys in verify)
 * - work() split in to work() with PBKDF2 and hash() with SHA-256
 *
 * todo [OPEN]
 *  - use multiformats (self contained) for signed and encrypted data
 *  - add separate serialize/restore for persistent keys
 *  - introduce key management (known keys), but not implicit in crypto methods
 *  - in future the keys should be moved to a SE (secure element) or a 2FA device
 *  - add check methods if data is enrypted or signed
 *  - add certify (like a signature) and proof for software modules and packages
 *  - there may be a chain of certs for developers and certificants
 *
 *  @see
 *  - https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
 *  - https://github.com/diafygi/webcrypto-examples
 *  - https://gist.github.com/deiu/2c3208c89fbc91d23226
 *  - https://www.heise.de/news/US-Geheimdienst-NSA-nimmt-Stellung-zu-Post-Quanten-Kryptographie-6191190.html
 *
 */

import SafeBuffer from "./safebuffer.mjs";

import { CRYPTO_SETTINGS, parseSEA, aeskey, rsapubkey, rsaprivkey, sha256hash, ecdhpubkey, ecdhprivkey, ecdsapubkey, ecdsaprivkey, isSEA } from "./util.mjs"

// shorten
const ENCODE = (msg) => new TextEncoder().encode(msg);
const DECODE = (buf) => new TextDecoder('utf8').decode(buf);
const CRYPTO = crypto.subtle;   // shortcut

// literals
const AESGCM    = 'AES-GCM';             // symmetric encryption:    AES Galois/Counter Mode (Advanced Encryption Standard)
const RSA       = 'RSA-OAEP';            // asymmetric encryption:   RSA Optimal Asymmetric Encryption Padding (Rivest–Shamir–Adleman)
const ECDSA     = 'ECDSA';               // signing and verifying:   Elliptic Curve Digital Signature Algorithm, requires a named curve (P-256)
const ECDH      = 'ECDH';                // secret key exchange:     Elliptic Curve Diffie-Hellman, requires a named curve (P-256)
const P256      = 'P-256';               // named curve for ECDSA
const SHA256    = 'SHA-256';             // hash (HMAC) algorithm
const PBKDF2    = 'PBKDF2';              // derive key from seed:    Password-Based Key Derivation Function 2
const PUBEXP    = new Uint8Array([1, 0, 1]);
const KEYLEN    = 3072;
const BASE64    = 'base64';
const BASE64URL = 'base64url';
const UTF8      = 'utf8';
const ALPHABET  = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXZabcdefghijklmnopqrstuvwxyz';

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
     * @return {Promise<{apub: string, apriv: string, epub: string, epriv: string, spriv: string, spub: string}>}
     */
    static async pair(opt) {
        opt  = { ecdsa: true, ecdh: true, rsa: true, raw: false, ...opt };
        let keys, pub, priv;
        let pairs = {};

        // first ECDSA keys for signing/verifying
        let signingPair;
        if (opt.ecdsa) {
            keys = await CRYPTO.generateKey({ name: ECDSA, namedCurve: P256 }, true, ['sign', 'verify']);
            // pub is UTF8 but filename/URL safe (https://www.ietf.org/rfc/rfc3986.txt)
            // but split on a non-base64 letter.
            pub  = await CRYPTO.exportKey('jwk', keys.publicKey);
            priv = await CRYPTO.exportKey('jwk', keys.privateKey);
            // privateKey scope doesn't leak out from here!
            pairs = { ...pairs,
                spriv: priv.d,
                spub : pub.x + '.' + pub.y
            }
        }

        // now EDHC for shared secrets
        let dhPair;
        if (opt.ecdh) {
            keys   = await CRYPTO.generateKey({ name: ECDH, namedCurve: P256 }, true, ['deriveKey']);
            pub    = await CRYPTO.exportKey('jwk', keys.publicKey);
            priv   = await CRYPTO.exportKey('jwk', keys.privateKey);
            pairs = { ...pairs,
                epriv: priv.d,
                epub : pub.x + '.' + pub.y
            }
        }

        // at last RSA for async encryption
        let rsaPair;
        if (opt.rsa) {
            keys    = await CRYPTO.generateKey({ name: RSA, modulusLength: KEYLEN, publicExponent: PUBEXP, hash: SHA256 }, true, ['encrypt', 'decrypt']);
            pub     = await CRYPTO.exportKey('jwk', keys.publicKey);
            priv    = await CRYPTO.exportKey('jwk', keys.privateKey);
            pairs = { ...pairs,
                apriv: [priv.d, priv.dp, priv.dq, priv.n, priv.p, priv.q, priv.qi].join('.'),
                apub : pub.n
            };
        }

        return pairs;
    }

    static async serializePairs(pairs) {
        const serialized = {};
        if (!pairs) return;
        // ECDSA keys for signing/verifying
        if (pairs.spub && pairs.spriv) {

        }
        // ECDH keys for secret key derivation
        if (pairs.epub && pairs.epriv) {

        }
        // RSA keys for asymmetric encryption
        if (pairs.apub && pairs.apriv) {

        }
        return serialized;
    }

    static async restorePairs(serialized) {
        const pairs = {};
        if (!serialized) return;
        // ECDSA keys for signing/verifying
        if (serialized.spub && serialized.spriv) {

        }
        // ECDH keys for secret key derivation
        if (serialized.epub && serialized.epriv) {

        }
        // RSA keys for asymmetric encryption
        if (serialized.apub && serialized.apriv) {

        }
        return pairs;
    }

    /**
     * transform iv to string
     *
     * @param iv
     * @param {{name: string, encode: string, raw: boolean}} opt
     * @return {String}
     */
    static ivString(iv, opt) {
        opt = { encode: BASE64, ...opt };
        return iv.toString(opt.encode);
    }

    /**
     * AES symmetric encrypt data
     *
     * @param {String | Object} data
     * @param pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param {{name: string, encode: string, raw: boolean, salt: string, iv: string}} opt
     * @return {Promise<{ct: string, s: string, iv: string}>}   ct ... ciphertext, s ... salt, iv ... initialization vector
     */
    static async encrypt(data, pairsOrKey, opt) {
        opt = { name: AESGCM, encode: BASE64, raw: true, ...opt };
        if (data == undefined) throw "can't encrypt 'undefined'";
        const key  = pairsOrKey.epriv || pairsOrKey;
        const msg  = (typeof data == 'string') ? data : JSON.stringify(data);
        const salt = opt.salt || this.rndstr(9);    // if supplied use the salt
        const iv   = opt.iv ? SafeBuffer.from(opt.iv, opt.encode) : this.random(15);
        const ct   = await CRYPTO.encrypt({ name: opt.name, iv: new Uint8Array(iv) },
                                      await aeskey(key, salt, opt), // Keeping the AES key scope as private as possible...
                                      ENCODE(msg));
        let encrypted = {
            ct: SafeBuffer.from(ct, 'binary').toString(opt.encode),
            iv: iv.toString(opt.encode),
            s: salt
        }
        if(!opt.raw) encrypted = JSON.stringify(encrypted);
        return encrypted;
    }

    /**
     * AES symmetric decrypt a ciphertext
     *
     * @param {String | Object} data
     * @param {CryptoKey | { spub: string ,spriv: string } | String} pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param {{name: string, encode: string, raw: boolean}}opt
     * @return {Promise<Object*>}
     */
    static async decrypt(data, pairsOrKey, opt) {
        opt = { name: AESGCM, encode: BASE64, ...opt };
        if (data == undefined) throw "can't decrypt 'undefined'";
        const key = pairsOrKey.epriv || pairsOrKey;
        let obj = parseSEA(data);
        let decrypted;
        try {
            const salt  = obj.s; // SafeBuffer.from(obj.s, opt.encode);
            const iv    = new Uint8Array(SafeBuffer.from(obj.iv, opt.encode));
            const ct    = new Uint8Array(SafeBuffer.from(obj.ct, opt.encode));
            decrypted   = await CRYPTO.decrypt({
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
        const r = parseSEA(DECODE(decrypted));
        return r;
    }

    /**
     * derive a shared secret from another's public and my encryption keys (epub/epriv)
     * returns an AES key to be used for symmetric encryption/decryption
     * between me an the other.
     *
     * @param {CryptoKey | { spub: string ,spriv: string } | String} otherPubkey   other's the pub key
     * @param {CryptoKey | { spub: string ,spriv: string }} pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param {{ raw: boolean }} opt
     * @return {Promise<String | CryptoKey>}
     */
    static async secret(otherPubkey, pairsOrKey, opt) {
        opt               = { raw: false, ...opt };
        const opub        = otherPubkey.epub || otherPubkey;
        const epub        = pairsOrKey.epub || pairsOrKey;
        const epriv       = pairsOrKey.epriv;
        const pubKey      = await ecdhpubkey(opub);
        const privKey     = await ecdhprivkey(epub, epriv);
        const derivedBits = await CRYPTO.deriveBits({
                                                        name      : ECDH,
                                                        namedCurve: P256,
                                                        public    : pubKey
                                                    }, privKey, 256);
        const derivedKey  = await CRYPTO.importKey('raw', new Uint8Array(derivedBits), {
            name  : 'AES-GCM',
            length: 256
        }, true, ['encrypt', 'decrypt']);
        const secret = opt.raw
                        ? derivedKey
                        : (await CRYPTO.exportKey('jwk', derivedKey)).k;
        return secret;
    }

    /**
     * sign provided data
     *
     *
     * @param {Object | String} data
     * @param {CryptoKey | { spub: string ,spriv: string }} pairsOrKey    a set of key pairs or a (simplified JWK) key
     * @param {{ raw: boolean, encode: string }} opt
     * @return {Promise<{}>}
     */
    static async sign(data, pairsOrKey, opt) {
        opt = { raw: false, encode: BASE64, ...opt };
        if (data == undefined) throw "can't sign 'undefined'";
        const signed = await CRYPTO.sign({ name: ECDSA, hash: { name: SHA256 }}, await ecdsaprivkey(pairsOrKey), new Uint8Array(sha256hash(data)));
        let r = { m: data, s: SafeBuffer.from(signed, 'binary').toString(opt.encode)};
        return r;
    }

    /**
     *
     *
     *
     * @param {Object | String} data
     * @param {CryptoKey | { spub: string ,spriv: string } | String} pairsOrKey     a set of key pairs or a (simplified JWK) key
     * @param {{ raw: boolean, encode: string }} opt
     * @return {Promise<Object | undefined>} if 'undefined' the signature could not be verified, otherwise the plain data
     */
    static async verify(data, pairsOrKey, opt) {
        opt = { raw: false, encode: BASE64, ...opt };
        if (data == undefined) throw "can't verify 'undefined'";
        const msg  = (typeof data == 'string') ? JSON.parse(data) : data;
        const pub = pairsOrKey.spub || pairsOrKey;
        const signature = SafeBuffer.from(data.s,opt.encode);
        const verified = await CRYPTO.verify({ name: ECDSA, hash: { name: SHA256 }}, await ecdsapubkey(pub), new Uint8Array(signature), new Uint8Array(sha256hash(data.m)));
        let r = verified ? data.m : undefined;
        return r;
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
     * @param {String} salt    if omitted, a random salt will be added
     * @param {{ name: string, encode: string, iterations: int, hash: { name: string }, length: int }} opt
     * @return {Promise<String>} work result (hash) to be used as PoW (proof of work)
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
        if (data == undefined) throw "can't work 'undefined'";
        data       = (typeof data == 'string') ? data : JSON.stringify(data);
        salt       = salt || this.random(9);
        const key  = await CRYPTO.importKey('raw', ENCODE(data), { name: PBKDF2 }, false, ['deriveBits']);
        const work = await CRYPTO.deriveBits({
                                               name      : opt.name,
                                               iterations: opt.iterations,
                                               salt      : ENCODE(salt),
                                               hash      : opt.hash,
                                           }, key, opt.length)
        data     = this.random(data.length)  // Erase data in case of passphrase (enable garbage collection)
        const r    = SafeBuffer.from(work, 'binary').toString(opt.encode);
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
        opt        = { encode: BASE64, ...opt };
        if (data == undefined) throw "can't hash 'undefined'";
        data       = (typeof data == 'string') ? data : JSON.stringify(data);
        salt       = salt || this.random(9);
        const hash = await sha256hash(data + salt);
        const r    = SafeBuffer.from(hash, 'binary').toString(opt.encode)
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
    static async encryptPub(data, pairsOrPubkey, opt) {
        opt = { raw: false, encode: BASE64, ...opt };
        const key = pairsOrPubkey.apub || pairsOrPubkey;
        if (data == undefined) throw "can't pub encrypt 'undefined'";
        const msg = (typeof data == 'string') ? data : JSON.stringify(data);

        let encrypted = await CRYPTO.encrypt(
            { name: "RSA-OAEP" },
            await rsapubkey(key),
            ENCODE(msg)
        );
        const r = opt.raw ? encrypted : SafeBuffer.from(encrypted, 'binary').toString(opt.encode);
        return r;

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
    static async decryptPriv(data, pairsOrPrivkey, opt) {
        opt = { raw: false, encode: BASE64, ...opt };
        if (data == undefined) throw "can't priv decrypt 'undefined'";
        const key       = pairsOrPrivkey.apriv || pairsOrPrivkey;
        data = opt.raw ? data : new Uint8Array(SafeBuffer.from(data, opt.encode));
        const decrypted = await CRYPTO.decrypt(
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
