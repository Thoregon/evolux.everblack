/**
 *
 *
 */

import Base64url  from "/evolux.util/lib/base64url.mjs";

// This is Buffer implementation used in SEA. Functionality is mostly
// compatible with NodeJS 'safe-buffer' and is used for encoding conversions
// between binary and 'hex' | 'utf8' | 'base64'
// See documentation and validation for safe implementation in:
// https://github.com/feross/safe-buffer#update

class SeaArray extends Array {

    toString(enc, start, end) {
        enc          = enc || 'utf8';
        start        = start || 0;
        const length = this.length
        if (enc === 'hex') {
            const buf = new Uint8Array(this)
            return [...Array(((end && (end + 1)) || length) - start).keys()]
                .map((i) => buf[i + start].toString(16).padStart(2, '0')).join('')
        }
        if (enc === 'utf8') {
            return Array.from(
                { length: (end || length) - start },
                (_, i) => String.fromCharCode(this[i + start])
            ).join('')
        }
        if (enc === 'base64') {
            return btoa(this)
        }
        if (enc === 'base64url') {
            return Base64url.encode(this.toString('utf8'));
        }
    }
}

export default class SafeBuffer extends SeaArray {

    constructor(props) {
        super(props);
        console.warn('new SafeBuffer() is depreciated, please use SafeBuffer.from()')
    }

    static from(input, enc) {
        let buf
        if (typeof input === 'string') {
            enc = enc || 'utf8'
            if (enc === 'hex') {
                const bytes = input.match(/([\da-fA-F]{2})/g)
                                   .map((byte) => parseInt(byte, 16))
                if (!bytes || !bytes.length) {
                    throw new TypeError('Invalid first argument for type \'hex\'.')
                }
                buf = SeaArray.from(bytes)
            } else if (enc === 'utf8') {
                const length = input.length
                const words = new Uint16Array(length)
                Array.from({ length: length }, (_, i) => words[i] = input.charCodeAt(i))
                buf = SeaArray.from(words)
            } else if (enc === 'base64') {
                const dec = atob(input)
                const length = dec.length
                const bytes = new Uint8Array(length)
                Array.from({ length: length }, (_, i) => bytes[i] = dec.charCodeAt(i))
                buf = SeaArray.from(bytes)
            } else if (enc === 'base64url') {
                const dec = Base64url.decode(input);
                const length = dec.length
                const bytes = new Uint8Array(length)
                Array.from({ length: length }, (_, i) => bytes[i] = dec.charCodeAt(i))
                buf = SeaArray.from(bytes)
            } else if (enc === 'binary') {
                buf = SeaArray.from(input)
            } else {
                console.info('SafeBuffer.from unknown encoding: '+enc)
            }
            return buf
        }
        const byteLength = input.byteLength // what is going on here? FOR MARTTI
        const length = input.byteLength ? input.byteLength : input.length
        if (length) {
            let buf
            if (input instanceof ArrayBuffer) {
                buf = new Uint8Array(input)
            }
            return SeaArray.from(buf || input)
        }
    }

    /** This is 'safe-buffer.alloc' sans encoding support
     *
     * @param length
     * @param fill
     * @return {*}
     */
    static alloc(length, fill = 0 /*, enc*/ ) {
        return SeaArray.from(new Uint8Array(Array.from({ length: length }, () => fill)))
    }

    /** This is normal UNSAFE 'buffer.alloc' or 'new Buffer(length)' - don't use!
     *
     * @param length
     * @return {*}
     */
    static allocUnsafe(length) {
        return SeaArray.from(new Uint8Array(Array.from({ length : length })))
    }

    /** This puts together array of array like members
     *
     * @param arr
     * @return {*}
     */
    static concat(arr) { // octet array
        if (!Array.isArray(arr)) {
            throw new TypeError('First argument must be Array containing ArrayBuffer or Uint8Array instances.')
        }
        return SeaArray.from(arr.reduce((ret, item) => ret.concat(Array.from(item)), []))
    }

}
