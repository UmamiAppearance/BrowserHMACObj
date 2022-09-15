/**
 * [BrowserHMACObj]{@link https://github.com/UmamiAppearance/BrowserHMACObj}
 *
 * @version 0.1.0
 * @author UmamiAppearance [mail@umamiappearance.eu]
 * @license GPL-3.0
 */

import { cryptoSubtle, getDigestModFromParam, PermissionError } from "./helpers.js";
import { BaseEx } from "../node_modules/base-ex/src/base-ex.js";

const DIGESTMODS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
const BASE_EX = new BaseEx();
const KEY_FORMATS = ["raw", "jwk"];


/**
 * Creates a HMAC-SHA-(1-512) object for the browser.
 * It is very closely related to pythons hmac library
 * in its methods and features but with many extras.
 * 
 * It provides an easy access to the browsers Crypto.subtle
 * method, and also makes it possible to get multiple
 * different digest methods.
 * 
 * @see: https://docs.python.org/3/library/hmac.html
 */
export default class BrowserHMACObj {

    #bits = null;
    #digest = null;
    #digestmod = null;
    #input = [];
    #key = null;
    #keyFormats = this.constructor.keyFormats();
    #keyIsExportable = null;


    /**
     * Creates a HMAC Object.
     * @param {string|number} digestmod - The parameter must contain one of the numbers (1/256/384/512), eg: SHA-1, sha256, 384, ... 
     */
    constructor(digestmod) {
        [ this.#digestmod, this.#bits ] = getDigestModFromParam(digestmod, DIGESTMODS);
        this.#addConverters();
    }


    /**
     * Static method to receive information about the 
     * available digestmod.
     * @returns {set} - A set of available digestmod.
     */
    static digestmodsAvailable() {
        return new Set(DIGESTMODS);
    }


    /**
     * Static method to receive information about the
     * available key formats.
     * @returns {set} - A set of available key formats.
     */
    static keyFormats() {
        return new Set(KEY_FORMATS);
    }


    /**
     * Static method to generate a crypto key for the HMAC algorithm.
     * @param {string|number} digestmod - The parameter must contain one of the numbers (1/256/384/512), eg: SHA-1, sha256, 384, ...
     * @param {boolean} [permitExports=false] - If true the key can get exported. 
     * @returns {Object} - Crypto Key.
     */
    static async generateKey(digestmod="", permitExports=false) {
        digestmod = getDigestModFromParam(digestmod, DIGESTMODS).at(0);
        return await cryptoSubtle.generateKey(digestmod, permitExports);
    }


    /**
     * Return a === b. This function uses an approach designed
     * to prevent timing analysis by avoiding content-based
     * short circuiting behavior, making it appropriate for
     * cryptography.
     * a and b (or more precisely their byte representation)
     * must both be of the same type.
     * @param {*} a 
     * @param {*} b 
     * @returns 
     */
    static compareDigest(a, b) {

        if (typeof a === "undefined" || typeof b === "undefined") {
            throw new Error("BrowserSHAobj.compareDigest takes exactly two positional arguments.");
        }

        a = BASE_EX.byteConverter.encode(a, "uint8");
        b = BASE_EX.byteConverter.encode(b, "uint8");

        // set the greater array as 'A'
        let A, B; 
        if (a.byteLength > b.byteLength) {
            A = a;
            B = b;
        } else {
            A = b;
            B = a;
        }

        // Walk through the greater (or equally sized) array and
        // compare each value with the value at the corresponding
        // index. (If B is smaller it will return undefined at a
        // certain point).
        const test = A.map((byte, i) => {
            return byte === B.at(i);
        });

        // Only if every value is true the result of the 
        // reduced array will be 1. If one value is false
        // the result will be zero.
        const passed = Boolean(test.reduce((x, y) => x*y));
        
        return passed;
    }


    /**
     * Asynchronously creates a new instance. In contrast
     * to the regular new operator a message and key can 
     * be provided. If a message is set a key must also be
     * handed over or a crypto key gets generated automatically.
     * A message gets passed to the 'update' method.
     * 
     * @param {*} key - Almost any input can be provided. It gets converted to bytes and used for the crypto key generation.
     * @param {*} msg - Input gets converted to bytes and processed by window.crypto.subtle.digest.
     * @param {string|number} digestmod - The parameter must contain one of the numbers (1/256/384/512), eg: SHA-1, sha256, 384, ... 
     * @param {string} [keyFormat="raw"] - As defined by KEY_FORMATS. If not set to raw, 'key' must match the format.
     * @param {boolean} [permitExports=false] - If a key is getting generated, this bool sets it to exportable or not.
     * @returns {Object} - A HMACObj instance.
     */
    static async new(key=null, msg=null, digestmod="", keyFormat="raw", permitExports=false) {
        
        const hmacObj = new this(digestmod);

        if (key) {
            if (keyFormat === "object") {
                await hmacObj.setKey(key);
            } else {
                await hmacObj.importKey(key, keyFormat, permitExports);
            }
        }

        if (msg !== null) {
            if (!key) {
                await hmacObj.generateKey();
                console.warn("A message but no key was provided. The key was generated for you.");
            }
            await hmacObj.update(msg);
        }
        return hmacObj;
    }


    /**
     * The size of the resulting hash in bytes.
     */
    get digestSize() {
        return this.#bits / 8;
    }


    /**
     * The internal block size of the hash algorithm in bytes.
     */
    get blockSize() {
        return this.#bits > 256 ? 128 : 64;
    }


    /**
     * The canonical name of this HMAC, always uppercase,
     * e.g. HMAC-SHA-256.
     */
    get name() {
        return "HMAC-" + this.#digestmod;
    }


    /**
     * Shortcut to the BaseEy byte converter.
     * @param {*} input - Almost any input.
     * @returns {Object} - Uint8Array/Byte representation of the input.
     */
    #ensureBytes(input) {
        return BASE_EX.byteConverter.encode(input, "bytes");
    } 


    /**
     * Test wether the provided format matches the
     * predetermined formats.
     */
    #testFormat(format) {
        if (!this.#keyFormats.has(format)) { 
            throw new TypeError(
                `Invalid key format '${format}'\n\nValid formats are: ${KEY_FORMATS.join(", ")}`
            );
        }
    }


    /**
     * Test wether a key is assigned to the current instance.
     */
    #testKeyAvail() {
        if (this.#key === null) {
            throw new Error("No key is assigned yet. Import or generate key.");
        }
    }


    /**
     * Convert buffer to many different representations.
     * (Helper for method 'sign')
     * @param {ArrayBuffer} buffer - ArrayBuffer.
     * @param {string} base - Base Representation as required by BaseEx.
     * @returns {string} - Base Representation.
     */
    #bufferToBase(buffer, base) {
        const decapitalize = str => str.charAt(0).toLowerCase().concat(str.slice(1));
        const errMsg = "Invalid base conversion keyword.";
        base = decapitalize(base.replace(/^to/, ""));
        
        if (base === "hex" || base == "hexdigest") {
            base = "base16";
        }

        else if (base === "bytes") {
            base = "byteConverter";
        }

        else if ((/SimpleBase/i).test(base)) {
            base = `base${[].concat(String(base).match(/[0-9]+/)).at(0)|0}`;
            if (!(base in BASE_EX.simpleBase)) {
                throw new TypeError(errMsg);
            }
            return BASE_EX.simpleBase[base].encode(buffer); 
        }
        
        if (!(base in BASE_EX)) {
            throw new TypeError(errMsg);
        }

        return BASE_EX[base].encode(buffer);
    }


    /**
     * Update the HMAC object with almost any input. The input
     * gets converted to a Uint8Array. Unless 'replace' is set
     * to true, repeated calls are equivalent to a single call
     * with the concatenation of all the arguments:
     * hmacObj.update(a); hmacObj.update(b) is in many occasions
     * equivalent to hmacObj.update(a+b).
     * 
     * (Note: The process is a concatenation of bytes. Take as
     * an exception for instance:
     * hmacObj.update(1); hmacObj.update(2) which is not the same
     * as hmacObj.update(1+2))
     * 
     * @param {*} msg - Input gets converted to bytes and processed by window.crypto.subtle.digest. 
     * @param {boolean} replace - If true, the input is not concatenated with former input.
     */
    async update(msg, replace=false) {
        msg = this.#ensureBytes(msg);
        
        this.#testKeyAvail();
        
        if (replace) {
            this.#input = Array.from(msg);
        } else {
            this.#input = this.#input.concat(Array.from(msg));
        }
        
        this.#digest = await cryptoSubtle.sign(
            Uint8Array.from(this.#input),
            this.#key
        );
    }


    /**
     * Shortcut to 'update(input, true)'.
     * @param {*} msg - Input gets converted to bytes and processed by window.crypto.subtle.digest. 
     */
    async replace(msg) {
        await this.update(msg, true);
    }


    /**
     * Method to replace the assigned Crypto Key.
     * @param {Object} keyObj - The new Crypto Key. 
     */
    async setKey(keyObj) {
        this.#key = keyObj;

        if (this.#input.length) {
            console.warn("A new crypto key was established. A fresh digest is now getting calculated.");
            this.#digest = await cryptoSubtle.sign(
                Uint8Array.from(this.#input),
                this.#key
            );
        }
    }


    /**
     * Import a Crypto Key from almost any input or
     * a pre existing key.
     * @param {*} key - Almost any input can be provided. It gets converted to bytes and used for the crypto key generation.
     * @param {string} [format="raw"] - As defined by KEY_FORMATS. If not set to raw, 'key' must match the format.
     * @param {boolean} [permitExports=false] - This bool sets the generated key to exportable or not.
     */
    async importKey(key, format="raw", permitExports=false) {
        
        if (format === "raw") {
            key = this.#ensureBytes(key);
            
            if (key.byteLength < this.blockSize) {
                console.warn(`Your provided key-length is '${key.length}'.\n\nThis is less than blocksize of ${this.blockSize} used by ${this.#digestmod}.\nIt will work, but this is not secure.`);
            }
        } else {
            this.#testFormat(format);
        }
        this.#keyIsExportable = permitExports;
        
        const keyObj = await cryptoSubtle.importKey(key, this.#digestmod, format, permitExports);
        await this.setKey(keyObj);

    }


    /**
     * Method to apply a auto generated Crypto Key
     * to the instance.
     * @param {boolean} [permitExports=true] - This bool sets the generated key to exportable or not.
     */
    async generateKey(permitExports=true) {
        this.#keyIsExportable = Boolean(permitExports);
        const keyObj = await cryptoSubtle.generateKey(this.#digestmod, this.#keyIsExportable);
        await this.setKey(keyObj);
    }


    /**
     * Exports the Crypto Key assigned to the instance,
     * if it is a exportable key.
     * @param {string} [format="raw"] - As defined by KEY_FORMATS.
     * @returns {Object} - Crypto Key
     */
    async exportKey(format="raw") {
        
        this.#testFormat(format);
        
        if (this.#key === null) {
            throw new Error("Key is unset.");
        }
        
        if (!this.#keyIsExportable) {
            throw new PermissionError("Key exports are not allowed. You have to permit this before key-generation.");
        }
        
        const key = await cryptoSubtle.exportKey(this.#key, format);
        return key;
    }


    /**
     * Return a copy (“clone”) of the hmac object. This can be used
     * to efficiently compute the digests of strings that share a
     * common initial substring.
     * @returns {Object} - BrowserHMACObject instance.
     */
    async copy() {
        return await this.constructor.new(
            this.#key,
            this.#input.length ? Uint8Array.from(this.#input) : null,
            this.#digestmod,
            "object",
            this.#keyIsExportable
        );
    }


    /**
     * Signs a single message independent from the current
     * instance message.
     * @param {*} msg - Input gets converted to bytes and processed by window.crypto.subtle.digest.
     * @param {*} [base=null] - Optional Base Representation as required by BaseEx.
     * @returns {ArrayBuffer|string} - ArrayBuffer or a representation of the signed message.
     */
    async sign(msg, base=null) {
        this.#testKeyAvail();
        
        msg = this.#ensureBytes(msg);
        const buffer = await cryptoSubtle.sign(msg, this.#key);
        
        if (base !== null) {
            return this.#bufferToBase(buffer, base);
        }
        
        return buffer;
    }


    /**
     * A given message and signature can be tested 
     * if it is signed with the help of the instance
     * crypto key.
     * @param {*} msg - Message.
     * @param {ArrayBuffer} signature - Signature as ArrayBuffer. 
     * @returns {boolean} - Verification result.
     */
    async verify(msg, signature) { 
        msg = this.#ensureBytes(msg);
        this.#testKeyAvail();

        if (this.signature === null) {
            throw new TypeError("Signature must be provided");
        }
        const isValid = await cryptoSubtle.verify(msg, signature, this.#key);
        return isValid;
    }


    /**
     * Returns the current digest as an ArrayBuffer;
     * @returns {ArrayBuffer}
     */
    digest() {
        return this.#digest;
    }

    
    /**
     * Appends BaseEx encoders to the returned object for the ability
     * to covert the byte array of a hash to many representations.
     */
    #addConverters() {
        
        const detach = (arr, str) => arr.splice(arr.indexOf(str), 1);
        const capitalize = str => str.charAt(0).toUpperCase().concat(str.slice(1));

        this.hexdigest = () => this.#digest
            ? BASE_EX.base16.encode(this.#digest)
            : null;
        
        const converters = Object.keys(BASE_EX);
        this.basedigest = {
            toSimpleBase: {}
        };

        detach(converters, "base1");
        detach(converters, "byteConverter");
        detach(converters, "simpleBase");

        for (const converter of converters) {
            this.basedigest[`to${capitalize(converter)}`] = () => this.#digest 
                ? BASE_EX[converter].encode(this.#digest)
                : null;
        }

        for (const converter in BASE_EX.simpleBase) {
            this.basedigest.toSimpleBase[capitalize(converter)] = () => this.#digest
                ? BASE_EX.simpleBase[converter].encode(this.#digest)
                : null;
        }

        this.basedigest.toBytes = () => this.#digest
            ? BASE_EX.byteConverter.encode(this.#digest)
            : null;
    }

}
