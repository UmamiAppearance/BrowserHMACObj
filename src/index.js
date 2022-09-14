import { cryptoSubtle, getDigestModFromParam, PermissionError } from "./helpers.js";
import { BaseEx } from "../node_modules/base-ex/src/base-ex.js";


const DIGESTMODS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
const BASE_EX = new BaseEx();
const KEY_FORMATS = ["raw", "jwk"];


class BrowserHMACObj {
    #bits = null;
    #digest = null;
    #digestmod = null;
    #input = [];
    #key = null;
    #keyFormats = this.constructor.keyFormats();
    #keyIsExportable = null;

    constructor(digestmod="") {
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

    static keyFormats() {
        return new Set(KEY_FORMATS);
    }

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
     * Asynchronously creates a new instance.
     * Additionally key and input can be provided, which 
     * gets passed to the 'update' method.
     * @param {string|number} algorithm - The parameter must contain one of the numbers (1/256/384/512), eg: SHA-1, sha256, 384, ... 
     * @param {*} input - Input gets converted to bytes and processed by window.crypto.subtle.digest. 
     * @returns {Object} - A SHAObj instance.
     */
    static async new(key=null, msg=null, digestmod="", keyFormat="raw", permitExports=false) {
        
        const hmacObj = new this(digestmod);

        if (key) {
            if (keyFormat === "object") {
                hmacObj.setKey(key);
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

    get blockSize() {
        return this.#bits > 256 ? 128 : 64;
    }


    /**
     * The canonical name of this hash, always uppercase and
     * always suitable as a parameter to create another hash
     * of this type.
     */
    get name() {
        return "HMAC-" + this.#digestmod;
    }

    #ensureBytes(input) {
        return BASE_EX.byteConverter.encode(input, "bytes");
    } 

    #testFormat(format) {
        if (!this.#keyFormats.has(format)) { 
            throw new TypeError(
                `Invalid key format '${format}'\n\nValid formats are: ${KEY_FORMATS.join(", ")}`
            );
        }
    }

    #testKeyAvail() {
        if (this.#key === null) {
            throw new Error("No key is assigned yet. Import or generate key.");
        }
    }

    async update(input, replace=false) {
        input = this.#ensureBytes(input);
        
        this.#testKeyAvail();
        
        if (replace) {
            this.#input = Array.from(input);
        } else {
            this.#input = this.#input.concat(Array.from(input));
        }
        
        this.#digest = await cryptoSubtle.sign(
            Uint8Array.from(this.#input),
            this.#key
        );
    }

    /**
     * Shortcut to 'update(input, true)'.
     * @param {*} input - Input gets converted to bytes and processed by window.crypto.subtle.digest. 
     */
    async replace(input) {
        await this.update(input, true);
    }

    setKey(keyObj) {
        this.#key = keyObj;
        this.#digest = null;
    }

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
        this.setKey(keyObj);

    }

    static async generateKey(digestmod="", permitExports=false) {
        digestmod = getDigestModFromParam(digestmod, DIGESTMODS).at(0);
        return await cryptoSubtle.generateKey(digestmod, permitExports);
    }

    async generateKey(permitExports=true) {
        this.#keyIsExportable = Boolean(permitExports);
        const keyObj = await cryptoSubtle.generateKey(this.#digestmod, this.#keyIsExportable);
        this.setKey(keyObj);
    }

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
     * Returns the current digest as an ArrayBuffer;
     * @returns {ArrayBuffer}
     */
    digest() {
        return this.#digest;
    }

    async sign(msg, base=null) {
        this.#testKeyAvail();
        
        msg = this.#ensureBytes(msg);
        const buffer = await cryptoSubtle.sign(msg, this.#key);
        
        if (base !== null) {
            return this.#convert(buffer, base);
        }
        
        return buffer;
    }

    async verify(msg, signature) { 
        msg = this.#ensureBytes(msg);
        this.#testKeyAvail();

        if (this.signature === null) {
            throw new TypeError("Signature must be provided");
        }
        const isValid = await cryptoSubtle.verify(msg, signature, this.#key);
        return isValid;
    }

    #convert(buffer, base) {
        const decapitalize = str => str.charAt(0).toLowerCase().concat(str.slice(1));    
        const keywordError = () => {
            throw new TypeError("Invalid base conversion keyword.");
        };
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
                keywordError();
            }
            return BASE_EX.simpleBase[base].encode(buffer); 
        }
        

        if (!(base in BASE_EX)) {
            keywordError();
        }

        return BASE_EX[base].encode(buffer);
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

export {
    BrowserHMACObj as default,
    BASE_EX as baseEx
};
