import { BaseEx } from "../lib/BaseEx/src/BaseEx.js";

class HMACObj {
    constructor(algorithm="SHA-256") {
        const algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

        // simplify the input for the user - sha1, Sha-256...
        // everything is fine, even 384 by itself, as long
        // as the numbers match to the provided algorithms
        const version = String(algorithm).match(/[0-9]+/)[0];
        algorithm = `SHA-${version}`;
        if (!algorithms.includes(algorithm)) {
            throw new Error(`Invalid algorithm.\nValid arguments are: "${algorithms.join(", ")}".`);
        }

        // set the block-size (64 for SHA-1 & SHA-256 / 128 for SHA-384 & SHA-512)
        this.blockSize = (parseInt(version, 10) < 384) ? 64 : 128;

        // set other class-variables
        this.algorithm = algorithm;
        this.key = null;
        this.keyIsExportable = false;
        this.signature = null;
    }

    convertInput(key, type) {
        let msgEnc;
        
        if (type == "buffer") {
            msgEnc = key;
        } else {
            // convert input to string 
            key = String(key);

            // convert to ArrayBuffer from the given type
            if (type === "str") {
                msgEnc = new TextEncoder().encode(key);
            } else if (type === "hex") {
                msgEnc = this.converters.base16(key);
            } else if (type === "base32") {
                msgEnc = this.converters.base32_rfc4648.decode(key);
            } else if (type === "base64") {
                msgEnc = this.converters.base64.decode(key);
            } else {
                throw new TypeError("Unknown input type.")
            }
        }
        
        return msgEnc;
    }

    setKey(keyObj) {
        this.key = keyObj;
        this.signature = null;      // reset signature
    }

    async importKey(key, type="str", allowExports=false) {
        const classObj = this;
        const keyEnc = this.convertInput(key, type);
        if (keyEnc.length < this.blockSize) {
            const message = `WARNING: Your provided key-length is ${keyEnc.length}.\n\nThis is less than blocksize of ${this.blockSize} used by ${this.algorithm}.\nIt will work, but this is not secure.`
            this.warnUser(message);
        }
        this.keyIsExportable = allowExports;
        
        crypto.subtle.importKey(
            "raw",
            keyEnc,
            {
                name: "HMAC",
                hash: {name: this.algorithm}
            },
            allowExports,
            ["sign", "verify"]
        ).then(
            keyObj => classObj.setKey(keyObj)
        );
    }

    async generateKey(allowExports=false) {
        const classObj = this;
        this.keyIsExportable = allowExports;

        window.crypto.subtle.generateKey(
            {
              name: "HMAC",
              hash: {name: this.algorithm}
            },
            allowExports,
            ["sign", "verify"]
        ).then(
            keyObj => classObj.setKey(keyObj)
        );
    }

    async exportKey() {
        if (this.key === null) {
            throw Error("Key is unset.");
        }
        if (!this.keyIsExportable) {
            throw Error("Key exports are not permitted. You have to allow this before key-generation.");
        }
        const keyBuffer = await window.crypto.subtle.exportKey("raw", this.key);
        const keyObj = {
            array: Array.from(new Uint8Array(keyBuffer))
        }
        return this.appendObjConversions(keyObj);
    }

    async sign(data, type="str") {
        const dataEnc = this.convertInput(data, type);
        if (this.key === null) {
            throw new Error('No key is assigned yet. Import or generate a key.');
        } 
        window.crypto.subtle.sign(
            {
                name: "HMAC",
                hash: {name: this.algorithm}
            },
            this.key,
            dataEnc
        ).then(
            signature => this.signature = signature
        );
    }

    async verify(data, type="str") { // FIXME: not only data but signature as input 
        const dataEnc = this.convertInput(data, type);
        if (this.key === null) {
            throw new Error('No key is assigned yet. Import or generate a key.');
        }
        if (this.signature === null) {
            throw new Error('No signature is assigned yet. Sign your data before verifying.');
        }
        const isValid = await window.crypto.subtle.verify(
            "HMAC",
            this.key,
            this.signature,
            dataEnc
        );
        return isValid;
    }

    getSignature() {
        if (this.signature === null) {
            return null;
        }
        const signatureObj = {
            array: Array.from(new Uint8Array(this.signature))
        };
        return this.appendObjConversions(signatureObj);
    }

    appendObjConversions(obj) {
        /*
            Appends BaseEx encoders to the returned object for the ability
            to covert the byte array to many representations.
        */

        if (!obj.array) throw new Error("No signature associated to this object.");

        const capitalize = str => str.charAt(0).toUpperCase().concat(str.slice(1));

        obj.toHex = () => this.converters.base16.encode(obj.array);
        const converters = Object.keys(this.converters).slice(1);
        for (const converter of converters) {
            obj[`to${capitalize(converter)}`] = () => this.converters[converter].encode(obj.array);
        }

        return obj;
        
    }

    warnUser(message) {
        if (console.hasOwnProperty("warn")) {
            console.warn(message);
        } else {
            console.log(`___\n${message}\n`);
        }
    }
}

HMACObj.prototype.converters = new BaseEx("bytes");

export default HMACObj; 
