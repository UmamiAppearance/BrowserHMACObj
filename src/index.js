import { crypto, PermissionError } from "./crypto.js";
import { BaseEx } from "../node_modules/base-ex/src/base-ex.js";


const ALGORITHMS = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
const BASE_EX = new BaseEx();


class BrowserHMACObj {
    constructor(digestmod) {

        if (!digestmod) {
            throw new TypeError("Missing required parameter 'digestmod'.");
        }

        // Simplify the input for the user - sha1, Sha-256...
        // everything is fine, even 384 by itself, as long
        // as the numbers match to the provided digestmods.
        const version = String(digestmod).match(/[0-9]+/)[0];
        digestmod = `SHA-${version}`;
        if (!ALGORITHMS.includes(digestmod)) {
            throw new TypeError(`Invalid digestmod.\nValid arguments are: "${ALGORITHMS.join(", ")}".`);
        }

        // set the block-size (64 for SHA-1 & SHA-256 / 128 for SHA-384 & SHA-512)
        this.blockSize = (parseInt(version, 10) < 384) ? 64 : 128;

        // set digestmod
        this.digestmod = digestmod;
        this.msg = new Array();

        this.converters = BASE_EX;

    }

    async init(msg, key="auto") {
        if (key === "auto") {
            console.warn("No key was specified. It is generated for you and exportable. If you don't want this behaviour, pass a key as second argument to this call.");
            crypto.generateKey(this.digestmod, true).then(freshKey => this.key = freshKey);
        } else {
            this.key = key;
        }
        await this.update();
    }

    async update(msg) {
        this.msg = this.msg.concat(msg);
        this.current = await crypto.sign(this.msg, this.key);
    }

    toBytes(input) {
        return BASE_EX.byteConverter.encode(input, "uint8");
    } 

    setKey(keyObj) {
        this.key = keyObj;
        this.signature = null;      // reset signature
    }

    async importKey(key, permitExports=false) {
        key = this.toBytes(key);
        if (key.byteLength < this.blockSize) {
            console.warn(`Your provided key-length is '${key.length}'.\n\nThis is less than blocksize of ${this.blockSize} used by ${this.digestmod}.\nIt will work, but this is not secure.`);
        }
        this.keyIsExportable = permitExports;
        
        const keyObj = await crypto.importKey(key, this.digestmod, permitExports);
        this.setKey(keyObj);

    }

    async generateKey(permitExports=false) {
        this.keyIsExportable = Boolean(permitExports);
        const keyObj = await crypto.generateKey(this.digestmod, this.keyIsExportable);
        this.setKey(keyObj);
    }

    async exportKey() {
        if (this.key === null) {
            throw new Error("Key is unset.");
        }
        if (!this.keyIsExportable) {
            throw new PermissionError("Key exports are not allowed. You have to set this before key-generation.");
        }
        const keyBuffer = await crypto.exportKey(this.key);
        const keyObj = {
            array: Array.from(new Uint8Array(keyBuffer))
        };
        return this.appendObjConversions(keyObj);
    }

    async sign(data) {
        if (this.key === null) {
            throw new Error("No key is assigned yet. Import or generate a key.");
        }
        data = this.toBytes(data);
        this.signature = await crypto.sign(data, this.key);
    }

    async verify(data, signature=null) { 
        data = this.toBytes(data);
        if (this.key === null) {
            throw new Error("No key is assigned yet. Import or generate a key.");
        }
        if (this.signature === null) {
            signature = this.signature;
        }
        const isValid = await crypto.verify(data, signature, this.key);
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
}

export default BrowserHMACObj;
