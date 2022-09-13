import { BaseEx } from "../node_modules/base-ex/src/base-ex.js";

class PermissionError extends Error {
    constructor(message) {
        super(message);
        this.name = "PermissionError";
    }
}

function warn(message) {
    if (Object.prototype.hasOwnProperty.call(console, "warn")) {
        console.warn(message);
    } else {
        console.log(`___\n${message}\n`);
    }
}

const digestmods = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

class HMAC {
    constructor(digestmod) {

        if (!digestmod) {
            throw new TypeError("Missing required parameter 'digestmod'.");
        }

        // Simplify the input for the user - sha1, Sha-256...
        // everything is fine, even 384 by itself, as long
        // as the numbers match to the provided digestmods.
        const version = String(digestmod).match(/[0-9]+/)[0];
        digestmod = `SHA-${version}`;
        if (!digestmods.includes(digestmod)) {
            throw new TypeError(`Invalid digestmod.\nValid arguments are: "${digestmods.join(", ")}".`);
        }

        // set the block-size (64 for SHA-1 & SHA-256 / 128 for SHA-384 & SHA-512)
        this.blockSize = (parseInt(version, 10) < 384) ? 64 : 128;

        // set digestmod
        this.digestmod = digestmod;
        this.msg = new Array();

        this.converters = new BaseEx("bytes");

    }

    async init(msg, key="auto") {
        if (key === "auto") {
            warn("No key was specified. It is generated for you and exportable. If you don't want this behaviour, pass a key as second argument to this call.");
            CryptoSubtle.generateKey(this.digestmod, true).then(freshKey => this.key = freshKey);
        } else {
            this.key = key;
        }
        await this.update();
    }

    async update(msg) {
        this.msg = this.msg.concat(msg);
        this.current = await this.CryptoSubtle.sign(this.msg, this.key);
    }

    prepMsg(msg) {
        let prepped;
        if (typeof(msg) === "string") {
            prepped = new TextEncoder().encode(input);
        } else if (!(input instanceof ArrayBuffer || ArrayBuffer.isView(input))) {
            throw new TypeError("Input must be of type String, ArrayBuffer or ArrayBufferView (typed array)");
        }
    } 


    setKey(keyObj) {
        this.key = keyObj;
        this.signature = null;      // reset signature
    }

    async importKey(key, type="str", allowExports=false) {
        const classObj = this;
        const keyEnc = this.convertInput(key, type);
        if (keyEnc.length < this.blockSize) {
            warning(`WARNING: Your provided key-length is '${keyEnc.length}'.\n\nThis is less than blocksize of ${this.blockSize} used by ${this.digestmod}.\nIt will work, but this is not secure.`);
        }
        this.keyIsExportable = allowExports;
        
        crypto.subtle.importKey(
            "raw",
            keyEnc,
            {
                name: "HMAC",
                hash: {name: this.digestmod}
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
                hash: {name: this.digestmod}
            },
            allowExports,
            ["sign", "verify"]
        ).then(
            keyObj => classObj.setKey(keyObj)
        );
    }

    async exportKey() {
        if (this.key === null) {
            throw new Error("Key is unset.");
        }
        if (!this.keyIsExportable) {
            throw new PermissionError("Key exports are not allowed. You have to set this before key-generation.");
        }
        const keyBuffer = await window.crypto.subtle.exportKey("raw", this.key);
        const keyObj = {
            array: Array.from(new Uint8Array(keyBuffer))
        };
        return this.appendObjConversions(keyObj);
    }

    async sign(data, type="str") {
        const dataEnc = this.convertInput(data, type);
        if (this.key === null) {
            throw new Error("No key is assigned yet. Import or generate a key.");
        } 
        window.crypto.subtle.sign(
            {
                name: "HMAC",
                hash: {name: this.digestmod}
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
            throw new Error("No key is assigned yet. Import or generate a key.");
        }
        if (this.signature === null) {
            throw new Error("No signature is assigned yet. Sign your data before verifying.");
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
}

const CryptoSubtle = {

    importKey: async (key, digestmod, permitExports=false) => {
        if (!key) {
            throw new TypeError("Missing required parameter 'key'.");
        }
        return crypto.subtle.importKey(
            "raw",
            key,
            {
                name: "HMAC",
                hash: {name: digestmod}
            },
            permitExports,
            ["sign", "verify"]
        );
    },

    generateKey: async (digestmod, permitExports=false) => {
        return await window.crypto.subtle.generateKey(
            {
                name: "HMAC",
                hash: {name: digestmod}
            },
            permitExports,
            ["sign", "verify"]
        );
    },

    exportKey: async (key) => {
        if (!key.extractable) {
            throw new PermissionError("Key exports are not allowed. You have to set this before key-generation.");
        }
        return await window.crypto.subtle.exportKey("raw", key);
    },

    sign: async (msg, key) => { 
        return await window.crypto.subtle.sign(
            {
                name: "HMAC",
                hash: key.digestmod.hash
            },
            key,
            msg
        );
    },

    verify: async (msg, signature, key) => {  
        return await window.crypto.subtle.verify(
            "HMAC",
            key,
            signature,
            msg
        );
    },
};


class Main {
    constructor() {
        this.CryptoSubtle = CryptoSubtle;
        this.HMAC = HMAC;
    }

    converters() {
        warning("Converters are not initialized");
        return false;
    }

}

const hmac = new Main();

export default hmac; 
