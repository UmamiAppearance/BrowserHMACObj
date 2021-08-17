class HMACObj {
    constructor(algorithm="SHA-256") {
        const algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];

        // simplify the input for the user - sha1, Sha-256...
        // everything is fine, even 384 by itself, as long
        // as the numbers match to the provided algorithms
        const version = String(algorithm).match(/[0-9]+/)[0];
        algorithm = `SHA-${version}`;
        if (!algorithms.includes(algorithm)) {
            throw new Error(`Ivalid algorithm.\nValid arguments are: "${algorithms.join(", ")}".`);
        }

        // set the block-size (64 for SHA-1 & SHA-256 / 128 for SHA-384 & SHA-512)
        this.blockSize = (parseInt(version, 10) < 384) ? 64 : 128;

        // set other class-variables
        this.algorithm = algorithm;
        this.key = null;
        this.keyIsExportable = false;
        this.signature = null;

        // genrate the conversions for user-input
        this.genToBufferConversions();
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
                msgEnc = this.conversions.hexStr(key);
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

    async verify(data, type="str") {
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
        const signatureObj = {
            array: Array.from(new Uint8Array(this.signature))
        };
        return this.appendObjConversions(signatureObj);
    }


    genToBufferConversions() {
        this.conversions = { 
            hexStr: function(hexString) {
                /*
                    inspired by:
                    https://gist.github.com/don/871170d88cf6b9007f7663fdbc23fe09
                */
               
                // remove the leading 0x
                hexString = hexString.replace(/^0x/, '');
                
                if (isNaN(parseInt(hexString, 16))) {
                    throw new TypeError("The provided input is not a valid hexadecimal string.")
                }

                // ensure even number of characters
                if (Boolean(hexString.length % 2)) {
                    hexString = "0".concat(hexString);
                }
                
                // Split the string into pairs of octets, convert to integers 
                // and create a Uin8array from the output.
                const array = Uint8Array.from(hexString.match(/../g).map(s => parseInt(s, 16)));
                
                return array;
            }   
        }
    }

    appendObjConversions(obj) {    
        /* 
            The following conversion functions are
            appended to exported key or signature.
        */
        if (!obj.array) throw new Error("No signature associated to this object.");

        obj.toASCII = () => obj.array.map(b => String.fromCharCode(b)).join('');
        obj.toBase = (radix) => obj.array.map(b => b.toString(radix).padStart(2, '0')).join('');
        obj.toBin = () => obj.toBase(2);
        obj.toOct = () => obj.toBase(8);
        obj.toDec = () => obj.toBase(10);
        obj.toHex = () => obj.toBase(16);
        obj.toBase36 = () => obj.toBase(36).toUpperCase();
        obj.toBase64 = () => window.btoa(obj.toASCII());
        obj.toInt = () => parseInt(obj.toBase(10), 10);

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
