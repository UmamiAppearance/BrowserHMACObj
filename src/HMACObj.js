class HMACObj {
    constructor(algorithm="SHA-256") {
        const algorithms = ["SHA-1", "SHA-256", "SHA-384", "SHA-512"];
        algorithm = `SHA-${String(algorithm).match(/[0-9]+/)[0]}`;                      // simplify the input for the user - sha1, Sha-256... everything is fine, even 384 by itself, as long as the numbers match to the provided algorithms
        if (!algorithms.includes(algorithm)) {
            throw new Error(`Ivalid algorithm.\nValid arguments are: "${algorithms.join(", ")}".`);
        }

        this.algorithm = algorithm;
        this.key = null;
        this.signature = null;

        this.genImportCoversions();
    }
    
    convertInput(key, type) {
        let msgEnc;
        
        if (type == "buffer") {
            msgEnc = key;
        } else {
            // convert input to string 
            key = String(key);

            // convert from given type
            if (type === "str") {
                msgEnc = new TextEncoder().encode(key);
            } else if (type === "hex") {
                msgEnc = this.conversions.hexStr(key);
            } else {
                throw new Error("Unknown input type.")
            }
        }
        
        return msgEnc;
    }

    async importKey(key, type="str") {
        const keyEnc = this.convertInput(key, type); 
        crypto.subtle.importKey(
            "raw",
            keyEnc,
            {
                name: "HMAC",
                hash: {name: this.algorithm}
            },
            true,
            ["sign", "verify"]
        ).then(
            keyObj => this.key = keyObj
        );
    }

    async generateKey() {
        window.crypto.subtle.generateKey(
            {
              name: "HMAC",
              hash: {name: this.algorithm}
            },
            true,
            ["sign", "verify"]
        ).then(
            keyObj => this.key = keyObj
        );
    }

    async exportKey() {
        if (this.key === null) {
            throw Error("No key is unset.");
        }
        const keyObj = {};
        const keyBuffer = await window.crypto.subtle.exportKey("raw", this.key);
        keyObj.array = Array.from(new Uint8Array(keyBuffer));
        keyObj.toBase = radix => keyObj.array.map(b => b.toString(radix).padStart(2, '0')).join('');
        keyObj.toStr = () => keyObj.array.map(b => String.fromCharCode(b)).join('');
        return keyObj;
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


    genImportCoversions() {
        this.conversions = { 
            hexStr: function(hexString) {
                /*
                    https://gist.github.com/don/871170d88cf6b9007f7663fdbc23fe09
                */
                // remove the leading 0x
                hexString = hexString.replace(/^0x/, '');
                
                // ensure even number of characters
                if (Boolean(hexString.length % 2)) {
                    hexString = "0".concat(hexString);
                }
                
                // check for some non-hex characters
                const nonHex = hexString.match(/[G-Z\s]/i);
                if (nonHex) {
                    console.log('WARNING: found non-hex characters', nonHex);    
                }
                
                // split the string into pairs of octets
                const pairs = hexString.match(/[\dA-F]{2}/gi);
                
                // convert the octets to integers
                const integers = pairs.map(s => parseInt(s, 16));
                
                return new Uint8Array(integers);
            }
        }
    }
}
