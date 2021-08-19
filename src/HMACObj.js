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

        this.converters = {
            base32: new Base32("rfc4648")
        }

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
            } else if (type === "base32") {
                this.converters.base32.decode(key);
            } else if (type === "base64") {
                msgEnc = Uint8Array.from(window.atob(key), c => c.charCodeAt(0));
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

    genToBufferConversions() {
        this.conversions = { 
            hexStr: function(hexString) {
                /*
                    inspired by:
                    https://gist.github.com/don/871170d88cf6b9007f7663fdbc23fe09
                */
               
                // remove the leading 0x if present
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
                const array = Uint8Array.from(hexString.match(/../g).map(pair => parseInt(pair, 16)));
                
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

        obj.toASCII = () => obj.array.map(b => String.fromCharCode(b)).join("");
        obj.toBin = () => obj.array.map(b => b.toString(2).padStart(8, "0")).join("");
        obj.toDec = () => obj.array.map(b => b.toString(10)).join("");
        obj.toHex = () => obj.array.map(b => b.toString(16).padStart(2, "0")).join("");
        obj.toBase32 = () => this.converters.base32.encode(obj.array, "array");
        obj.toBase64 = () => window.btoa(obj.toASCII());
        obj.toInt = () => parseInt(obj.toDec());

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


// from: https://github.com/UmamiAppearance/BaseExJS
class Base32 {
    constructor(standard=null) {
        
        if (standard && !(standard === "rfc3548" || standard === "rfc4648")) {
            throw new TypeError("Unknown standard.\nThe options are 'rfc3548' and 'rfc4648'.");
        }

        this.standard = standard;

        this.chars = {
            rfc3548: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
            rfc4648: "0123456789ABCDEFGHIJKLMNOPQRSTUV" 
        }
    }

    validateArgs(args) {
        if (Boolean(args.length)) {
            const validArgs = ["rfc3548", "rfc4648", "str", "array"];
            const globalStandard = Boolean(this.standard);
            const warning = this.warnUser;

            args.forEach(arg => {
                if (!validArgs.includes(arg)) {
                    throw new TypeError(`Invalid argument: "${arg}"\nThe options are 'rfc3548' and 'rfc4648' for the rfc-standard, for in- and output-type, valid arguments are 'str' and 'array'.`);
                } else if (validArgs.slice(0, 2).includes(arg)) {
                    warning(`Standard is already set.\nArgument '${arg}' will be ignored.`)
                }
            });
        }
    }

    validateInput(input, inputType) {
        if (inputType === "str") {
            if (typeof input !== "string") {
                this.warnUser("Your input was converted into a string.");
            }
            return String(input);
        } else {
            if (typeof input === "string") {
                throw new TypeError("Your provided input is a string, but some kind of (typed) Array is expected.");
            } else if (typeof input !== 'object') {
                throw new TypeError("Input must be some kind of (typed) Array if input type is set to 'array'.");
            }
            return input; 
        }
    }
    
    encode(input, ...args) {
        
        this.validateArgs(args);
        
        let standard = "rfc4648";
        if (this.standard) {
            standard = this.standard;
        } else if (args.includes("rfc3548")) {
            standard = "rfc3548";
        }

        const inputType = (args.includes("array")) ? "array" : "str";
        input = this.validateInput(input, inputType);

        const chars = this.chars[standard];

        let binaryStr;
        if (inputType === "str") {
            binaryStr = input.split('').map((c) => c.charCodeAt(0).toString(2).padStart(8, "0")).join("");
        } else if (inputType === "array") {
            binaryStr = Array.from(input).map(b => b.toString(2).padStart(8, "0")).join("");
        }

        const bitGroups = binaryStr.match(/.{1,40}/g);

        let output = "";
        bitGroups.map(function(group) {
            const blocks = group.match(/.{1,5}/g).map(s=>s.padEnd(5, '0'));
            blocks.map(function(block) {
                const charIndex = parseInt(block, 2);
                output = output.concat(chars[charIndex]);
            });
        });
        const missingChars = output.length % 8;
        if (Boolean(missingChars)) {
            output = output.padEnd(output.length + 8-missingChars, "=");
        }

        return output;
    }

    decode(input, ...args) {

        this.validateArgs(args);
        let standard = "rfc4648";
        if (this.standard) {
            standard = this.standard;
        } else if (args.includes("rfc3548")) {
            standard = "rfc3548";
        }

        const outputType = (args.includes("array")) ? "array" : "str";
        const chars = this.chars[standard];
        
        let binaryStr = "";

        input.split('').map((c) => {
            const index = chars.indexOf(c);
            console.log(index);
            if (index > -1) {                                       // -1 is the index if the char was not found, "=" will be ignored
                binaryStr = binaryStr.concat(index.toString(2).padStart(5, "0"));
            }
        });
        
        const byteArray = binaryStr.match(/.{8}/g).map(bin => parseInt(bin, 2))
        const uInt8 = Uint8Array.from(byteArray);

        if (outputType === "array") {
            return uInt8;
        } else {
            return byteArray.map(b => String.fromCharCode(b)).join("");
        }
    }

    warnUser(message) {
        if (console.hasOwnProperty("warn")) {
            console.warn(message);
        } else {
            console.log(`___\n${message}\n`);
        }
    }
}
