class PermissionError extends Error {
    constructor(message) {
        super(message);
        this.name = "PermissionError";
    }
}

const crypto = {

    importKey: async (key, digestmod, permitExports=false) => {
        console.log(key);
        return await window.crypto.subtle.importKey(
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
                hash: key.algorithm.hash.name
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

export { crypto, PermissionError };
