class PermissionError extends Error {
    constructor(message) {
        super(message);
        this.name = "PermissionError";
    }
}

const cryptoSubtle = {

    importKey: async (key, digestmod, format="raw", permitExports=false) => {
        return await window.crypto.subtle.importKey(
            format,
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

    exportKey: async (key, format="raw") => {
        if (!key.extractable) {
            throw new PermissionError("Key exports are not allowed. You can permit this during key-generation.");
        }
        return await window.crypto.subtle.exportKey(format, key);
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

export { cryptoSubtle, PermissionError };
