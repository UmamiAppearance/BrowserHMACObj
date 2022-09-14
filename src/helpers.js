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

const getDigestModFromParam = (digestmod, digestmods) => {
        
    if (!digestmod) {
        throw new TypeError("Missing required parameter 'digestmod'.");
    }

    let bits = [].concat(String(digestmod).match(/[0-9]+/)).at(0)|0;
    digestmod = `SHA-${bits}`;

    if (!digestmods.includes(digestmod)) {
        throw new TypeError(`Available digestmod are: '${digestmods.join(", ")}'.`);
    }

    if (bits === 1) {
        bits = 160;
    }

    return [ digestmod, bits ];
};


export {
    cryptoSubtle,
    getDigestModFromParam,
    PermissionError
};
