/* eslint-disable no-undef */
import { test } from "no-bro-cote";

test.addImport("import BrowserHMACObj from './dist/BrowserHMACObj.esm.min.js';");

test.makeUnit(
    "Creating an instance, generating a key and testing for output.",
    48,
    async () => {
        const hmacObj = new BrowserHMACObj("SHA-384");
        await hmacObj.generateKey();
        await hmacObj.update("Hello World!");
        const digest = hmacObj.digest();
        return digest.byteLength;

    }
);

test.makeUnit(
    "Simple key and message combination.",
    "6fa7b4dea28ee348df10f9bb595ad985ff150a4adfd6131cca677d9acee07dc6",
    async () => {
        const hmacObj = await BrowserHMACObj.new("secret", "Hello World!", "SHA-256");
        
        return hmacObj.hexdigest();
    }
);

test.makeUnit(
    "Block and digest size calculation for all four digestmods.",
    false,
    async () => {
        const errors = [];
        
        const testProps = async (digestmod, digestSize, blockSize) => {

            const h = await new BrowserHMACObj(digestmod);
            
            if (h.digestSize !== digestSize) {
                console.error(`Wrong digest size for ${digestmod}.`);
                errors.push(true);
            } else {
                errors.push(false);
            }
            
            if (h.blockSize !== blockSize) {
                console.error(`Wrong block size for ${digestmod}.`);
                errors.push(true);
            } else {
                errors.push(false);
            }
        };

        await Promise.all([
            [ "SHA-1",   20,  64 ],
            [ "SHA-256", 32,  64 ],
            [ "SHA-384", 48, 128 ],
            [ "SHA-512", 64, 128 ]
        ].map(async values => await testProps(...values)));

        return errors.some(e => e);
    }
);

test.makeUnit(
    "Input concatenation, single signing and digest comparison.",
    true,
    async () => {
        const sha384 = new BrowserHMACObj("SHA-384");
        await sha384.generateKey();
        await sha384.update("Hello ");
        await sha384.update("World!");
        
        const digestA = sha384.digest();
        const digestB = await sha384.sign("Hello World!");

        return BrowserHMACObj.compareDigest(digestA, digestB);
    }
);

test.makeUnit(
    "Copy instance, expect identical output as the original.",
    "e76370666b4f08472093fa26223782d6cdacf947",
    async () => {
        const h = new BrowserHMACObj("SHA-1");
        await h.importKey("2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b");
        await h.update("Hello World!");

        const clone = await h.copy();
        return clone.hexdigest();
    } 
);

test.makeUnit(
    "Create external secret key, assign it to instance and test 'verify' method.",
    true,
    async () => {
        const key = await BrowserHMACObj.generateKey("SHA-512");
        const msg = "Hello World!";
        const h = await BrowserHMACObj.new(key, msg, "SHA-512", "object");
        
        const wrongSignature = new TextEncoder().encode("abc123"); 
        const correctSignature = h.digest();

        if (await h.verify(msg, wrongSignature) === true) {
            return false;
        }

        return await h.verify(msg, correctSignature);
    }
);

test.init();
