/* eslint-disable no-undef */
import { test } from "no-bro-cote";

test.addImport("import BrowserHMACObj from './dist/BrowserHMACObj.esm.min.js';");

test.makeUnit(
    "Create an instance, generate a key and test for output.",
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
    "Test a simple key and message combination.",
    "6fa7b4dea28ee348df10f9bb595ad985ff150a4adfd6131cca677d9acee07dc6",
    async () => {
        const warn = console.warn.bind(console);
        
        // ignore key warning (yes, it is too short)
        console.warn = () => null;
        const hmacObj = await BrowserHMACObj.new("secret", "Hello World!", "SHA-256");
        console.warn = warn;
        
        return hmacObj.hexdigest();
    }
);

test.init();
