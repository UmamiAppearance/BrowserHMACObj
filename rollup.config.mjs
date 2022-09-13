import { terser } from "rollup-plugin-terser";

export default {
    input: "src/index.js",
    output: [ 
        {   
            format: "iife",
            name: "BrowserHMACObj",
            file: "dist/BrowserHMACObj.iife.js"
        },
        {   
            format: "iife",
            name: "BrowserHMACObj",
            file: "dist/BrowserHMACObj.iife.min.js",
            plugins: [terser()]
        },
        {   
            format: "es",
            name: "BrowserHMACObj",
            file: "dist/BrowserHMACObj.esm.js"
        },
        {   
            format: "es",
            name: "BrowserHMACObj",
            file: "dist/BrowserHMACObj.esm.min.js",
            plugins: [terser()]
        },
    ]
};
