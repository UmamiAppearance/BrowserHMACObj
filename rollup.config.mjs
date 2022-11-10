import terser from "@rollup/plugin-terser";

const selectiveTerser = terser({
    output: {
        comments: (node, comment) => {
            const text = comment.value;
            const type = comment.type;
            if (type === "comment2") {
                return !(/BaseEx\|\w+/).test(text) && (/@license/i).test(text);
            }
        }
    },
});

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
            plugins: [selectiveTerser]
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
            plugins: [selectiveTerser]
        },
    ]
};
