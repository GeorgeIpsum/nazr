import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";

// rollup.config.mjs
import resolve from "@rollup/plugin-node-resolve";
import terser from "@rollup/plugin-terser";
import typescript from "@rollup/plugin-typescript";
import dts from "rollup-plugin-dts";
import { obfuscate } from "./scripts/obfuscate.mjs";

const config = [
    {
        watch: {
            include: "src/**",
            exclude: "node_modules/**",
            clearScreen: false, // Prevents the console from being cleared on each rebuild
        },
        input: "src/index.ts", // replace with your entry file
        onwarn(warning, warn) {
            // The UMD output deliberately has no source map (it is obfuscated);
            // the TypeScript plugin warns whenever any output omits one.
            if (warning.plugin === "typescript" && warning.message.includes("'sourcemap' option"))
                return;
            warn(warning);
        },
        output: [
            {
                // .cjs, not .cjs.js: package.json declares "type": "module", which makes Node
                // parse every .js file in this package as ESM regardless of the rest of the name.
                file: "dist/thumbmark.cjs",
                format: "cjs",
                sourcemap: true,
            },
            {
                file: "dist/thumbmark.esm.js",
                format: "esm",
                sourcemap: true,
            },
            {
                file: "dist/thumbmark.umd.js",
                format: "umd",
                // Obfuscated drop-in bundle: a source map would undo it.
                sourcemap: false,
                name: "ThumbmarkJS",
                // Output plugins run after terser, so this obfuscates the
                // minified code. ESM and CJS above stay readable.
                plugins: [obfuscate()],
            },
        ],
        plugins: [
            resolve(), // so Rollup can find `ms`
            commonjs(), // so Rollup can convert `ms` to an ES module
            typescript(),
            json(),
            terser(), // minify, but only in production
        ],
    },
    {
        input: "./dist/types/index.d.ts",
        output: [{ file: "dist/thumbmark.esm.d.ts", format: "es" }],
        plugins: [dts()],
    },
];

export default config;
