// Package fingerprint reproduces the nazr TypeScript client's fingerprint
// pipeline on the server: stable JSON stringification, murmur3 x86 128
// hashing, component filtering (include/exclude/stabilize rules) and merging
// of server-side components.
//
// The package mirrors packages/thumbmark/src (utils/stableStringify.ts,
// utils/hash.ts, functions/filterComponents.ts and options.ts) and must stay
// byte-for-byte compatible with it. The golden fixtures in testdata/fixtures,
// generated from the client, are the contract: when they disagree with this
// code, the code is wrong.
package fingerprint
