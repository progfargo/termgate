# zig-js

A copy of [mitchellh/zig-js](https://github.com/mitchellh/zig-js) (MIT, see
LICENSE), commit 3c23860 (2026-04-16): access to JavaScript values from Zig
compiled to WASM, used by termgate's panel (`src/spa`).

Changed:
- For Zig 0.17: `src/Object.zig` reads a tuple's fields with `field_names`
  and `field_types` (0.17's `@typeInfo` has no `fields`).
- `src/value.zig`: an empty string is not copied (its buffer's address is
  not a valid one, and the JS side threw on it).

The JS side is `../../web/spa/zigjs.js`, the original `js/src/zigjs.ts` written as
plain JavaScript.
