# qrcodegen

A copy of the C version of [nayuki/QR-Code-generator](https://github.com/nayuki/QR-Code-generator)
(MIT; the license is at the top of each file), commit bcfe1b0 (2026-10-29),
unchanged: `qrcodegen.c` and `qrcodegen.h`.

termgate's server uses it to draw the setup key of a user's second step as a
QR code (`src/server/qr.zig`).
