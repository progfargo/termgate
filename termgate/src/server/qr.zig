//! A QR code as SVG, for the setup key of a user's second step (the
//! otpauth:// address an authenticator app scans). Encoded by nayuki's
//! qrcodegen (vendor/qrcodegen, C).

const std = @import("std");

// vendor/qrcodegen/qrcodegen.h
extern fn qrcodegen_encodeText(text: [*:0]const u8, temp: [*]u8, qrcode: [*]u8, ecl: c_int, min_version: c_int, max_version: c_int, mask: c_int, boost_ecl: bool) bool;
extern fn qrcodegen_getSize(qrcode: [*]const u8) c_int;
extern fn qrcodegen_getModule(qrcode: [*]const u8, x: c_int, y: c_int) bool;

/// qrcodegen_BUFFER_LEN_MAX: version 40
const buffer_len = ((40 * 4 + 17) * (40 * 4 + 17) + 7) / 8 + 1;
/// qrcodegen_Ecc_MEDIUM, qrcodegen_Mask_AUTO
const ecc_medium = 1;
const mask_auto = -1;

/// `text` as a QR code: an SVG of dark squares on white with the quiet
/// zone around them, scaling to its box.
pub fn svg(a: std.mem.Allocator, text: []const u8) ![]const u8 {
    const z = try a.dupeSentinel(u8, text, 0);
    const temp = try a.alloc(u8, buffer_len);
    const code = try a.alloc(u8, buffer_len);
    if (!qrcodegen_encodeText(z.ptr, temp.ptr, code.ptr, ecc_medium, 1, 40, mask_auto, true)) return error.TooLong;
    const n = qrcodegen_getSize(code.ptr);
    const quiet = 4;
    var out: std.Io.Writer.Allocating = .init(a);
    const w = &out.writer;
    try w.print("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {d} {d}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><path fill=\"#000\" d=\"", .{ n + 2 * quiet, n + 2 * quiet });
    var y: c_int = 0;
    while (y < n) : (y += 1) {
        var x: c_int = 0;
        while (x < n) : (x += 1) {
            if (qrcodegen_getModule(code.ptr, x, y)) try w.print("M{d} {d}h1v1h-1z", .{ x + quiet, y + quiet });
        }
    }
    try w.writeAll("\"/></svg>");
    return out.written();
}

test "a QR code as SVG" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const s = try svg(arena.allocator(), "otpauth://totp/termgate:veli?secret=JBSWY3DPEHPK3PXP&issuer=termgate");
    try std.testing.expect(std.mem.startsWith(u8, s, "<svg "));
    try std.testing.expect(std.mem.indexOf(u8, s, "M4 4h1v1h-1z") != null); // the finder pattern's corner
    try std.testing.expect(std.mem.endsWith(u8, s, "</svg>"));
}
