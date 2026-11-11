//! Calls from the panel (WASM) to termgate: POST /api/<name> with JSON,
//! made by the page's loader (web/loader.js). The call blocks until the
//! answer is there, so the screens read data as from a local database.

const std = @import("std");

// web/loader.js
extern "env" fn tg_call(name: [*]const u8, name_len: usize, body: [*]const u8, body_len: usize) i32;
extern "env" fn tg_call_len() usize;
extern "env" fn tg_call_read(out: [*]u8) void;

pub const Response = struct {
    /// HTTP status; 0: the server could not be reached
    status: u16,
    body: []u8,
};

pub fn call(a: std.mem.Allocator, name: []const u8, body: []const u8) !Response {
    const status = tg_call(name.ptr, name.len, body.ptr, body.len);
    const out = try a.alloc(u8, tg_call_len());
    tg_call_read(out.ptr);
    return .{ .status = if (status < 0) 0 else @intCast(status), .body = out };
}

/// A call that answers {"ok": value} or {"err": "ErrorName"} (the database
/// and relay calls). `E` is the error set the caller expects; an error
/// outside it, or a failed call, becomes `fallback`.
pub fn result(comptime R: type, comptime E: type, comptime fallback: E, a: std.mem.Allocator, name: []const u8, args: anytype) E!R {
    const body = std.json.Stringify.valueAlloc(a, args, .{}) catch return fallback;
    const resp = call(a, name, body) catch return fallback;
    if (resp.status != 200) return fallback;
    const Wire = struct { ok: ?std.json.Value = null, err: ?[]const u8 = null };
    const w = std.json.parseFromSliceLeaky(Wire, a, resp.body, .{ .ignore_unknown_fields = true }) catch return fallback;
    if (w.err) |name_of| {
        if (@typeInfo(E).error_set.error_names) |names| {
            inline for (names) |n| {
                if (std.mem.eql(u8, n, name_of)) return @field(E, n);
            }
        }
        return fallback;
    }
    if (R == void) return;
    const v = w.ok orelse std.json.Value{ .null = {} };
    return std.json.parseFromValueLeaky(R, a, v, .{ .ignore_unknown_fields = true }) catch fallback;
}

pub fn decodeBase64(a: std.mem.Allocator, text: []const u8) ![]u8 {
    const dec = std.base64.standard.Decoder;
    const out = try a.alloc(u8, dec.calcSizeForSlice(text) catch return error.InvalidData);
    dec.decode(out, text) catch return error.InvalidData;
    return out;
}
