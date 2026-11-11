//! Node keys and access keys: the one-line codes termgate hands out.
//!
//!   tg1-<relay host>:<port>-<CA fingerprint>-<token>
//!
//! CA fingerprint: SHA-256 of termgate's CA certificate (DER), unpadded
//! base32 (52 characters). Token: 32 random bytes, unpadded base32 (52
//! characters). The host may contain "-", so the code is split from the right:
//! the last two parts have a fixed length and no "-" (base32 has none).

const std = @import("std");

pub const prefix = "tg1-";
pub const part_len = 52;

pub const Code = struct {
    host: []const u8,
    port: u16,
    ca_fingerprint: [32]u8,
    token: []const u8,
};

pub const Error = error{InvalidCode};

/// Parses a code. Slices point into `text`.
pub fn parse(text_in: []const u8) Error!Code {
    const text = std.mem.trim(u8, text_in, " \t\r\n");
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidCode;
    const body = text[prefix.len..];
    const token_dash = std.mem.lastIndexOfScalar(u8, body, '-') orelse return error.InvalidCode;
    const token = body[token_dash + 1 ..];
    const rest = body[0..token_dash];
    const fp_dash = std.mem.lastIndexOfScalar(u8, rest, '-') orelse return error.InvalidCode;
    const fp_text = rest[fp_dash + 1 ..];
    const addr = rest[0..fp_dash];
    if (token.len != part_len or fp_text.len != part_len) return error.InvalidCode;
    var tok_raw: [32]u8 = undefined;
    base32Decode(&tok_raw, token) catch return error.InvalidCode;

    var fp: [32]u8 = undefined;
    base32Decode(&fp, fp_text) catch return error.InvalidCode;

    const colon = std.mem.lastIndexOfScalar(u8, addr, ':') orelse return error.InvalidCode;
    const host = addr[0..colon];
    if (host.len == 0) return error.InvalidCode;
    for (host) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '-')) return error.InvalidCode;
    const port = std.fmt.parseInt(u16, addr[colon + 1 ..], 10) catch return error.InvalidCode;
    if (port == 0) return error.InvalidCode;
    return .{ .host = host, .port = port, .ca_fingerprint = fp, .token = token };
}

/// Formats a code. `token_raw` is the 32 random bytes. The caller owns the
/// result.
pub fn format(gpa: std.mem.Allocator, host: []const u8, port: u16, ca_fingerprint: [32]u8, token_raw: [32]u8) ![]u8 {
    var fp: [part_len]u8 = undefined;
    base32Encode(&fp, &ca_fingerprint);
    var tok: [part_len]u8 = undefined;
    base32Encode(&tok, &token_raw);
    return std.fmt.allocPrint(gpa, prefix ++ "{s}:{d}-{s}-{s}", .{ host, port, &fp, &tok });
}

/// SHA-256 of a token, unpadded base32: what termgate stores instead of the
/// token itself.
pub fn tokenDigest(token: []const u8) [part_len]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &digest, .{});
    var full: [part_len]u8 = undefined;
    base32Encode(&full, &digest);
    return full;
}

/// A short, non-secret id of a token for subjects and logs: the first 16
/// characters of tokenDigest.
pub fn tokenId(token: []const u8) [16]u8 {
    return tokenDigest(token)[0..16].*;
}

/// SHA-256 of the first certificate in a PEM text.
pub fn caFingerprint(gpa: std.mem.Allocator, pem: []const u8) ![32]u8 {
    const der = try firstCertDer(gpa, pem);
    defer gpa.free(der);
    var fp: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &fp, .{});
    return fp;
}

/// DER bytes of the first certificate in a PEM text. The caller owns them.
pub fn firstCertDer(gpa: std.mem.Allocator, pem: []const u8) ![]u8 {
    return firstPemBlockDer(gpa, pem, "CERTIFICATE");
}

/// DER bytes of the first PEM block with this label. The caller owns them.
pub fn firstPemBlockDer(gpa: std.mem.Allocator, pem: []const u8, comptime label: []const u8) ![]u8 {
    const begin = "-----BEGIN " ++ label ++ "-----";
    const end = "-----END " ++ label ++ "-----";
    const b = std.mem.indexOf(u8, pem, begin) orelse return error.InvalidPem;
    const start = b + begin.len;
    const stop = std.mem.indexOfPos(u8, pem, start, end) orelse return error.InvalidPem;
    var b64: std.ArrayList(u8) = .empty;
    defer b64.deinit(gpa);
    for (pem[start..stop]) |ch| if (!std.ascii.isWhitespace(ch)) try b64.append(gpa, ch);
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64.items) catch return error.InvalidPem;
    const der = try gpa.alloc(u8, n);
    errdefer gpa.free(der);
    dec.decode(der, b64.items) catch return error.InvalidPem;
    return der;
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32Encode(out: *[part_len]u8, data: *const [32]u8) void {
    var acc: u16 = 0;
    var bits: u4 = 0;
    var o: usize = 0;
    for (data) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o] = alphabet[(acc >> bits) & 31];
            o += 1;
        }
    }
    out[o] = alphabet[(acc << (5 - bits)) & 31];
}

fn base32Decode(out: *[32]u8, text: []const u8) !void {
    var acc: u16 = 0;
    var bits: u4 = 0;
    var o: usize = 0;
    for (text) |ch| {
        const v: u16 = switch (ch) {
            'A'...'Z' => ch - 'A',
            '2'...'7' => ch - '2' + 26,
            else => return error.InvalidCode,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o] = @truncate(acc >> bits);
            o += 1;
        }
    }
    if (o != out.len) return error.InvalidCode;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "format and parse round trip, host with dashes" {
    const a = testing.allocator;
    var fp: [32]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i);
    const tok: [32]u8 = @splat(0xAB);
    const text = try format(a, "relay-1.firma-x.com", 4222, fp, tok);
    defer a.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "tg1-relay-1.firma-x.com:4222-"));

    const c = try parse(text);
    try testing.expectEqualStrings("relay-1.firma-x.com", c.host);
    try testing.expectEqual(@as(u16, 4222), c.port);
    try testing.expectEqualSlices(u8, &fp, &c.ca_fingerprint);
    try testing.expectEqual(@as(usize, part_len), c.token.len);

    // Surrounding whitespace from copy and paste is tolerated
    const padded = try std.fmt.allocPrint(a, "  {s}\n", .{text});
    defer a.free(padded);
    _ = try parse(padded);
}

test "malformed codes are rejected" {
    const a = testing.allocator;
    const text = try format(a, "10.0.0.1", 4222, @splat(1), @splat(2));
    defer a.free(text);
    try testing.expectError(error.InvalidCode, parse(text[0 .. text.len - 1]));
    try testing.expectError(error.InvalidCode, parse(text[1..]));
    try testing.expectError(error.InvalidCode, parse("tg1-host-xx-yy"));
    var bad = try a.dupe(u8, text);
    defer a.free(bad);
    bad[bad.len - 3] = '1'; // not in the base32 alphabet
    try testing.expectError(error.InvalidCode, parse(bad));
    const no_port = try std.mem.replaceOwned(u8, a, text, ":4222", "");
    defer a.free(no_port);
    try testing.expectError(error.InvalidCode, parse(no_port));
}

test "token id is stable and short" {
    const id1 = tokenId("TOKEN");
    const id2 = tokenId("TOKEN");
    try testing.expectEqualSlices(u8, &id1, &id2);
    try testing.expect(!std.mem.eql(u8, &id1, &tokenId("OTHER")));
}
