//! Signing in to the panel: passwords, the second step (TOTP) and browser
//! session tokens. No storage here; see db.zig for the tables.
//!
//! - Passwords: Argon2id, stored as a PHC string (salt and cost inside).
//! - Second step: time-based one-time codes (RFC 6238: HMAC-SHA1, 30 s
//!   steps, 6 digits), as in Google Authenticator and every other
//!   authenticator app. A code is accepted for its own step and the one
//!   before and after (clock drift), and never twice.
//! - Session token: 32 random bytes, base64url. The server stores only its
//!   SHA-256, so a copy of the database holds no usable session.

const std = @import("std");
const Io = std.Io;
const argon2 = std.crypto.pwhash.argon2;
const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64 = std.base64.url_safe_no_pad;

/// Argon2id cost for passwords: OWASP's recommendation (19 MiB, 2 passes,
/// 1 lane), fast enough that signing in does not keep anyone waiting.
pub const Cost = struct { t: u32, m: u32, p: u24 };
pub const default_cost: Cost = .{ .t = 2, .m = 19 * 1024, .p = 1 };
/// For tests only
pub const test_cost: Cost = .{ .t = 1, .m = 1024, .p = 1 };

/// The PHC string to store for `password`. Caller owns it.
pub fn hashPassword(gpa: std.mem.Allocator, io: Io, password: []const u8, cost: Cost) ![]u8 {
    var buf: [256]u8 = undefined;
    const s = try argon2.strHash(password, .{ .allocator = gpa, .params = .{ .t = cost.t, .m = cost.m, .p = cost.p } }, &buf, io);
    return gpa.dupe(u8, s);
}

/// Whether a stored hash was made with another cost than `cost` (it is
/// hashed again at the next sign-in).
pub fn needsRehash(phc: []const u8, cost: Cost) bool {
    var buf: [64]u8 = undefined;
    const want = std.fmt.bufPrint(&buf, "$argon2id$v=19$m={d},t={d},p={d}$", .{ cost.m, cost.t, cost.p }) catch return true;
    return !std.mem.startsWith(u8, phc, want);
}

pub fn checkPassword(gpa: std.mem.Allocator, io: Io, phc: []const u8, password: []const u8) bool {
    argon2.strVerify(phc, password, .{ .allocator = gpa }, io) catch return false;
    return true;
}

/// A password an admin hands over (first sign-in, reset): 20 characters
/// from an alphabet without look-alikes.
pub fn randomPassword(io: Io) [20]u8 {
    const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    var raw: [20]u8 = undefined;
    io.random(&raw);
    var out: [20]u8 = undefined;
    // 256 mod 56 is not 0: the bias is far below what matters at 20 characters
    for (raw, 0..) |b, i| out[i] = alphabet[b % alphabet.len];
    return out;
}

test "a hash with another cost is hashed again" {
    const a = std.testing.allocator;
    const h = try hashPassword(a, std.testing.io, "ankara12", test_cost);
    defer a.free(h);
    try std.testing.expect(!needsRehash(h, test_cost));
    try std.testing.expect(needsRehash(h, default_cost));
    try std.testing.expect(needsRehash("$argon2id$v=19$m=65536,t=3,p=1$abc$def", default_cost));
}

// --- TOTP -------------------------------------------------------------------

pub const totp_secret_len = 20;
pub const totp_step_s = 30;

pub fn newTotpSecret(io: Io) [totp_secret_len]u8 {
    var s: [totp_secret_len]u8 = undefined;
    io.random(&s);
    return s;
}

/// The 6-digit code of time step `step`.
pub fn totpCode(secret: []const u8, step: u64) u32 {
    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, step, .big);
    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, &msg, secret);
    const off = mac[mac.len - 1] & 0x0f;
    const bin = std.mem.readInt(u32, mac[off..][0..4], .big) & 0x7fff_ffff;
    return bin % 1_000_000;
}

/// Checks a typed code at time `now`. Returns the step it belongs to (store
/// it: the same or an older step is not accepted again), or null.
pub fn totpVerify(secret: []const u8, code_text: []const u8, now: i64, last_used_step: u64) ?u64 {
    const text = std.mem.trim(u8, code_text, " ");
    if (text.len != 6) return null;
    const code = std.fmt.parseInt(u32, text, 10) catch return null;
    const current: u64 = @intCast(@divFloor(now, totp_step_s));
    var step = current -| 1;
    while (step <= current + 1) : (step += 1) {
        if (step <= last_used_step) continue;
        if (totpCode(secret, step) == code) return step;
    }
    return null;
}

/// The secret as authenticator apps take it: base32, in groups of four.
pub fn totpSecretText(secret: [totp_secret_len]u8) [39]u8 {
    var raw: [32]u8 = undefined;
    base32(&raw, &secret);
    var out: [39]u8 = undefined;
    var o: usize = 0;
    for (raw, 0..) |c, i| {
        if (i > 0 and i % 4 == 0) {
            out[o] = ' ';
            o += 1;
        }
        out[o] = c;
        o += 1;
    }
    return out;
}

/// otpauth:// URI (what a QR code for the app would hold). Caller owns it.
pub fn totpUri(gpa: std.mem.Allocator, secret: [totp_secret_len]u8, user: []const u8) ![]u8 {
    var raw: [32]u8 = undefined;
    base32(&raw, &secret);
    return std.fmt.allocPrint(gpa, "otpauth://totp/termgate:{s}?secret={s}&issuer=termgate&algorithm=SHA1&digits=6&period=30", .{ user, raw });
}

/// Unpadded base32 (RFC 4648); 20 bytes give exactly 32 characters.
fn base32(out: []u8, in: []const u8) void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    var bits: u32 = 0;
    var n: u5 = 0;
    var o: usize = 0;
    for (in) |b| {
        bits = (bits << 8) | b;
        n += 8;
        while (n >= 5) {
            n -= 5;
            out[o] = alphabet[(bits >> n) & 31];
            o += 1;
        }
    }
    if (n > 0) {
        out[o] = alphabet[(bits << (5 - n)) & 31];
        o += 1;
    }
    std.debug.assert(o == out.len);
}

// --- browser sessions ---------------------------------------------------------

pub const token_len = b64.Encoder.calcSize(32);
pub const token_hash_len = 2 * Sha256.digest_length;

/// A new session token (goes to the browser as a cookie).
pub fn newToken(io: Io) [token_len]u8 {
    var raw: [32]u8 = undefined;
    io.random(&raw);
    var out: [token_len]u8 = undefined;
    _ = b64.Encoder.encode(&out, &raw);
    return out;
}

/// What the server stores for a token: its SHA-256, hex.
pub fn tokenHash(token: []const u8) [token_hash_len]u8 {
    var d: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(token, &d, .{});
    return std.fmt.bytesToHex(d, .lower);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "password hashes verify only their password" {
    const a = testing.allocator;
    const h = try hashPassword(a, testing.io, "correct horse battery", test_cost);
    defer a.free(h);
    try testing.expect(std.mem.startsWith(u8, h, "$argon2id$"));
    try testing.expect(checkPassword(a, testing.io, h, "correct horse battery"));
    try testing.expect(!checkPassword(a, testing.io, h, "correct horse batterx"));
    try testing.expect(!checkPassword(a, testing.io, "not a hash", "x"));
    const p = randomPassword(testing.io);
    try testing.expect(!std.mem.eql(u8, &p, &randomPassword(testing.io)));
}

test "TOTP codes match RFC 6238 and are used once" {
    // RFC 6238 appendix B, SHA-1, secret "12345678901234567890" (8 digits
    // there; the last six are what a 6-digit app shows)
    const secret = "12345678901234567890";
    try testing.expectEqual(@as(u32, 287082), totpCode(secret, 59 / 30));
    try testing.expectEqual(@as(u32, 81804), totpCode(secret, 1111111109 / 30));
    try testing.expectEqual(@as(u32, 5924), totpCode(secret, 1234567890 / 30));
    try testing.expectEqual(@as(u32, 279037), totpCode(secret, 2000000000 / 30));

    const now: i64 = 1111111109;
    const step = totpVerify(secret, "081804", now, 0).?;
    try testing.expectEqual(@as(u64, 1111111109 / 30), step);
    // Not twice, not an older one, not a wrong one, not malformed
    try testing.expect(totpVerify(secret, "081804", now, step) == null);
    try testing.expect(totpVerify(secret, "081805", now, 0) == null);
    try testing.expect(totpVerify(secret, "81804", now, 0) == null);
    // One step of clock drift is fine, two are not
    try testing.expect(totpVerify(secret, "081804", now + 30, 0) != null);
    try testing.expect(totpVerify(secret, "081804", now + 61, 0) == null);
}

test "secret text and URI for the authenticator app" {
    const a = testing.allocator;
    const secret: [20]u8 = "12345678901234567890".*;
    // base32 of the RFC secret
    try testing.expectEqualStrings("GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ", &totpSecretText(secret));
    const uri = try totpUri(a, secret, "erdem");
    defer a.free(uri);
    try testing.expect(std.mem.startsWith(u8, uri, "otpauth://totp/termgate:erdem?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"));
}

test "session tokens are stored hashed" {
    const t = newToken(testing.io);
    try testing.expectEqual(@as(usize, 43), t.len);
    const h = tokenHash(&t);
    try testing.expectEqualSlices(u8, &h, &tokenHash(&t));
    try testing.expect(std.mem.indexOf(u8, &h, &t) == null);
}
