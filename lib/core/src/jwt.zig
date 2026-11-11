//! NATS JWT (v2): creation and verification.
//!
//! Format: base64url(header) "." base64url(claims) "." base64url(signature), unpadded.
//! The header is always {"typ":"JWT","alg":"ed25519-nkey"}. The signature is the
//! Ed25519 signature of "header.claims" by the issuer's (iss) nkey.
//! jti: unpadded base32 of the SHA-512/256 digest of the claims serialized
//! without jti. Compatible with nats-io/jwt v2.

const std = @import("std");
const nkeys = @import("nkeys.zig");

const b64 = std.base64.url_safe_no_pad;

pub const Error = error{
    InvalidToken,
    UnsupportedHeader,
    InvalidIssuer,
    InvalidSignature,
    Expired,
    NotYetValid,
};

const header_json = "{\"typ\":\"JWT\",\"alg\":\"ed25519-nkey\"}";
const algorithm = "ed25519-nkey";

/// Fields shared by all claim types plus the type-specific "nats" section.
pub fn Claims(comptime Nats: type) type {
    return struct {
        jti: ?[]const u8 = null,
        iat: i64 = 0,
        iss: []const u8 = "",
        name: ?[]const u8 = null,
        sub: []const u8,
        /// Audience (auth callout: server id, account name)
        aud: ?[]const u8 = null,
        exp: ?i64 = null,
        nbf: ?i64 = null,
        nats: Nats,
    };
}

/// Subject permissions (allow / deny lists).
pub const Permission = struct {
    allow: ?[]const []const u8 = null,
    deny: ?[]const []const u8 = null,
};

/// Lets a connection reply to requests it received on its subscriptions,
/// whatever the reply subject (nats-io/jwt ResponsePermission).
pub const ResponsePermission = struct {
    max: i64 = 1,
    /// Nanoseconds; 0 = no time limit
    ttl: i64 = 0,
};

/// The nats section of a user JWT. -1 = unlimited.
pub const UserNats = struct {
    @"pub": Permission = .{},
    sub: Permission = .{},
    subs: i64 = -1,
    data: i64 = -1,
    payload: i64 = -1,
    resp: ?ResponsePermission = null,
    /// Public key of the owning account when the user is signed by a signing key
    issuer_account: ?[]const u8 = null,
    type: []const u8 = "user",
    version: u8 = 2,
};

pub const UserClaims = Claims(UserNats);

/// The nats section of an operator JWT.
pub const OperatorNats = struct {
    /// Extra keys allowed to sign account JWTs
    signing_keys: ?[]const []const u8 = null,
    /// Public key of the system account
    system_account: ?[]const u8 = null,
    type: []const u8 = "operator",
    version: u8 = 2,
};

pub const OperatorClaims = Claims(OperatorNats);

/// Account limits. -1 = unlimited (the defaults of nats-io/jwt).
pub const AccountLimits = struct {
    subs: i64 = -1,
    data: i64 = -1,
    payload: i64 = -1,
    imports: i64 = -1,
    exports: i64 = -1,
    wildcards: bool = true,
    conn: i64 = -1,
    leaf: i64 = -1,
};

/// The nats section of an account JWT.
pub const AccountNats = struct {
    limits: AccountLimits = .{},
    /// Keys allowed to sign user JWTs for this account (besides the account key)
    signing_keys: ?[]const []const u8 = null,
    default_permissions: struct { @"pub": Permission = .{}, sub: Permission = .{} } = .{},
    type: []const u8 = "account",
    version: u8 = 2,
};

pub const AccountClaims = Claims(AccountNats);

const json_out: std.json.Stringify.Options = .{ .emit_null_optional_fields = false };

/// Signs the claims and returns the token. iss, iat and jti are filled in here.
/// The caller owns the returned memory.
pub fn encode(gpa: std.mem.Allocator, comptime T: type, claims: T, signer: nkeys.KeyPair, now: i64) ![]u8 {
    var c = claims;
    const iss = signer.publicKey().encode();
    c.iss = &iss;
    c.iat = now;
    c.jti = null;

    // jti: digest of the claims without jti
    const unhashed = try std.json.Stringify.valueAlloc(gpa, c, json_out);
    defer gpa.free(unhashed);
    var digest: [std.crypto.hash.sha2.Sha512_256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha512_256.hash(unhashed, &digest, .{});
    var jti: [52]u8 = undefined;
    base32NoPad(&jti, &digest);
    c.jti = &jti;

    const payload = try std.json.Stringify.valueAlloc(gpa, c, json_out);
    defer gpa.free(payload);

    const h_len = b64.Encoder.calcSize(header_json.len);
    const p_len = b64.Encoder.calcSize(payload.len);
    const s_len = b64.Encoder.calcSize(nkeys.signature_len);
    const out = try gpa.alloc(u8, h_len + 1 + p_len + 1 + s_len);
    errdefer gpa.free(out);

    _ = b64.Encoder.encode(out[0..h_len], header_json);
    out[h_len] = '.';
    _ = b64.Encoder.encode(out[h_len + 1 ..][0..p_len], payload);
    const sig = try signer.sign(out[0 .. h_len + 1 + p_len]);
    out[h_len + 1 + p_len] = '.';
    _ = b64.Encoder.encode(out[h_len + 1 + p_len + 1 ..], &sig);
    return out;
}

/// Verifies the token and decodes its claims: header, iss being a valid nkey,
/// signature, exp and nbf (against now). Checking who the issuer must be is
/// the caller's job (the iss field of the returned claims).
pub fn decode(gpa: std.mem.Allocator, comptime T: type, token: []const u8, now: i64) !std.json.Parsed(T) {
    return decodeLeeway(gpa, T, token, now, 0);
}

/// Like decode, but exp and nbf are allowed to be off by up to `leeway`
/// seconds (clock skew on devices without NTP).
pub fn decodeLeeway(gpa: std.mem.Allocator, comptime T: type, token: []const u8, now: i64, leeway: i64) !std.json.Parsed(T) {
    var parts = std.mem.splitScalar(u8, token, '.');
    const h_text = parts.next() orelse return error.InvalidToken;
    const p_text = parts.next() orelse return error.InvalidToken;
    const s_text = parts.next() orelse return error.InvalidToken;
    if (parts.next() != null) return error.InvalidToken;

    // Header
    {
        const raw = try decodeB64(gpa, h_text);
        defer gpa.free(raw);
        const H = struct { typ: []const u8 = "", alg: []const u8 = "" };
        const h = std.json.parseFromSlice(H, gpa, raw, .{ .ignore_unknown_fields = true }) catch |e| return jsonError(e);
        defer h.deinit();
        if (!std.ascii.eqlIgnoreCase(h.value.typ, "JWT") or !std.mem.eql(u8, h.value.alg, algorithm))
            return error.UnsupportedHeader;
    }

    // Claims
    const raw = try decodeB64(gpa, p_text);
    defer gpa.free(raw);
    const parsed = std.json.parseFromSlice(T, gpa, raw, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch |e| return jsonError(e);
    errdefer parsed.deinit();
    const c = parsed.value;

    // Signature
    const issuer = nkeys.PublicKey.decode(c.iss) catch return error.InvalidIssuer;
    const sig_len = b64.Decoder.calcSizeForSlice(s_text) catch return error.InvalidToken;
    if (sig_len != nkeys.signature_len) return error.InvalidToken;
    var sig: [nkeys.signature_len]u8 = undefined;
    b64.Decoder.decode(&sig, s_text) catch return error.InvalidToken;
    issuer.verify(token[0 .. h_text.len + 1 + p_text.len], sig) catch return error.InvalidSignature;

    // Validity period
    if (c.exp) |exp| if (now - leeway >= exp) return error.Expired;
    if (c.nbf) |nbf| if (now + leeway < nbf) return error.NotYetValid;

    return parsed;
}

/// Out of memory stays as is; any other JSON error means a malformed token.
fn jsonError(e: anyerror) error{ OutOfMemory, InvalidToken } {
    return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidToken;
}

fn decodeB64(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    const n = b64.Decoder.calcSizeForSlice(text) catch return error.InvalidToken;
    const buf = try gpa.alloc(u8, n);
    errdefer gpa.free(buf);
    b64.Decoder.decode(buf, text) catch return error.InvalidToken;
    return buf;
}

fn base32NoPad(out: []u8, data: []const u8) void {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
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
    if (bits > 0) {
        out[o] = alphabet[(acc << (5 - bits)) & 31];
        o += 1;
    }
    std.debug.assert(o == out.len);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn testSeed() [32]u8 {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(i);
    return s;
}

/// Generated with nats-io/jwt v2.8.1: issuer account and subject user, both from
/// seed 0x00..0x1f; name "ali", exp 4102444800 (2100), pub "in.gw17.>",
/// sub "out.gw17.>" and "_INBOX.>".
const go_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJleHAiOjQxMDI0NDQ4MDAsImp0aSI6IjVQRkJVTUJaVEZDTlZCQVVXSFQyR0VYSE9TR05RUjIySVM1Vkk1WlhNNVk3N1JQRFFLV0EiLCJpYXQiOjE3OTQyODkwNTcsImlzcyI6IkFBQjJDQjU3NlBIQkJQUTVPRE9SUloyTFlDTVdQWkdXR0NOMktESzdEWE9JTVpBU0tVWTNRUFpWIiwibmFtZSI6ImFsaSIsInN1YiI6IlVBQjJDQjU3NlBIQkJQUTVPRE9SUloyTFlDTVdQWkdXR0NOMktESzdEWE9JTVpBU0tVWTNSTEtLIiwibmF0cyI6eyJwdWIiOnsiYWxsb3ciOlsiaW4uZ3cxNy5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJvdXQuZ3cxNy5cdTAwM2UiLCJfSU5CT1guXHUwMDNlIl19LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.IpFHCYFro72k1l4MywADuNYl7cxwVEj4xoX2kpZbNOKLOr17T-b868H-quJESaQUTHxKrXZJDBX-jZ35zGUlBA";
const account_pub = "AAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3QPZV";
const user_pub = "UAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3RLKK";
const now_2026: i64 = 1794289057;

test "user JWT produced by nats-io/jwt verifies" {
    const p = try decode(testing.allocator, UserClaims, go_token, now_2026);
    defer p.deinit();
    const c = p.value;
    try testing.expectEqualStrings(account_pub, c.iss);
    try testing.expectEqualStrings(user_pub, c.sub);
    try testing.expectEqualStrings("ali", c.name.?);
    try testing.expectEqual(@as(?i64, 4102444800), c.exp);
    try testing.expectEqualStrings("in.gw17.>", c.nats.@"pub".allow.?[0]);
    try testing.expectEqualStrings("_INBOX.>", c.nats.sub.allow.?[1]);
    try testing.expectEqualStrings("user", c.nats.type);
    try testing.expectEqual(@as(u8, 2), c.nats.version);
}

test "tampered, expired and malformed tokens are rejected" {
    const a = testing.allocator;
    // Change the claims (name "ali" -> "ala") but keep the original signature
    var parts = std.mem.splitScalar(u8, go_token, '.');
    const h = parts.next().?;
    const p = parts.next().?;
    const s = parts.next().?;
    const claims = try decodeB64(a, p);
    defer a.free(claims);
    const i = std.mem.indexOf(u8, claims, "\"ali\"").?;
    claims[i + 3] = 'a';
    var p2: [1024]u8 = undefined;
    const p2_text = b64.Encoder.encode(&p2, claims);
    const forged = try std.mem.join(a, ".", &.{ h, p2_text, s });
    defer a.free(forged);
    try testing.expectError(error.InvalidSignature, decode(a, UserClaims, forged, now_2026));

    try testing.expectError(error.Expired, decode(a, UserClaims, go_token, 4102444800));
    try testing.expectError(error.InvalidToken, decode(a, UserClaims, "a.b", now_2026));
    try testing.expectError(error.InvalidToken, decode(a, UserClaims, "a.b.c.d", now_2026));
}

test "encode/decode round trip, nbf and issuer" {
    const a = testing.allocator;
    const account = try nkeys.KeyPair.fromRawSeed(.account, testSeed());
    const user = try nkeys.KeyPair.fromRawSeed(.user, testSeed());
    const upub = user.publicKey().encode();

    const tok = try encode(a, UserClaims, .{
        .name = "bot-1",
        .sub = &upub,
        .exp = now_2026 + 3600,
        .nbf = now_2026 - 60,
        .nats = .{
            .@"pub" = .{ .allow = &.{"in.gw17.>"} },
            .sub = .{ .allow = &.{ "out.gw17.>", "_INBOX.>" } },
        },
    }, account, now_2026);
    defer a.free(tok);

    const p = try decode(a, UserClaims, tok, now_2026);
    defer p.deinit();
    try testing.expectEqualStrings(account_pub, p.value.iss);
    try testing.expectEqualStrings(user_pub, p.value.sub);
    try testing.expectEqual(now_2026, p.value.iat);
    try testing.expectEqual(@as(usize, 52), p.value.jti.?.len);
    try testing.expectEqualStrings("out.gw17.>", p.value.nats.sub.allow.?[0]);

    try testing.expectError(error.NotYetValid, decode(a, UserClaims, tok, now_2026 - 120));
    try testing.expectError(error.Expired, decode(a, UserClaims, tok, now_2026 + 3600));
}

test "no leaks on allocation failures" {
    const run = struct {
        fn f(a: std.mem.Allocator) !void {
            const p = try decode(a, UserClaims, go_token, now_2026);
            p.deinit();
        }
    }.f;
    try testing.checkAllAllocationFailures(testing.allocator, run, .{});
}
