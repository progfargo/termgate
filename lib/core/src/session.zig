//! Session open requests: proof that the requester holds the grant's user key.
//!
//! NATS does not tell a subscriber who published a message, so a grant alone
//! would let anyone who saw it open a session. tgterm therefore signs each
//! request with the user key named in the grant's sub, over the node name, a
//! timestamp, a random nonce and the grant. tgnode verifies the grant, the
//! signature, that the timestamp is fresh, and that the nonce was not seen
//! before (ReplayCache). This adapts farlogin's per-session jti replay check.
//!
//! The request also carries tgterm's session public key for end-to-end
//! encryption (e2e.zig); being signed, the relay cannot replace it.
//!
//! Wire format (JSON, sent to session.open.<node>):
//!   {"grant":"<jwt>","node":"gw17","ts":1794289057,"nonce":"<22 chars>",
//!    "kx":"<43 chars>","sig":"<base64url>"}
//! Signed text: "termgate-session-v2\n" node "\n" ts "\n" nonce "\n" kx "\n" grant

const std = @import("std");
const nkeys = @import("nkeys.zig");
const grant = @import("grant.zig");

const b64 = std.base64.url_safe_no_pad;
const context = "termgate-session-v2";
const nonce_bytes = 16;
const nonce_len = 22; // base64url of 16 bytes

pub const Error = error{
    InvalidRequest,
    WrongNode,
    StaleRequest,
    Replay,
    ReplayCacheFull,
    InvalidSignature,
};

const Request = struct {
    grant: []const u8,
    node: []const u8,
    ts: i64,
    nonce: []const u8,
    /// tgterm's session public key (e2e.Ephemeral.publicText)
    kx: []const u8,
    sig: []const u8,
};

fn signedText(gpa: std.mem.Allocator, r: Request) ![]u8 {
    return std.fmt.allocPrint(gpa, context ++ "\n{s}\n{d}\n{s}\n{s}\n{s}", .{ r.node, r.ts, r.nonce, r.kx, r.grant });
}

pub const Created = struct {
    /// The request (JSON)
    body: []u8,
    /// Its nonce, which termgate's approval echoes
    nonce: [nonce_len]u8,

    pub fn deinit(c: Created, gpa: std.mem.Allocator) void {
        gpa.free(c.body);
    }
};

/// Builds a signed session request (tgterm side). `user` must be the key named
/// in the grant's sub; `kx` is tgterm's session public key (base64url).
pub fn create(gpa: std.mem.Allocator, io: std.Io, user: nkeys.KeyPair, grant_token: []const u8, node: []const u8, kx: []const u8, now: i64) !Created {
    var raw_nonce: [nonce_bytes]u8 = undefined;
    io.random(&raw_nonce);
    var nonce: [nonce_len]u8 = undefined;
    _ = b64.Encoder.encode(&nonce, &raw_nonce);

    var r: Request = .{ .grant = grant_token, .node = node, .ts = now, .nonce = &nonce, .kx = kx, .sig = "" };
    const text = try signedText(gpa, r);
    defer gpa.free(text);
    const sig = try user.sign(text);
    var sig_text: [b64.Encoder.calcSize(nkeys.signature_len)]u8 = undefined;
    _ = b64.Encoder.encode(&sig_text, &sig);
    r.sig = &sig_text;
    return .{ .body = try std.json.Stringify.valueAlloc(gpa, r, .{}), .nonce = nonce };
}

/// Nonces seen within the freshness window. Bounded: entries are dropped once
/// their window has passed, and new requests are refused when it is full.
pub const ReplayCache = struct {
    gpa: std.mem.Allocator,
    /// nonce -> time after which it can be forgotten
    seen: std.StringHashMapUnmanaged(i64) = .empty,
    max_entries: usize = 10_000,

    pub fn init(gpa: std.mem.Allocator) ReplayCache {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *ReplayCache) void {
        var it = self.seen.keyIterator();
        while (it.next()) |k| self.gpa.free(k.*);
        self.seen.deinit(self.gpa);
    }

    fn sweep(self: *ReplayCache, now: i64) void {
        var it = self.seen.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.* < now) {
                const key = e.key_ptr.*;
                self.seen.removeByPtr(e.key_ptr);
                self.gpa.free(key);
                it = self.seen.iterator(); // removal invalidates the iterator
            }
        }
    }

    /// Records the nonce; fails if it was already used.
    pub fn use(self: *ReplayCache, nonce: []const u8, forget_after: i64, now: i64) !void {
        if (self.seen.contains(nonce)) return error.Replay;
        if (self.seen.count() >= self.max_entries) self.sweep(now);
        if (self.seen.count() >= self.max_entries) return error.ReplayCacheFull;
        const key = try self.gpa.dupe(u8, nonce);
        errdefer self.gpa.free(key);
        try self.seen.put(self.gpa, key, forget_after);
    }
};

pub const Expect = struct {
    /// Trusted account keys (see grant.Expect)
    issuers: []const []const u8,
    /// This node's name
    node: []const u8,
    now: i64,
    leeway: i64 = grant.default_leeway,
    replay: *ReplayCache,
};

/// A verified session request: the grant and the request's nonce (which the
/// approval must echo).
pub const Verified = struct {
    grant: std.json.Parsed(grant.GrantClaims),
    /// The grant as sent (JWT), for forwarding to termgate
    grant_token: []u8,
    nonce: []u8,
    /// tgterm's session public key (base64url)
    kx: []u8,
    gpa: std.mem.Allocator,

    pub fn deinit(v: Verified) void {
        v.grant.deinit();
        v.gpa.free(v.grant_token);
        v.gpa.free(v.nonce);
        v.gpa.free(v.kx);
    }
};

/// Verifies a session request (tgnode side). The caller frees the result with
/// deinit().
pub fn verify(gpa: std.mem.Allocator, body: []const u8, expect: Expect) !Verified {
    const req = std.json.parseFromSlice(Request, gpa, body, .{ .ignore_unknown_fields = true }) catch |e|
        return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidRequest;
    defer req.deinit();
    const r = req.value;

    if (!std.mem.eql(u8, r.node, expect.node)) return error.WrongNode;
    if (@abs(expect.now - r.ts) > expect.leeway) return error.StaleRequest;
    if (r.nonce.len != nonce_len) return error.InvalidRequest;

    const g = try grant.verify(gpa, r.grant, .{
        .issuers = expect.issuers,
        .node = expect.node,
        .user = null,
        .now = expect.now,
        .leeway = expect.leeway,
    });
    errdefer g.deinit();

    // Proof of possession: signed by the grant's user
    const user = nkeys.PublicKey.decode(g.value.sub) catch return error.InvalidSignature;
    if (user.prefix != .user) return error.InvalidSignature;
    var sig: [nkeys.signature_len]u8 = undefined;
    const sig_len = b64.Decoder.calcSizeForSlice(r.sig) catch return error.InvalidRequest;
    if (sig_len != sig.len) return error.InvalidRequest;
    b64.Decoder.decode(&sig, r.sig) catch return error.InvalidRequest;
    const text = try signedText(gpa, r);
    defer gpa.free(text);
    user.verify(text, sig) catch return error.InvalidSignature;

    // Only a correctly signed request may consume a nonce
    const nonce = try gpa.dupe(u8, r.nonce);
    errdefer gpa.free(nonce);
    const token = try gpa.dupe(u8, r.grant);
    errdefer gpa.free(token);
    const kx = try gpa.dupe(u8, r.kx);
    errdefer gpa.free(kx);
    try expect.replay.use(r.nonce, r.ts + expect.leeway, expect.now);
    return .{ .grant = g, .grant_token = token, .nonce = nonce, .kx = kx, .gpa = gpa };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

const Fixture = struct {
    account: nkeys.KeyPair,
    account_pub: [nkeys.public_len]u8,
    user: nkeys.KeyPair,
    user_pub: [nkeys.public_len]u8,
    token: []u8,

    fn init(a: std.mem.Allocator) !Fixture {
        const account = try nkeys.KeyPair.fromRawSeed(.account, @splat(1));
        const user = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
        var f: Fixture = .{
            .account = account,
            .account_pub = account.publicKey().encode(),
            .user = user,
            .user_pub = user.publicKey().encode(),
            .token = undefined,
        };
        f.token = try grant.issue(a, account, .{
            .user = &f.user_pub,
            .nodes = &.{"gw17"},
            .exp = t0 + 3600,
        }, t0);
        return f;
    }

    fn deinit(self: *Fixture, a: std.mem.Allocator) void {
        a.free(self.token);
    }

    fn expect(self: *const Fixture, cache: *ReplayCache) Expect {
        return .{ .issuers = &.{&self.account_pub}, .node = "gw17", .now = t0, .replay = cache };
    }
};

test "signed request verifies once, replay is rejected" {
    const a = testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var cache = ReplayCache.init(a);
    defer cache.deinit();

    const body_c = try create(a, testing.io, f.user, f.token, "gw17", "KX", t0);
    defer body_c.deinit(a);
    const body = body_c.body;

    const v = try verify(a, body, f.expect(&cache));
    defer v.deinit();
    try testing.expectEqualStrings(&f.user_pub, v.grant.value.sub);
    try testing.expectEqual(@as(usize, 22), v.nonce.len);

    try testing.expectError(error.Replay, verify(a, body, f.expect(&cache)));
}

test "a grant sent by someone without the user key is rejected" {
    const a = testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var cache = ReplayCache.init(a);
    defer cache.deinit();

    // Attacker saw the grant and signs with their own user key
    const attacker = try nkeys.KeyPair.fromRawSeed(.user, @splat(9));
    const body_c = try create(a, testing.io, attacker, f.token, "gw17", "KX", t0);
    defer body_c.deinit(a);
    const body = body_c.body;
    try testing.expectError(error.InvalidSignature, verify(a, body, f.expect(&cache)));
    // The failed attempt does not consume anything
    try testing.expectEqual(@as(u32, 0), cache.seen.count());
}

test "wrong node and stale timestamp are rejected" {
    const a = testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var cache = ReplayCache.init(a);
    defer cache.deinit();

    const other_c = try create(a, testing.io, f.user, f.token, "gw20", "KX", t0);
    defer other_c.deinit(a);
    const other = other_c.body;
    try testing.expectError(error.WrongNode, verify(a, other, f.expect(&cache)));

    const old_c = try create(a, testing.io, f.user, f.token, "gw17", "KX", t0 - grant.default_leeway - 1);
    defer old_c.deinit(a);
    const old = old_c.body;
    try testing.expectError(error.StaleRequest, verify(a, old, f.expect(&cache)));

    try testing.expectError(error.InvalidRequest, verify(a, "{}", f.expect(&cache)));
}

test "tampered request fields break the signature" {
    const a = testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    var cache = ReplayCache.init(a);
    defer cache.deinit();

    const body_c = try create(a, testing.io, f.user, f.token, "gw17", "KX", t0);
    defer body_c.deinit(a);
    const body = body_c.body;
    // Shift the timestamp by one second
    const ts = try std.fmt.allocPrint(a, "\"ts\":{d}", .{t0});
    defer a.free(ts);
    const ts2 = try std.fmt.allocPrint(a, "\"ts\":{d}", .{t0 + 1});
    defer a.free(ts2);
    const forged = try std.mem.replaceOwned(u8, a, body, ts, ts2);
    defer a.free(forged);
    try testing.expectError(error.InvalidSignature, verify(a, forged, f.expect(&cache)));
    // The relay swaps in its own session key: the signature breaks
    const swapped = try std.mem.replaceOwned(u8, a, body, "\"kx\":\"KX\"", "\"kx\":\"RELAY\"");
    defer a.free(swapped);
    try testing.expect(!std.mem.eql(u8, swapped, body));
    try testing.expectError(error.InvalidSignature, verify(a, swapped, f.expect(&cache)));
}

test "replay cache forgets expired nonces and stays bounded" {
    const a = testing.allocator;
    var cache = ReplayCache.init(a);
    defer cache.deinit();
    cache.max_entries = 2;

    try cache.use("n1", t0 + 10, t0);
    try cache.use("n2", t0 + 100, t0);
    try testing.expectError(error.ReplayCacheFull, cache.use("n3", t0 + 100, t0));
    // After n1's window has passed it is swept and there is room again
    try cache.use("n3", t0 + 100, t0 + 11);
    try testing.expectError(error.Replay, cache.use("n2", t0 + 100, t0 + 11));
}

test "no leaks on allocation failures" {
    const a = testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit(a);
    const body_c = try create(a, testing.io, f.user, f.token, "gw17", "KX", t0);
    defer body_c.deinit(a);
    const body = body_c.body;

    const run = struct {
        fn run(alloc: std.mem.Allocator, b: []const u8, fx: *const Fixture) !void {
            var cache = ReplayCache.init(alloc);
            defer cache.deinit();
            (try verify(alloc, b, fx.expect(&cache))).deinit();
        }
    }.run;
    try testing.checkAllAllocationFailures(a, run, .{ body, &f });
}
