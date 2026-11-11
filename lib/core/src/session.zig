//! Session open requests: proof that the requester holds the user key.
//!
//! NATS does not tell a subscriber who published a message, so tgterm signs
//! each request with the user's key, over the node name, a timestamp, a
//! random nonce and its session public key. tgnode verifies the signature,
//! that the timestamp is fresh, and that the nonce was not seen before
//! (ReplayCache); then termgate decides, from its database, whether this
//! user may open a session on this node (approval.zig). The request carries
//! nothing else: no permission travels with the user.
//!
//! The session public key is for end-to-end encryption (e2e.zig); being
//! signed, the relay cannot replace it.
//!
//! Wire format (JSON, sent to session.open.<node>):
//!   {"user":"U...","node":"gw17","ts":1794289057,"nonce":"<22 chars>",
//!    "kx":"<43 chars>","sig":"<base64url>"}
//! Signed text: "termgate-session-v3\n" node "\n" ts "\n" nonce "\n" kx "\n" user

const std = @import("std");
const nkeys = @import("nkeys.zig");

const b64 = std.base64.url_safe_no_pad;
const context = "termgate-session-v3";
const nonce_bytes = 16;
const nonce_len = 22; // base64url of 16 bytes

/// Clock skew tolerated between tgterm and tgnode (seconds)
pub const default_leeway: i64 = 5 * 60;

pub const Error = error{
    InvalidRequest,
    WrongNode,
    StaleRequest,
    Replay,
    ReplayCacheFull,
    InvalidSignature,
};

const Request = struct {
    /// The user's public key ("U...")
    user: []const u8,
    node: []const u8,
    ts: i64,
    nonce: []const u8,
    /// tgterm's session public key (e2e.Ephemeral.publicText)
    kx: []const u8,
    sig: []const u8,
};

fn signedText(gpa: std.mem.Allocator, r: Request) ![]u8 {
    return std.fmt.allocPrint(gpa, context ++ "\n{s}\n{d}\n{s}\n{s}\n{s}", .{ r.node, r.ts, r.nonce, r.kx, r.user });
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

/// Builds a signed session request (tgterm side); `kx` is tgterm's session
/// public key (base64url).
pub fn create(gpa: std.mem.Allocator, io: std.Io, user: nkeys.KeyPair, node: []const u8, kx: []const u8, now: i64) !Created {
    var raw_nonce: [nonce_bytes]u8 = undefined;
    io.random(&raw_nonce);
    var nonce: [nonce_len]u8 = undefined;
    _ = b64.Encoder.encode(&nonce, &raw_nonce);

    const upub = user.publicKey().encode();
    var r: Request = .{ .user = &upub, .node = node, .ts = now, .nonce = &nonce, .kx = kx, .sig = "" };
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
    /// This node's name
    node: []const u8,
    now: i64,
    leeway: i64 = default_leeway,
    replay: *ReplayCache,
};

/// A verified session request: who asks, the nonce (which the approval must
/// echo) and tgterm's session public key.
pub const Verified = struct {
    user: []u8,
    nonce: []u8,
    /// tgterm's session public key (base64url)
    kx: []u8,
    gpa: std.mem.Allocator,

    pub fn deinit(v: Verified) void {
        v.gpa.free(v.user);
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

    // Proof of possession: signed by the user's key
    const user = nkeys.PublicKey.decode(r.user) catch return error.InvalidSignature;
    if (user.prefix != .user) return error.InvalidSignature;
    var sig: [nkeys.signature_len]u8 = undefined;
    const sig_len = b64.Decoder.calcSizeForSlice(r.sig) catch return error.InvalidRequest;
    if (sig_len != sig.len) return error.InvalidRequest;
    b64.Decoder.decode(&sig, r.sig) catch return error.InvalidRequest;
    const text = try signedText(gpa, r);
    defer gpa.free(text);
    user.verify(text, sig) catch return error.InvalidSignature;

    // Only a correctly signed request may consume a nonce
    const who = try gpa.dupe(u8, r.user);
    errdefer gpa.free(who);
    const nonce = try gpa.dupe(u8, r.nonce);
    errdefer gpa.free(nonce);
    const kx = try gpa.dupe(u8, r.kx);
    errdefer gpa.free(kx);
    try expect.replay.use(r.nonce, r.ts + expect.leeway, expect.now);
    return .{ .user = who, .nonce = nonce, .kx = kx, .gpa = gpa };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

fn userKey() !nkeys.KeyPair {
    return nkeys.KeyPair.fromRawSeed(.user, @splat(2));
}

fn expectAt(cache: *ReplayCache) Expect {
    return .{ .node = "gw17", .now = t0, .replay = cache };
}

test "signed request verifies once, replay is rejected" {
    const a = testing.allocator;
    var cache = ReplayCache.init(a);
    defer cache.deinit();
    const user = try userKey();

    const c = try create(a, testing.io, user, "gw17", "KX", t0);
    defer c.deinit(a);
    const v = try verify(a, c.body, expectAt(&cache));
    defer v.deinit();
    try testing.expectEqualStrings(&user.publicKey().encode(), v.user);
    try testing.expectEqual(@as(usize, 22), v.nonce.len);

    try testing.expectError(error.Replay, verify(a, c.body, expectAt(&cache)));
}

test "a request for someone else's key is rejected" {
    const a = testing.allocator;
    var cache = ReplayCache.init(a);
    defer cache.deinit();
    const user = try userKey();

    // An attacker signs with its own key and puts the user's key in
    const attacker = try nkeys.KeyPair.fromRawSeed(.user, @splat(9));
    const c = try create(a, testing.io, attacker, "gw17", "KX", t0);
    defer c.deinit(a);
    const upub = user.publicKey().encode();
    const apub = attacker.publicKey().encode();
    const forged = try std.mem.replaceOwned(u8, a, c.body, &apub, &upub);
    defer a.free(forged);
    try testing.expectError(error.InvalidSignature, verify(a, forged, expectAt(&cache)));
    // The failed attempt does not consume anything
    try testing.expectEqual(@as(u32, 0), cache.seen.count());
}

test "wrong node and stale timestamp are rejected" {
    const a = testing.allocator;
    var cache = ReplayCache.init(a);
    defer cache.deinit();
    const user = try userKey();

    const other = try create(a, testing.io, user, "gw20", "KX", t0);
    defer other.deinit(a);
    try testing.expectError(error.WrongNode, verify(a, other.body, expectAt(&cache)));

    const old = try create(a, testing.io, user, "gw17", "KX", t0 - default_leeway - 1);
    defer old.deinit(a);
    try testing.expectError(error.StaleRequest, verify(a, old.body, expectAt(&cache)));

    try testing.expectError(error.InvalidRequest, verify(a, "{}", expectAt(&cache)));
}

test "tampered request fields break the signature" {
    const a = testing.allocator;
    var cache = ReplayCache.init(a);
    defer cache.deinit();
    const user = try userKey();

    const c = try create(a, testing.io, user, "gw17", "KX", t0);
    defer c.deinit(a);
    // Shift the timestamp by one second
    const ts = try std.fmt.allocPrint(a, "\"ts\":{d}", .{t0});
    defer a.free(ts);
    const ts2 = try std.fmt.allocPrint(a, "\"ts\":{d}", .{t0 + 1});
    defer a.free(ts2);
    const forged = try std.mem.replaceOwned(u8, a, c.body, ts, ts2);
    defer a.free(forged);
    try testing.expectError(error.InvalidSignature, verify(a, forged, expectAt(&cache)));
    // The relay swaps in its own session key: the signature breaks
    const swapped = try std.mem.replaceOwned(u8, a, c.body, "\"kx\":\"KX\"", "\"kx\":\"RELAY\"");
    defer a.free(swapped);
    try testing.expect(!std.mem.eql(u8, swapped, c.body));
    try testing.expectError(error.InvalidSignature, verify(a, swapped, expectAt(&cache)));
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
    const user = try userKey();
    const c = try create(a, testing.io, user, "gw17", "KX", t0);
    defer c.deinit(a);

    const run = struct {
        fn run(alloc: std.mem.Allocator, b: []const u8) !void {
            var cache = ReplayCache.init(alloc);
            defer cache.deinit();
            (try verify(alloc, b, expectAt(&cache))).deinit();
        }
    }.run;
    try testing.checkAllAllocationFailures(a, run, .{c.body});
}
