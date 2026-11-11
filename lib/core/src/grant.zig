//! Grants: account-signed permission for one user (or bot) to open terminal
//! sessions on the nodes matching a set of name patterns, as a given Unix user,
//! until a time and/or a limited number of times.
//!
//! A grant is a NATS-style JWT (see jwt.zig) whose "nats" section has
//! type "grant". The type keeps a grant from being accepted as a user JWT and
//! vice versa. termgate issues grants with the account signing key; tgnode
//! verifies them offline against the trusted account keys.
//!
//! The use counter (max_uses) is not kept in the grant; termgate counts uses
//! by the grant's jti when it approves a session.

const std = @import("std");
const nkeys = @import("nkeys.zig");
const jwt = @import("jwt.zig");
const node_name = @import("node.zig");

pub const Kind = enum { human, bot };

pub const GrantNats = struct {
    type: []const u8 = "grant",
    version: u8 = 1,
    kind: Kind = .human,
    /// Node name patterns the grant covers (glob: * any run, ? one character)
    nodes: []const []const u8,
    /// Unix user the shell runs as on the node
    run_as: []const u8,
    /// Number of sessions allowed; null = unlimited
    max_uses: ?u32 = null,
};

pub const GrantClaims = jwt.Claims(GrantNats);

/// Default clock skew tolerance (seconds).
pub const default_leeway: i64 = 5 * 60;

pub const Error = error{
    /// The signer is not an account key
    InvalidSigner,
    /// Missing or invalid field when issuing
    InvalidSpec,
    /// The token is a JWT but not a grant
    NotAGrant,
    UntrustedIssuer,
    WrongUser,
    NodeNotAllowed,
};

/// What termgate puts into a new grant.
pub const Spec = struct {
    /// Public key of the user or bot ("U...")
    user: []const u8,
    name: ?[]const u8 = null,
    kind: Kind = .human,
    nodes: []const []const u8,
    run_as: []const u8,
    max_uses: ?u32 = null,
    nbf: ?i64 = null,
    /// Expiry; a grant needs exp, max_uses or both
    exp: ?i64 = null,
};

/// Signs a new grant with an account key (identity or signing key).
/// The caller owns the returned token.
pub fn issue(gpa: std.mem.Allocator, signer: nkeys.KeyPair, spec: Spec, now: i64) ![]u8 {
    if (signer.prefix != .account) return error.InvalidSigner;
    const user = nkeys.PublicKey.decode(spec.user) catch return error.InvalidSpec;
    if (user.prefix != .user) return error.InvalidSpec;
    if (spec.nodes.len == 0 or spec.run_as.len == 0) return error.InvalidSpec;
    for (spec.nodes) |p| if (!node_name.isValidPattern(p)) return error.InvalidSpec;
    if (spec.exp == null and spec.max_uses == null) return error.InvalidSpec;
    if (spec.exp) |exp| if (exp <= now) return error.InvalidSpec;
    if (spec.max_uses) |m| if (m == 0) return error.InvalidSpec;

    return jwt.encode(gpa, GrantClaims, .{
        .name = spec.name,
        .sub = spec.user,
        .nbf = spec.nbf,
        .exp = spec.exp,
        .nats = .{
            .kind = spec.kind,
            .nodes = spec.nodes,
            .run_as = spec.run_as,
            .max_uses = spec.max_uses,
        },
    }, signer, now);
}

/// What tgnode checks a grant against.
pub const Expect = struct {
    /// Trusted issuers: the account's identity key and its signing keys
    issuers: []const []const u8,
    /// This node's name
    node: []const u8,
    /// The user the grant must belong to ("U..."); null = any user (the caller
    /// then checks proof of possession for the grant's sub, see session.zig)
    user: ?[]const u8,
    now: i64,
    leeway: i64 = default_leeway,
};

/// Verifies a grant: signature, validity window (with leeway), type, issuer,
/// user and node. The caller frees the result with deinit().
pub fn verify(gpa: std.mem.Allocator, token: []const u8, expect: Expect) !std.json.Parsed(GrantClaims) {
    const parsed = try jwt.decodeLeeway(gpa, GrantClaims, token, expect.now, expect.leeway);
    errdefer parsed.deinit();
    const c = parsed.value;

    if (!std.mem.eql(u8, c.nats.type, "grant")) return error.NotAGrant;
    if (c.exp == null and c.nats.max_uses == null) return error.NotAGrant;

    for (expect.issuers) |i| {
        if (std.mem.eql(u8, i, c.iss)) break;
    } else return error.UntrustedIssuer;

    if (expect.user) |u| if (!std.mem.eql(u8, c.sub, u)) return error.WrongUser;

    for (c.nats.nodes) |pattern| {
        if (globMatch(pattern, expect.node)) break;
    } else return error.NodeNotAllowed;

    return parsed;
}

/// Glob match on node names: * matches any run of characters (also empty),
/// ? matches exactly one. No character classes or escapes.
pub fn globMatch(pattern: []const u8, name: []const u8) bool {
    var p: usize = 0;
    var n: usize = 0;
    // Position after the last * and the name position it was tried at
    var star: ?usize = null;
    var star_n: usize = 0;
    while (n < name.len) {
        if (p < pattern.len and (pattern[p] == '?' or pattern[p] == name[n])) {
            p += 1;
            n += 1;
        } else if (p < pattern.len and pattern[p] == '*') {
            star = p + 1;
            star_n = n;
            p += 1;
        } else if (star) |s| {
            // Let the last * swallow one more character
            star_n += 1;
            n = star_n;
            p = s;
        } else return false;
    }
    while (p < pattern.len and pattern[p] == '*') p += 1;
    return p == pattern.len;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

fn seed(b: u8) [32]u8 {
    return @splat(b);
}

const Fixture = struct {
    account: nkeys.KeyPair,
    account_pub: [nkeys.public_len]u8,
    user: nkeys.KeyPair,
    user_pub: [nkeys.public_len]u8,

    fn init() !Fixture {
        const account = try nkeys.KeyPair.fromRawSeed(.account, seed(1));
        const user = try nkeys.KeyPair.fromRawSeed(.user, seed(2));
        return .{
            .account = account,
            .account_pub = account.publicKey().encode(),
            .user = user,
            .user_pub = user.publicKey().encode(),
        };
    }

    fn spec(self: *const Fixture) Spec {
        return .{
            .user = &self.user_pub,
            .name = "ali",
            .nodes = &.{ "gw17", "pump??", "ist_*_gw" },
            .run_as = "root",
            .max_uses = 3,
            .exp = t0 + 3600,
        };
    }

    fn expect(self: *const Fixture, node: []const u8) Expect {
        return .{ .issuers = &.{&self.account_pub}, .node = node, .user = &self.user_pub, .now = t0 };
    }
};

test "issue and verify a grant" {
    const f = try Fixture.init();
    const tok = try issue(testing.allocator, f.account, f.spec(), t0);
    defer testing.allocator.free(tok);

    const p = try verify(testing.allocator, tok, f.expect("pump07"));
    defer p.deinit();
    const c = p.value;
    try testing.expectEqualStrings(&f.account_pub, c.iss);
    try testing.expectEqualStrings(&f.user_pub, c.sub);
    try testing.expectEqual(Kind.human, c.nats.kind);
    try testing.expectEqualStrings("root", c.nats.run_as);
    try testing.expectEqual(@as(?u32, 3), c.nats.max_uses);
    try testing.expectEqual(@as(usize, 3), c.nats.nodes.len);
    try testing.expectEqual(@as(usize, 52), c.jti.?.len);
}

test "wrong node, user or issuer is rejected" {
    const a = testing.allocator;
    const f = try Fixture.init();
    const tok = try issue(a, f.account, f.spec(), t0);
    defer a.free(tok);

    try testing.expectError(error.NodeNotAllowed, verify(a, tok, f.expect("gw99")));
    try testing.expectError(error.NodeNotAllowed, verify(a, tok, f.expect("pump123")));
    (try verify(a, tok, f.expect("ist_kadikoy_gw"))).deinit();

    const other_user = (try nkeys.KeyPair.fromRawSeed(.user, seed(3))).publicKey().encode();
    var e = f.expect("gw17");
    e.user = &other_user;
    try testing.expectError(error.WrongUser, verify(a, tok, e));

    const other_account = try nkeys.KeyPair.fromRawSeed(.account, seed(4));
    const foreign = try issue(a, other_account, f.spec(), t0);
    defer a.free(foreign);
    try testing.expectError(error.UntrustedIssuer, verify(a, foreign, f.expect("gw17")));
}

test "validity window with leeway" {
    const a = testing.allocator;
    const f = try Fixture.init();
    var s = f.spec();
    s.nbf = t0 + 60;
    const tok = try issue(a, f.account, s, t0);
    defer a.free(tok);

    // nbf 60 s ahead is within the default 5 min leeway
    (try verify(a, tok, f.expect("gw17"))).deinit();
    var e = f.expect("gw17");
    e.leeway = 0;
    try testing.expectError(error.NotYetValid, verify(a, tok, e));

    // exp passed 2 min ago: accepted with leeway, rejected without
    e = f.expect("gw17");
    e.now = t0 + 3600 + 120;
    (try verify(a, tok, e)).deinit();
    e.now = t0 + 3600 + default_leeway;
    try testing.expectError(error.Expired, verify(a, tok, e));
}

test "a user JWT is not a grant" {
    const a = testing.allocator;
    const f = try Fixture.init();
    const user_jwt = try jwt.encode(a, jwt.UserClaims, .{ .sub = &f.user_pub, .exp = t0 + 3600, .nats = .{} }, f.account, t0);
    defer a.free(user_jwt);
    // Missing grant fields make it unparseable as a grant
    try testing.expectError(error.InvalidToken, verify(a, user_jwt, f.expect("gw17")));
}

test "a grant claiming another type is rejected" {
    const a = testing.allocator;
    const f = try Fixture.init();
    const tok = try jwt.encode(a, GrantClaims, .{
        .sub = &f.user_pub,
        .exp = t0 + 3600,
        .nats = .{ .type = "user", .nodes = &.{"gw17"}, .run_as = "root" },
    }, f.account, t0);
    defer a.free(tok);
    try testing.expectError(error.NotAGrant, verify(a, tok, f.expect("gw17")));
}

test "issue rejects bad input" {
    const a = testing.allocator;
    const f = try Fixture.init();

    try testing.expectError(error.InvalidSigner, issue(a, f.user, f.spec(), t0));

    var s = f.spec();
    s.nodes = &.{};
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.exp = t0;
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.exp = null;
    s.max_uses = null;
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.user = &f.account_pub;
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.max_uses = 0;
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.nodes = &.{"ist-*"};
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
    s = f.spec();
    s.run_as = "";
    try testing.expectError(error.InvalidSpec, issue(a, f.account, s, t0));
}

test "unlimited grant and bot kind round trip" {
    const a = testing.allocator;
    const f = try Fixture.init();
    var s = f.spec();
    s.max_uses = null;
    s.kind = .bot;
    s.run_as = "tgbot";
    const tok = try issue(a, f.account, s, t0);
    defer a.free(tok);
    const p = try verify(a, tok, f.expect("gw17"));
    defer p.deinit();
    try testing.expectEqual(@as(?u32, null), p.value.nats.max_uses);
    try testing.expectEqual(Kind.bot, p.value.nats.kind);
}

test "no leaks on allocation failures" {
    const f = try Fixture.init();
    const tok = try issue(testing.allocator, f.account, f.spec(), t0);
    defer testing.allocator.free(tok);
    const run = struct {
        fn run(a: std.mem.Allocator, t: []const u8, e: Expect) !void {
            (try verify(a, t, e)).deinit();
        }
    }.run;
    try testing.checkAllAllocationFailures(testing.allocator, run, .{ tok, f.expect("gw17") });
}

test "glob matching of node names" {
    try testing.expect(globMatch("gw17", "gw17"));
    try testing.expect(!globMatch("gw17", "gw170"));
    try testing.expect(globMatch("*", "anything"));
    try testing.expect(globMatch("*", ""));
    try testing.expect(globMatch("gw_*", "gw_"));
    try testing.expect(globMatch("gw_*", "gw_ist_01"));
    try testing.expect(!globMatch("gw_*", "pump_01"));
    try testing.expect(globMatch("pump??", "pump07"));
    try testing.expect(!globMatch("pump??", "pump7"));
    try testing.expect(globMatch("*_gw", "ist_kadikoy_gw"));
    try testing.expect(globMatch("ist_*_*_gw", "ist_a_b_gw"));
    try testing.expect(!globMatch("ist_*_*_gw", "ist_a_gw"));
    try testing.expect(globMatch("a*b*c", "aXXbYYbZc"));
    try testing.expect(!globMatch("a*b*c", "aXXbYY"));
}

test "a grant limited only by uses has no exp" {
    const a = testing.allocator;
    const f = try Fixture.init();
    var s = f.spec();
    s.exp = null;
    const tok = try issue(a, f.account, s, t0);
    defer a.free(tok);
    var e = f.expect("gw17");
    e.now = t0 + 10 * 365 * 86400;
    const p = try verify(a, tok, e);
    defer p.deinit();
    try testing.expectEqual(@as(?i64, null), p.value.exp);
}
