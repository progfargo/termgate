//! Session approvals: termgate's answer to "may this session open?".
//!
//! After verifying a session request (session.zig), tgnode sends an approval
//! request to authorize.<node>: the grant, the node, the request's nonce and
//! the session id it chose. termgate checks revocation and max_uses, counts
//! the use, records the start and replies with an approval: a JWT signed by the
//! account key whose nats section has type "approval" and echoes node, nonce,
//! sid and the grant's jti. tgnode accepts only an approval that is signed by
//! a trusted account key and matches its own request, so a compromised relay
//! cannot fake or replay one.
//!
//! End-to-end encryption (e2e.zig): the request carries both sides' session
//! public keys and the session keys sealed to termgate; the approval echoes
//! the two public keys. tgnode passes the approval to tgterm, which checks
//! it (verifyForUser) and takes the node's public key from it: signed by
//! termgate, the relay cannot swap it.

const std = @import("std");
const nkeys = @import("nkeys.zig");
const jwt = @import("jwt.zig");

/// How long an approval is valid; it is used right away.
pub const lifetime: i64 = 60;

/// Body of the request on authorize.<node> (JSON).
pub const Request = struct {
    grant: []const u8,
    node: []const u8,
    nonce: []const u8,
    sid: []const u8,
    /// tgterm's and tgnode's session public keys (base64url)
    kx_user: []const u8,
    kx_node: []const u8,
    /// The session keys sealed to termgate (e2e.sealForTermgate); not echoed
    keys: []const u8 = "",
};

pub const ApprovalNats = struct {
    type: []const u8 = "approval",
    version: u8 = 1,
    node: []const u8,
    nonce: []const u8,
    sid: []const u8,
    kx_user: []const u8,
    kx_node: []const u8,
    /// jti of the approved grant
    grant: []const u8,
    ok: bool,
    /// Why the session was refused (shown to the user)
    reason: ?[]const u8 = null,
};

pub const ApprovalClaims = jwt.Claims(ApprovalNats);

pub const Decision = union(enum) {
    allow,
    deny: []const u8,
};

/// Signs an approval (termgate side) for a request whose grant termgate has
/// already verified. `user` is the grant's sub, `grant_jti` its jti.
pub fn issue(gpa: std.mem.Allocator, signer: nkeys.KeyPair, req: Request, user: []const u8, grant_jti: []const u8, decision: Decision, now: i64) ![]u8 {
    if (signer.prefix != .account) return error.InvalidSigner;
    return jwt.encode(gpa, ApprovalClaims, .{
        .sub = user,
        .exp = now + lifetime,
        .nats = .{
            .node = req.node,
            .nonce = req.nonce,
            .sid = req.sid,
            .kx_user = req.kx_user,
            .kx_node = req.kx_node,
            .grant = grant_jti,
            .ok = decision == .allow,
            .reason = switch (decision) {
                .allow => null,
                .deny => |r| r,
            },
        },
    }, signer, now);
}

pub const Expect = struct {
    /// Trusted account keys
    issuers: []const []const u8,
    /// The request this approval must answer
    request: Request,
    /// The grant's user and jti (from the verified grant)
    user: []const u8,
    grant_jti: []const u8,
    now: i64,
    leeway: i64 = 5 * 60,
};

pub const Error = error{
    NotAnApproval,
    UntrustedIssuer,
    /// Signed and valid, but for another request
    Mismatch,
    /// termgate refused the session; see the reason in the claims
    Denied,
};

/// Verifies an approval (tgnode side). On success the session may open. On
/// error.Denied the caller can read the reason by decoding with decodeDenied.
pub fn verify(gpa: std.mem.Allocator, token: []const u8, expect: Expect) !void {
    const p = try decodeChecked(gpa, token, expect);
    defer p.deinit();
    if (!p.value.nats.ok) return error.Denied;
}

/// Like verify, for a denied approval: returns the reason, owned by the caller.
pub fn denialReason(gpa: std.mem.Allocator, token: []const u8, expect: Expect) ![]u8 {
    const p = try decodeChecked(gpa, token, expect);
    defer p.deinit();
    if (p.value.nats.ok) return error.NotDenied;
    return gpa.dupe(u8, p.value.nats.reason orelse "denied");
}

fn decodeChecked(gpa: std.mem.Allocator, token: []const u8, expect: Expect) !std.json.Parsed(ApprovalClaims) {
    const p = try jwt.decodeLeeway(gpa, ApprovalClaims, token, expect.now, expect.leeway);
    errdefer p.deinit();
    const c = p.value;
    if (!std.mem.eql(u8, c.nats.type, "approval")) return error.NotAnApproval;
    for (expect.issuers) |i| {
        if (std.mem.eql(u8, i, c.iss)) break;
    } else return error.UntrustedIssuer;
    const r = expect.request;
    if (!std.mem.eql(u8, c.sub, expect.user) or
        !std.mem.eql(u8, c.nats.node, r.node) or
        !std.mem.eql(u8, c.nats.nonce, r.nonce) or
        !std.mem.eql(u8, c.nats.sid, r.sid) or
        !std.mem.eql(u8, c.nats.kx_user, r.kx_user) or
        !std.mem.eql(u8, c.nats.kx_node, r.kx_node) or
        !std.mem.eql(u8, c.nats.grant, expect.grant_jti))
        return error.Mismatch;
    return p;
}

/// What tgterm expects of the approval tgnode passes on.
pub const UserExpect = struct {
    issuers: []const []const u8,
    /// tgterm's own key, the grant's jti, the node it asked, the nonce and
    /// session public key it sent
    user: []const u8,
    grant_jti: []const u8,
    node: []const u8,
    nonce: []const u8,
    kx_user: []const u8,
    now: i64,
    leeway: i64 = 5 * 60,
};

pub const ForUser = struct {
    /// The session id and the node's session public key, as termgate
    /// signed them; in the caller's allocator
    sid: []u8,
    kx_node: []u8,
};

/// Verifies the approval on tgterm's side: signed by termgate, allowing
/// this user's request. Returns what tgterm needs from it.
pub fn verifyForUser(gpa: std.mem.Allocator, token: []const u8, expect: UserExpect) !ForUser {
    const p = try jwt.decodeLeeway(gpa, ApprovalClaims, token, expect.now, expect.leeway);
    defer p.deinit();
    const c = p.value;
    if (!std.mem.eql(u8, c.nats.type, "approval")) return error.NotAnApproval;
    for (expect.issuers) |i| {
        if (std.mem.eql(u8, i, c.iss)) break;
    } else return error.UntrustedIssuer;
    if (!std.mem.eql(u8, c.sub, expect.user) or
        !std.mem.eql(u8, c.nats.node, expect.node) or
        !std.mem.eql(u8, c.nats.nonce, expect.nonce) or
        !std.mem.eql(u8, c.nats.kx_user, expect.kx_user) or
        !std.mem.eql(u8, c.nats.grant, expect.grant_jti))
        return error.Mismatch;
    if (!c.nats.ok) return error.Denied;
    const sid = try gpa.dupe(u8, c.nats.sid);
    errdefer gpa.free(sid);
    return .{ .sid = sid, .kx_node = try gpa.dupe(u8, c.nats.kx_node) };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

const test_req: Request = .{ .grant = "<grant jwt>", .node = "gw17", .nonce = "n0nce", .sid = "s1", .kx_user = "KXU", .kx_node = "KXN" };

fn fixture() !struct { account: nkeys.KeyPair, account_pub: [nkeys.public_len]u8 } {
    const account = try nkeys.KeyPair.fromRawSeed(.account, @splat(1));
    return .{ .account = account, .account_pub = account.publicKey().encode() };
}

fn expectFor(issuers: []const []const u8, r: Request) Expect {
    return .{ .issuers = issuers, .request = r, .user = "UUSER", .grant_jti = "JTI1", .now = t0 };
}

test "allowed approval verifies for its own request only" {
    const a = testing.allocator;
    const f = try fixture();
    const tok = try issue(a, f.account, test_req, "UUSER", "JTI1", .allow, t0);
    defer a.free(tok);
    const issuers: []const []const u8 = &.{&f.account_pub};

    try verify(a, tok, expectFor(issuers, test_req));

    var other = test_req;
    other.nonce = "other";
    try testing.expectError(error.Mismatch, verify(a, tok, expectFor(issuers, other)));
    other = test_req;
    other.sid = "s2";
    try testing.expectError(error.Mismatch, verify(a, tok, expectFor(issuers, other)));
    other = test_req;
    other.node = "gw18";
    try testing.expectError(error.Mismatch, verify(a, tok, expectFor(issuers, other)));
    // The relay swapped the node's session key in the request
    other = test_req;
    other.kx_node = "RELAY";
    try testing.expectError(error.Mismatch, verify(a, tok, expectFor(issuers, other)));

    // tgterm's side: the node's key comes from the signed approval
    const ue: UserExpect = .{ .issuers = issuers, .user = "UUSER", .grant_jti = "JTI1", .node = "gw17", .nonce = "n0nce", .kx_user = "KXU", .now = t0 };
    const fu = try verifyForUser(a, tok, ue);
    defer a.free(fu.sid);
    defer a.free(fu.kx_node);
    try testing.expectEqualStrings("KXN", fu.kx_node);
    try testing.expectEqualStrings("s1", fu.sid);
    var ue2 = ue;
    ue2.kx_user = "RELAY";
    try testing.expectError(error.Mismatch, verifyForUser(a, tok, ue2));
    ue2 = ue;
    ue2.issuers = &.{"AOTHER"};
    try testing.expectError(error.UntrustedIssuer, verifyForUser(a, tok, ue2));

    var e = expectFor(issuers, test_req);
    e.now = t0 + lifetime + e.leeway;
    try testing.expectError(error.Expired, verify(a, tok, e));
}

test "denied approval carries a reason" {
    const a = testing.allocator;
    const f = try fixture();
    const tok = try issue(a, f.account, test_req, "UUSER", "JTI1", .{ .deny = "no uses left" }, t0);
    defer a.free(tok);
    const issuers: []const []const u8 = &.{&f.account_pub};
    try testing.expectError(error.Denied, verify(a, tok, expectFor(issuers, test_req)));
    const why = try denialReason(a, tok, expectFor(issuers, test_req));
    defer a.free(why);
    try testing.expectEqualStrings("no uses left", why);
}

test "approval from an untrusted key is rejected" {
    const a = testing.allocator;
    const f = try fixture();
    const stranger = try nkeys.KeyPair.fromRawSeed(.account, @splat(7));
    const tok = try issue(a, stranger, test_req, "UUSER", "JTI1", .allow, t0);
    defer a.free(tok);
    try testing.expectError(error.UntrustedIssuer, verify(a, tok, expectFor(&.{&f.account_pub}, test_req)));

    const user = try nkeys.KeyPair.fromRawSeed(.user, @splat(8));
    try testing.expectError(error.InvalidSigner, issue(a, user, test_req, "UUSER", "JTI1", .allow, t0));
}

test "a grant is not an approval" {
    const a = testing.allocator;
    const f = try fixture();
    const grant = @import("grant.zig");
    const user = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const upub = user.publicKey().encode();
    const g = try grant.issue(a, f.account, .{ .user = &upub, .nodes = &.{"gw17"}, .exp = t0 + 60 }, t0);
    defer a.free(g);
    try testing.expectError(error.InvalidToken, verify(a, g, expectFor(&.{&f.account_pub}, test_req)));
}
