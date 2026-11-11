//! NATS auth callout (termgate side).
//!
//! The relay's nats-server runs with a fixed configuration in which every
//! client connection is put to termgate: the server publishes an
//! authorization request on $SYS.REQ.USER.AUTH and waits for the reply.
//!
//! Request: a JWT signed by the server's nkey ("N..."), nats.type
//! "authorization_request", with the server id, a fresh per-connection user
//! key (user_nkey), the client's info (host, nonce) and its CONNECT options
//! (nkey, signature of the nonce, auth token, name).
//!
//! Response: a JWT signed by termgate's issuer key, sub = user_nkey,
//! aud = server id, nats.type "authorization_response", carrying either a
//! user JWT for that connection (sub = user_nkey, aud = target account,
//! permissions) or an error that refuses the connection.
//!
//! The server does not check the client's nonce signature in this mode;
//! clientKey() does. Format follows nats-io/jwt v2 (authorization_claims.go).

const std = @import("std");
const nkeys = @import("nkeys.zig");
const jwt = @import("jwt.zig");

pub const subject = "$SYS.REQ.USER.AUTH";

pub const ServerId = struct {
    name: []const u8 = "",
    host: []const u8 = "",
    id: []const u8,
    version: ?[]const u8 = null,
};

pub const ClientInfo = struct {
    host: ?[]const u8 = null,
    id: ?u64 = null,
    name: ?[]const u8 = null,
    kind: ?[]const u8 = null,
    type: ?[]const u8 = null,
    /// The nonce the server sent this client (present when it signed one)
    nonce: ?[]const u8 = null,
};

pub const ConnectOpts = struct {
    nkey: ?[]const u8 = null,
    /// Signature of the nonce (base64url, or standard base64 from some clients)
    sig: ?[]const u8 = null,
    auth_token: ?[]const u8 = null,
    name: ?[]const u8 = null,
    lang: ?[]const u8 = null,
    version: ?[]const u8 = null,
};

pub const RequestNats = struct {
    server_id: ServerId,
    user_nkey: []const u8,
    client_info: ClientInfo = .{},
    connect_opts: ConnectOpts = .{},
    type: []const u8 = "authorization_request",
    version: u8 = 2,
};

pub const RequestClaims = jwt.Claims(RequestNats);

pub const ResponseNats = struct {
    jwt: ?[]const u8 = null,
    @"error": ?[]const u8 = null,
    type: []const u8 = "authorization_response",
    version: u8 = 2,
};

pub const ResponseClaims = jwt.Claims(ResponseNats);

pub const Error = error{ NotARequest, NoClientKey, BadClientSignature };

/// Decodes and verifies an authorization request (signed by the server).
pub fn decodeRequest(gpa: std.mem.Allocator, token: []const u8, now: i64) !std.json.Parsed(RequestClaims) {
    const p = try jwt.decodeLeeway(gpa, RequestClaims, token, now, 60);
    errdefer p.deinit();
    if (!std.mem.eql(u8, p.value.nats.type, "authorization_request")) return error.NotARequest;
    const iss = nkeys.PublicKey.decode(p.value.iss) catch return error.NotARequest;
    if (iss.prefix != .server) return error.NotARequest;
    return p;
}

/// The key the client proved to hold: CONNECT's nkey, whose signature over the
/// server nonce is checked here. error.NoClientKey if the client sent none.
pub fn clientKey(r: RequestNats) !nkeys.PublicKey {
    const nkey = r.connect_opts.nkey orelse return error.NoClientKey;
    const sig_text = r.connect_opts.sig orelse return error.NoClientKey;
    const nonce = r.client_info.nonce orelse return error.NoClientKey;
    const key = nkeys.PublicKey.decode(nkey) catch return error.BadClientSignature;
    if (key.prefix != .user) return error.BadClientSignature;
    var sig: [nkeys.signature_len]u8 = undefined;
    decodeSig(&sig, sig_text) catch return error.BadClientSignature;
    key.verify(nonce, sig) catch return error.BadClientSignature;
    return key;
}

fn decodeSig(out: *[nkeys.signature_len]u8, text: []const u8) !void {
    const trimmed = std.mem.trimEnd(u8, text, "=");
    if (std.mem.indexOfAny(u8, trimmed, "+/") != null) {
        const d = std.base64.standard_no_pad.Decoder;
        if (try d.calcSizeForSlice(trimmed) != out.len) return error.InvalidSignature;
        try d.decode(out, trimmed);
    } else {
        const d = std.base64.url_safe_no_pad.Decoder;
        if (try d.calcSizeForSlice(trimmed) != out.len) return error.InvalidSignature;
        try d.decode(out, trimmed);
    }
}

/// What the connection may do.
pub const Allow = struct {
    /// Shown as the connection's user name in server monitoring
    name: []const u8,
    /// Account the connection lands in (fixed server config)
    account: []const u8,
    permissions: jwt.UserNats = .{},
    /// The connection is closed when this passes; null = no limit
    exp: ?i64 = null,
};

pub const Decision = union(enum) {
    allow: Allow,
    deny: []const u8,
};

/// Builds the signed response to `req`. The caller owns the result.
pub fn respond(gpa: std.mem.Allocator, issuer: nkeys.KeyPair, req: RequestNats, decision: Decision, now: i64) ![]u8 {
    if (issuer.prefix != .account) return error.InvalidSigner;
    var user_jwt: ?[]u8 = null;
    defer if (user_jwt) |u| gpa.free(u);
    var err_text: ?[]const u8 = null;
    switch (decision) {
        .allow => |a| {
            var perms = a.permissions;
            perms.issuer_account = null;
            user_jwt = try jwt.encode(gpa, jwt.UserClaims, .{
                .name = a.name,
                .sub = req.user_nkey,
                .aud = a.account,
                .exp = a.exp,
                .nats = perms,
            }, issuer, now);
        },
        .deny => |why| err_text = why,
    }
    return jwt.encode(gpa, ResponseClaims, .{
        .sub = req.user_nkey,
        .aud = req.server_id.id,
        .nats = .{ .jwt = user_jwt, .@"error" = err_text },
    }, issuer, now);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

/// A request as nats-server would build it, signed by a server key.
fn fakeRequest(a: std.mem.Allocator, server: nkeys.KeyPair, client: nkeys.KeyPair, nonce: []const u8, token: ?[]const u8) ![]u8 {
    const sig = try client.sign(nonce);
    var sig_text: [86]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&sig_text, &sig);
    const per_conn = try nkeys.KeyPair.fromRawSeed(.user, @splat(77));
    const cpub = client.publicKey().encode();
    const upub = per_conn.publicKey().encode();
    return jwt.encode(a, RequestClaims, .{
        .sub = "AISSUER",
        .aud = "nats-authorization-request",
        .exp = t0 + 2,
        .nats = .{
            .server_id = .{ .id = "NSERVERID", .name = "relay" },
            .user_nkey = &upub,
            .client_info = .{ .host = "10.0.0.5", .nonce = nonce },
            .connect_opts = .{ .nkey = &cpub, .sig = &sig_text, .auth_token = token, .name = "tgnode" },
        },
    }, server, t0);
}

test "request: client key and token" {
    const a = testing.allocator;
    const server = try nkeys.KeyPair.fromRawSeed(.server, @splat(1));
    const client = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const tok = try fakeRequest(a, server, client, "n0nce-abc", "tg1-token");
    defer a.free(tok);

    const p = try decodeRequest(a, tok, t0);
    defer p.deinit();
    try testing.expectEqualStrings("tg1-token", p.value.nats.connect_opts.auth_token.?);
    try testing.expectEqualStrings("10.0.0.5", p.value.nats.client_info.host.?);
    const key = try clientKey(p.value.nats);
    try testing.expectEqualStrings(&client.publicKey().encode(), &key.encode());
}

test "request: wrong nonce signature and missing key" {
    const a = testing.allocator;
    const server = try nkeys.KeyPair.fromRawSeed(.server, @splat(1));
    const client = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const tok = try fakeRequest(a, server, client, "n0nce-abc", null);
    defer a.free(tok);
    const p = try decodeRequest(a, tok, t0);
    defer p.deinit();

    var r = p.value.nats;
    r.client_info.nonce = "another-nonce";
    try testing.expectError(error.BadClientSignature, clientKey(r));
    r = p.value.nats;
    r.connect_opts.nkey = null;
    try testing.expectError(error.NoClientKey, clientKey(r));
}

test "request signed by a non-server key is refused" {
    const a = testing.allocator;
    const not_server = try nkeys.KeyPair.fromRawSeed(.account, @splat(1));
    const client = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const tok = try fakeRequest(a, not_server, client, "n", null);
    defer a.free(tok);
    try testing.expectError(error.NotARequest, decodeRequest(a, tok, t0));
}

test "response carries a user JWT for the connection" {
    const a = testing.allocator;
    const server = try nkeys.KeyPair.fromRawSeed(.server, @splat(1));
    const client = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const issuer = try nkeys.KeyPair.fromRawSeed(.account, @splat(3));
    const tok = try fakeRequest(a, server, client, "n", null);
    defer a.free(tok);
    const req = try decodeRequest(a, tok, t0);
    defer req.deinit();

    const resp = try respond(a, issuer, req.value.nats, .{ .allow = .{
        .name = "ist_kadikoy_gw01",
        .account = "APP",
        .permissions = .{ .@"pub" = .{ .allow = &.{"hello.ist_kadikoy_gw01"} } },
    } }, t0);
    defer a.free(resp);
    const r = try jwt.decode(a, ResponseClaims, resp, t0);
    defer r.deinit();
    try testing.expectEqualStrings(req.value.nats.user_nkey, r.value.sub);
    try testing.expectEqualStrings("NSERVERID", r.value.aud.?);
    const u = try jwt.decode(a, jwt.UserClaims, r.value.nats.jwt.?, t0);
    defer u.deinit();
    try testing.expectEqualStrings(req.value.nats.user_nkey, u.value.sub);
    try testing.expectEqualStrings("APP", u.value.aud.?);
    try testing.expectEqualStrings("hello.ist_kadikoy_gw01", u.value.nats.@"pub".allow.?[0]);

    const deny = try respond(a, issuer, req.value.nats, .{ .deny = "unknown node" }, t0);
    defer a.free(deny);
    const d = try jwt.decode(a, ResponseClaims, deny, t0);
    defer d.deinit();
    try testing.expectEqualStrings("unknown node", d.value.nats.@"error".?);
    try testing.expectEqual(@as(?[]const u8, null), d.value.nats.jwt);
}
