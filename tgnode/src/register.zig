//! First run: registration with a node key (tgnode --node-key tg1-...).
//!
//! 1. Parse the node key: relay address, CA fingerprint, token.
//! 2. Connect without certificate verification and ask for termgate's CA
//!    (ca.get). Check its SHA-256 against the fingerprint in the node key.
//!    Nothing secret is sent on this connection.
//! 3. Reconnect, now verifying the relay against that CA, with the token as
//!    auth token. Send the registration request (hardware key and system
//!    info) to register.<token id>; repeat until termgate answers "approved"
//!    (the admin has accepted it) or refuses.
//! 4. Return the configuration to store: name, relay, CA, issuer.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const Config = @import("config.zig").Config;
const sysinfo = @import("sysinfo.zig");

const log = std.log.scoped(.tgnode);

pub const Options = struct {
    /// Time between registration requests while waiting for the admin
    poll: Io.Duration = .fromSeconds(5),
};

pub const Error = error{
    /// termgate refused the registration (unknown, expired or used node key)
    Refused,
};

/// Registers this node. Connections use `gpa` (each holds large buffers and
/// attempts may repeat for long); strings of the returned config live in
/// `arena`.
pub fn register(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, node_key: []const u8, key: core.nkeys.KeyPair, root: Io.Dir, opts: Options) !Config {
    const code = try core.code.parse(node_key);
    const kpub = key.publicKey().encode();
    const inbox = try std.fmt.allocPrint(arena, "_INBOX.{s}", .{kpub});

    const token_id = core.code.tokenId(code.token);
    const subject = try std.fmt.allocPrint(arena, "register.{s}", .{&token_id});
    // Until approved, or refused: while the relay or termgate cannot be
    // reached the node keeps trying (nobody has to start it again); only
    // termgate refusing the key (unknown, used or expired) ends it
    var told_waiting = false;
    while (true) {
        // Each round's CA in its own memory: rounds may repeat for long
        var round: std.heap.ArenaAllocator = .init(gpa);
        defer round.deinit();
        // Step 2: fetch and check the CA. termgate answers it, so getting
        // it also tells that termgate is there: a connection refused right
        // after is the key refused, not termgate gone. A wrong CA ends it
        // (another relay, or someone in between).
        const ca_pem = core.bootstrap.fetchCa(gpa, round.allocator(), io, code, key, inbox, "tgnode") catch |e| switch (e) {
            error.WrongCa, error.OutOfMemory, error.Canceled => return e,
            else => {
                log.warn("relay or termgate not reachable ({s}); will retry", .{@errorName(e)});
                try io.sleep(opts.poll, .awake);
                continue;
            },
        };
        // Step 3: register over a verified connection
        if (try attempt(gpa, arena, io, code, key, inbox, ca_pem, subject, root)) |cfg| return cfg;
        if (!told_waiting) {
            log.info("registration sent; waiting for the admin to approve it in termgate", .{});
            told_waiting = true;
        }
        try io.sleep(opts.poll, .awake);
    }
}

/// One registration request. null = not approved yet (pending, or termgate
/// not reachable right now).
fn attempt(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, code: core.code.Code, key: core.nkeys.KeyPair, inbox: []const u8, ca_pem: []const u8, subject: []const u8, root: Io.Dir) !?Config {
    const conn = Conn.connect(gpa, io, .{
        .host = code.host,
        .port = code.port,
        .key = key,
        .token = code.token,
        .name = "tgnode",
        .inbox_prefix = inbox,
        .tls = .{ .ca_pem = ca_pem },
    }) catch |e| switch (e) {
        // The callout said no: the node key is unknown, used or expired
        error.ServerRejected => return error.Refused,
        else => {
            log.warn("cannot reach the relay: {s}", .{@errorName(e)});
            return null;
        },
    };
    defer conn.close();

    // Per-attempt scratch memory, freed after each try
    var scratch_state: std.heap.ArenaAllocator = .init(gpa);
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();
    const kpub = key.publicKey().encode();
    const status = try sysinfo.collect(scratch, io, root, "/");
    const body = try std.json.Stringify.valueAlloc(scratch, .{ .hardware_key = @as([]const u8, &kpub), .status = status }, .{});
    const m = conn.request(subject, body, Conn.seconds(15)) catch |e| switch (e) {
        error.NoResponders, error.Timeout => {
            log.warn("termgate is offline; will retry", .{});
            return null;
        },
        else => return e,
    };
    defer m.deinit(gpa);

    const Answer = struct {
        status: []const u8,
        name: ?[]const u8 = null,
        issuer: ?[]const u8 = null,
        reason: ?[]const u8 = null,
    };
    const ans = std.json.parseFromSliceLeaky(Answer, scratch, m.payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch
        return error.Refused;
    if (std.mem.eql(u8, ans.status, "pending")) return null;
    if (!std.mem.eql(u8, ans.status, "approved")) {
        log.err("registration refused: {s}", .{ans.reason orelse ans.status});
        return error.Refused;
    }
    const name = ans.name orelse return error.Refused;
    const issuer = ans.issuer orelse return error.Refused;
    if (!core.node.isValidName(name)) return error.Refused;
    const ik = core.nkeys.PublicKey.decode(issuer) catch return error.Refused;
    if (ik.prefix != .account) return error.Refused;
    return .{
        .name = try arena.dupe(u8, name),
        .relay_host = try arena.dupe(u8, code.host),
        .relay_port = code.port,
        .ca_pem = try arena.dupe(u8, ca_pem),
        .issuer = try arena.dupe(u8, issuer),
        .hardware_key = try arena.dupe(u8, &kpub),
    };
}
