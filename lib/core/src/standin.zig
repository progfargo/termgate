//! Test stand-in for termgate, used by the binaries' integration tests against
//! lib/core/testdata/nats-callout-tls.conf (port 14227). It does what termgate
//! will do on the relay:
//!   - answers the auth callout for every connection (known nodes, users,
//!     itself, a registering node with its node key, a user with an
//!     access key, anyone else: ca.get only)
//!   - serves ca.get, register.<token id>, access.<token id>,
//!     authorize.<node> and audit.<node>
//! Admin decisions are automatic: registrations are approved on the second
//! request, sessions are approved unless `deny_sessions` is set. Not used in
//! production code.

const std = @import("std");
const Io = std.Io;
const core = @import("root.zig");
const Conn = core.nats.Conn;
const KeyPair = core.nkeys.KeyPair;

pub const port = 14227;

const max_known = 16;

pub const Termgate = struct {
    gpa: std.mem.Allocator,
    io: Io,
    issuer: KeyPair,
    issuer_pub: [56]u8,
    key: KeyPair,
    key_pub: [56]u8,
    svc: *Conn = undefined,
    app: *Conn = undefined,
    mutex: Io.Mutex = .init,
    /// Approved nodes: hardware key -> name
    node_keys: [max_known][56]u8 = undefined,
    node_names: [max_known][]const u8 = undefined,
    nodes: usize = 0,
    users: [max_known][56]u8 = undefined,
    user_count: usize = 0,
    /// One pending node record with its node key token
    reg_token: ?[]const u8 = null,
    reg_name: []const u8 = "",
    reg_requests: u32 = 0,
    /// One open access key (its token)
    access_token: ?[]const u8 = null,
    deny_sessions: bool = false,
    /// PEM of the test CA (the caller embeds lib/core/testdata/ca.pem)
    ca_pem: []const u8,
    serve_authorize: bool = true,
    /// false: audit.<node> is not answered, as if termgate were gone
    serve_audit: std.atomic.Value(bool) = .init(true),
    session_ends: std.atomic.Value(u32) = .init(0),
    tasks: Io.Group = .init,

    pub fn start(gpa: std.mem.Allocator, io: Io, ca_pem: []const u8) !*Termgate {
        const t = try gpa.create(Termgate);
        errdefer gpa.destroy(t);
        const issuer = try KeyPair.fromRawSeed(.account, @splat(0x1f));
        const key = try KeyPair.fromRawSeed(.user, @splat(0x1d));
        t.* = .{ .gpa = gpa, .io = io, .issuer = issuer, .issuer_pub = issuer.publicKey().encode(), .key = key, .key_pub = key.publicKey().encode(), .ca_pem = ca_pem };

        // Callout connection: termgate's own user in the AUTH account
        t.svc = try Conn.connect(gpa, io, .{ .port = port, .key = try KeyPair.fromRawSeed(.user, @splat(0x1e)), .tls = .{ .ca_pem = ca_pem } });
        const callout_sub = try t.svc.subscribe(core.callout.subject);
        try t.svc.flush(Conn.seconds(5));
        try t.tasks.concurrent(io, calloutLoop, .{ t, callout_sub });

        // Application connection, authorized by our own callout
        t.app = try Conn.connect(gpa, io, .{ .port = port, .key = key, .tls = .{ .ca_pem = ca_pem } });
        const subs = [_]*Conn.Sub{
            try t.app.subscribe("ca.get"),
            try t.app.subscribe("register.*"),
            try t.app.subscribe("authorize.*"),
            try t.app.subscribe("audit.*"),
            try t.app.subscribe("access.*"),
        };
        try t.app.flush(Conn.seconds(5));
        try t.tasks.concurrent(io, appLoop, .{ t, subs });
        return t;
    }

    pub fn stop(t: *Termgate) void {
        t.tasks.cancel(t.io);
        t.app.close();
        t.svc.close();
        t.gpa.destroy(t);
    }

    pub fn addNode(t: *Termgate, key: []const u8, name: []const u8) void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        t.node_keys[t.nodes] = key[0..56].*;
        t.node_names[t.nodes] = name;
        t.nodes += 1;
    }

    pub fn addUser(t: *Termgate, key: []const u8) void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        t.users[t.user_count] = key[0..56].*;
        t.user_count += 1;
    }

    /// The admin gave someone an access key with this token.
    pub fn expectAccessKey(t: *Termgate, token: []const u8) void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        t.access_token = token;
    }

    /// The admin created node `name` and got this node key token.
    pub fn expectRegistration(t: *Termgate, token: []const u8, name: []const u8) void {
        t.mutex.lockUncancelable(t.io);
        defer t.mutex.unlock(t.io);
        t.reg_token = token;
        t.reg_name = name;
    }

    fn nodeName(t: *Termgate, key: []const u8) ?[]const u8 {
        for (t.node_keys[0..t.nodes], t.node_names[0..t.nodes]) |*k, n| if (std.mem.eql(u8, k, key)) return n;
        return null;
    }

    fn isUser(t: *Termgate, key: []const u8) bool {
        for (t.users[0..t.user_count]) |*k| if (std.mem.eql(u8, k, key)) return true;
        return false;
    }

    fn now(t: *Termgate) i64 {
        return @intCast(@divFloor(Io.Timestamp.now(t.io, .real).nanoseconds, std.time.ns_per_s));
    }

    fn calloutLoop(t: *Termgate, sub: *Conn.Sub) void {
        while (true) {
            const m = sub.next(Conn.seconds(1)) catch |e| switch (e) {
                error.Timeout => continue,
                else => return,
            };
            defer m.deinit(t.gpa);
            t.answerCallout(m) catch |e| std.log.warn("test termgate callout: {s}", .{@errorName(e)});
        }
    }

    fn answerCallout(t: *Termgate, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(t.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const req = try core.callout.decodeRequest(a, m.payload, t.now());
        const r = req.value.nats;
        const decision: core.callout.Decision = blk: {
            const key = core.callout.clientKey(r) catch break :blk .{ .deny = "no valid key" };
            const kp = key.encode();
            const k = try a.dupe(u8, &kp);
            t.mutex.lockUncancelable(t.io);
            defer t.mutex.unlock(t.io);
            if (std.mem.eql(u8, k, &t.key_pub))
                break :blk .{ .allow = .{ .name = "termgate", .account = "APP", .permissions = core.perms.termgate() } };
            if (t.nodeName(k)) |name|
                break :blk .{ .allow = .{ .name = try std.fmt.allocPrint(a, "node:{s}", .{name}), .account = "APP", .permissions = try core.perms.node(a, name) } };
            if (t.isUser(k))
                break :blk .{ .allow = .{ .name = k, .account = "APP", .permissions = try core.perms.user(a, k) } };
            if (r.connect_opts.auth_token) |tok| {
                if (t.reg_token) |want| if (std.mem.eql(u8, tok, want)) {
                    const id = core.code.tokenId(tok);
                    break :blk .{ .allow = .{ .name = "registering", .account = "APP", .permissions = try core.perms.registering(a, &id, k) } };
                };
                if (t.access_token) |want| if (std.mem.eql(u8, tok, want)) {
                    const id = core.code.tokenId(tok);
                    break :blk .{ .allow = .{ .name = "access-key", .account = "APP", .permissions = try core.perms.usingAccessKey(a, &id, k) } };
                };
                break :blk .{ .deny = "unknown or used token" };
            }
            break :blk .{ .allow = .{ .name = "anonymous", .account = "APP", .permissions = try core.perms.anonymous(a, k) } };
        };
        const resp = try core.callout.respond(a, t.issuer, r, decision, t.now());
        try t.svc.publish(m.reply.?, resp);
    }

    fn appLoop(t: *Termgate, subs: [5]*Conn.Sub) void {
        while (true) {
            for (subs, 0..) |sub, i| {
                const m = sub.next(Conn.millis(50)) catch |e| switch (e) {
                    error.Timeout => continue,
                    else => return,
                };
                defer m.deinit(t.gpa);
                const reply = m.reply orelse continue;
                const answer: anyerror!void = switch (i) {
                    0 => t.app.publish(reply, t.ca_pem),
                    1 => t.answerRegister(m, reply),
                    2 => if (t.serve_authorize) t.answerAuthorize(m, reply) else {},
                    3 => blk: {
                        if (!t.serve_audit.load(.acquire)) break :blk {};
                        if (std.mem.indexOf(u8, m.payload, "\"event\":\"end\"") != null) _ = t.session_ends.fetchAdd(1, .release);
                        break :blk t.app.publish(reply, "ok");
                    },
                    else => t.answerAccessKey(m, reply),
                };
                answer catch |e| std.log.warn("test termgate: {s}", .{@errorName(e)});
            }
        }
    }

    fn answerRegister(t: *Termgate, m: Conn.Message, reply: []const u8) !void {
        var arena: std.heap.ArenaAllocator = .init(t.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Req = struct { hardware_key: []const u8 };
        const req = try std.json.parseFromSliceLeaky(Req, a, m.payload, .{ .ignore_unknown_fields = true });
        t.mutex.lockUncancelable(t.io);
        t.reg_requests += 1;
        const approve = t.reg_requests >= 2; // the "admin" approves after seeing the first request
        const name = t.reg_name;
        t.mutex.unlock(t.io);
        if (!approve) return t.app.publish(reply, "{\"status\":\"pending\"}");
        if (req.hardware_key.len != 56) return error.InvalidKey;
        t.addNode(req.hardware_key, name);
        const body = try std.json.Stringify.valueAlloc(a, .{ .status = "approved", .name = name, .issuer = @as([]const u8, &t.issuer_pub) }, .{});
        try t.app.publish(reply, body);
    }

    /// An access key is used: bind the key to the user, mark the token
    /// used, answer with termgate's issuer key (which signs approvals).
    fn answerAccessKey(t: *Termgate, m: Conn.Message, reply: []const u8) !void {
        var arena: std.heap.ArenaAllocator = .init(t.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Req = struct { user_key: []const u8 };
        const req = try std.json.parseFromSliceLeaky(Req, a, m.payload, .{ .ignore_unknown_fields = true });
        const k = core.nkeys.PublicKey.decode(req.user_key) catch return error.InvalidKey;
        if (k.prefix != .user) return error.InvalidKey;
        t.mutex.lockUncancelable(t.io);
        t.access_token = null; // single use
        t.mutex.unlock(t.io);
        t.addUser(req.user_key);
        try t.app.publish(reply, try std.json.Stringify.valueAlloc(a, .{ .issuer = @as([]const u8, &t.issuer_pub) }, .{}));
    }

    fn answerAuthorize(t: *Termgate, m: Conn.Message, reply: []const u8) !void {
        var arena: std.heap.ArenaAllocator = .init(t.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const req = try std.json.parseFromSliceLeaky(core.approval.Request, a, m.payload, .{});
        const decision: core.approval.Decision = if (t.deny_sessions) .{ .deny = "no uses left" } else .allow;
        const tok = try core.approval.issue(a, t.issuer, req, decision, t.now());
        try t.app.publish(reply, tok);
    }
};
