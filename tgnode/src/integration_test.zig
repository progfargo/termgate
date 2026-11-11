//! End-to-end tests of tgnode against the relay's real setup: nats-server with
//! TLS and auth callout (lib/core/testdata/nats-callout-tls.conf, port 14227),
//! with core.standin (lib/core/src/standin.zig) standing in for termgate and the test itself
//! standing in for tgterm. Run with `zig build test -Dnats-test`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const KeyPair = core.nkeys.KeyPair;
const agent_mod = @import("agent.zig");
const tg = core.standin;
const Termgate = tg.Termgate;
const test_ca = @embedFile("test_ca");
const c = @import("c");

fn now(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

fn currentUser(buf: []u8) ![]const u8 {
    var pw: c.struct_passwd = undefined;
    var result: ?*c.struct_passwd = null;
    var tmp: [4096]u8 = undefined;
    if (c.getpwuid_r(c.getuid(), &pw, &tmp, tmp.len, @ptrCast(&result)) != 0 or result == null)
        return error.SkipZigTest;
    const n = std.mem.span(pw.pw_name);
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

fn startAgent(a: std.mem.Allocator, io: Io, t: *Termgate, name: []const u8, node_key: KeyPair) !*agent_mod.Agent {
    var root = try Io.Dir.openDirAbsolute(io, "/", .{});
    errdefer root.close(io);
    return agent_mod.Agent.connect(a, io, .{
        .name = name,
        .relay_host = "127.0.0.1",
        .relay_port = tg.port,
        .ca_pem = test_ca,
        .issuer = &t.issuer_pub,
    }, node_key, root);
}

fn runAgent(ag: *agent_mod.Agent) void {
    ag.run() catch {};
}

/// tgterm's side: a user connection with its own inbox.
fn connectUser(a: std.mem.Allocator, io: Io, user: KeyPair, inbox_buf: []u8) !*Conn {
    const upub = user.publicKey().encode();
    return Conn.connect(a, io, .{
        .port = tg.port,
        .key = user,
        .inbox_prefix = try std.fmt.bufPrint(inbox_buf, "_INBOX.{s}", .{upub}),
        .tls = .{ .ca_pem = test_ca },
    });
}

test "a session end to end: open, type, read output, exit, audit" {
    const a = testing.allocator;
    const io = testing.io;
    var name_buf: [64]u8 = undefined;
    const me = try currentUser(&name_buf);
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();

    const node_key = try KeyPair.fromRawSeed(.user, @splat(20));
    t.addNode(&node_key.publicKey().encode(), "e2e_gw17");
    const user = try KeyPair.fromRawSeed(.user, @splat(14));
    const upub = user.publicKey().encode();
    t.addUser(&upub);

    // The node reports its system info once connected, and again when asked
    const status_sub = try t.app.subscribe("status.e2e_gw17");
    try t.app.flush(Conn.seconds(5));

    const ag = try startAgent(a, io, t, "e2e_gw17", node_key);
    defer ag.deinit();
    var agent_task = try io.concurrent(runAgent, .{ag});
    defer agent_task.cancel(io);

    {
        const st = try status_sub.next(Conn.seconds(5));
        defer st.deinit(a);
        try testing.expect(std.mem.indexOf(u8, st.payload, "\"mem_total_kb\"") != null);
    }
    try t.app.publish("status.req.all", "");
    {
        const st = try status_sub.next(Conn.seconds(5));
        st.deinit(a);
    }

    var inbox_buf: [80]u8 = undefined;
    const client = try connectUser(a, io, user, &inbox_buf);
    defer client.close();
    const grant_tok = try core.grant.issue(a, t.issuer, .{ .user = &upub, .nodes = &.{"e2e_*"}, .run_as = me, .max_uses = 3 }, now(io));
    defer a.free(grant_tok);

    // tgterm's side of the key agreement
    const eph = core.e2e.Ephemeral.generate(io);
    const user_kx = eph.publicText();
    const created = try core.session.create(a, io, user, grant_tok, "e2e_gw17", &user_kx, now(io));
    defer created.deinit(a);
    const req = created.body;
    const reply = try client.request("session.open.e2e_gw17", req, Conn.seconds(15));
    defer reply.deinit(a);
    const Reply = struct { sid: ?[]const u8 = null, approval: ?[]const u8 = null, @"error": ?[]const u8 = null };
    const r = try std.json.parseFromSlice(Reply, a, reply.payload, .{});
    defer r.deinit();
    try testing.expectEqual(@as(?[]const u8, null), r.value.@"error");
    const sid = r.value.sid.?;
    // The node's session key comes in termgate's signed approval
    const g = try core.jwt.decode(a, core.grant.GrantClaims, grant_tok, now(io));
    defer g.deinit();
    const ok = try core.approval.verifyForUser(a, r.value.approval.?, .{
        .issuers = &.{&t.issuer_pub},
        .user = &upub,
        .grant_jti = g.value.jti.?,
        .node = "e2e_gw17",
        .nonce = &created.nonce,
        .kx_user = &user_kx,
        .now = now(io),
    });
    defer a.free(ok.sid);
    defer a.free(ok.kx_node);
    try testing.expectEqualStrings(sid, ok.sid);
    const keys = try eph.keys(try core.e2e.decodePublic(ok.kx_node), sid, &user_kx, ok.kx_node);
    var tx: core.e2e.Sealer = .{ .key = keys.up, .sender = .user };
    var rx: core.e2e.Opener = .{ .key = keys.down };

    var buf: [256]u8 = undefined;
    const out = try client.subscribe(try std.fmt.bufPrint(&buf, "out.e2e_gw17.{s}.{s}.*", .{ &upub, sid }));
    try client.flush(Conn.seconds(5));
    var in_buf: [256]u8 = undefined;
    const in_prefix = try std.fmt.bufPrint(&in_buf, "in.e2e_gw17.{s}.{s}", .{ &upub, sid });
    var subj: [300]u8 = undefined;
    try client.publish(try std.fmt.bufPrint(&subj, "{s}.resize", .{in_prefix}), &.{ 0, 120, 0, 40 });
    // Typed in clear (not from tgterm): the node drops it
    try client.publish(try std.fmt.bufPrint(&subj, "{s}.data", .{in_prefix}), "echo clear-$((1+1))\n");
    {
        const m1 = try tx.seal(a, "stty size; echo marker-$((6*7))\n");
        defer a.free(m1);
        try client.publish(try std.fmt.bufPrint(&subj, "{s}.data", .{in_prefix}), m1);
    }

    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(a);
    while (std.mem.indexOf(u8, seen.items, "marker-42") == null) {
        const m = try out.next(Conn.seconds(10));
        defer m.deinit(a);
        // On the relay the output is ciphertext
        try testing.expect(std.mem.indexOf(u8, m.payload, "marker") == null);
        const plain = try rx.open(a, m.payload);
        defer a.free(plain);
        try seen.appendSlice(a, plain);
    }
    try testing.expect(std.mem.indexOf(u8, seen.items, "clear-2") == null);
    try testing.expect(std.mem.indexOf(u8, seen.items, "40 120") != null);

    {
        const m2 = try tx.seal(a, "exit\n");
        defer a.free(m2);
        try client.publish(try std.fmt.bufPrint(&subj, "{s}.data", .{in_prefix}), m2);
    }
    while (true) {
        const m = try out.next(Conn.seconds(10));
        defer m.deinit(a);
        if (std.mem.endsWith(u8, m.subject, ".end")) break;
    }
    var waited: u32 = 0;
    while (t.session_ends.load(.acquire) == 0 and waited < 100) : (waited += 1) try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectEqual(@as(u32, 1), t.session_ends.load(.acquire));

    // The same signed request cannot be used again
    const again = try client.request("session.open.e2e_gw17", req, Conn.seconds(15));
    defer again.deinit(a);
    try testing.expect(std.mem.indexOf(u8, again.payload, "Replay") != null);

    // A user may not type into another user's session (NATS refuses it)
    try client.publish("in.e2e_gw17.UOTHERUSER.sid.data", "x");
    try client.flush(Conn.seconds(5));
    try testing.expect(std.mem.indexOf(u8, client.lastError(), "Permissions Violation") != null);
}

test "termgate gone: open sessions are ended after the grace time" {
    const a = testing.allocator;
    const io = testing.io;
    var name_buf: [64]u8 = undefined;
    const me = try currentUser(&name_buf);
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();
    const node_key = try KeyPair.fromRawSeed(.user, @splat(24));
    t.addNode(&node_key.publicKey().encode(), "e2e_cut");
    const user = try KeyPair.fromRawSeed(.user, @splat(16));
    const upub = user.publicKey().encode();
    t.addUser(&upub);

    const ag = try startAgent(a, io, t, "e2e_cut", node_key);
    defer ag.deinit();
    ag.termgate_grace_s = 2;
    ag.termgate_check_s = 1;
    var agent_task = try io.concurrent(runAgent, .{ag});
    defer agent_task.cancel(io);
    try io.sleep(.fromMilliseconds(500), .awake);

    var inbox_buf: [80]u8 = undefined;
    const client = try connectUser(a, io, user, &inbox_buf);
    defer client.close();
    const grant_tok = try core.grant.issue(a, t.issuer, .{ .user = &upub, .nodes = &.{"e2e_*"}, .run_as = me, .max_uses = 1 }, now(io));
    defer a.free(grant_tok);
    const eph = core.e2e.Ephemeral.generate(io);
    const user_kx = eph.publicText();
    const created = try core.session.create(a, io, user, grant_tok, "e2e_cut", &user_kx, now(io));
    defer created.deinit(a);
    const reply = try client.request("session.open.e2e_cut", created.body, Conn.seconds(15));
    defer reply.deinit(a);
    const Reply = struct { sid: []const u8, approval: []const u8 };
    const r = try std.json.parseFromSlice(Reply, a, reply.payload, .{});
    defer r.deinit();
    const g = try core.jwt.decode(a, core.grant.GrantClaims, grant_tok, now(io));
    defer g.deinit();
    const ok = try core.approval.verifyForUser(a, r.value.approval, .{ .issuers = &.{&t.issuer_pub}, .user = &upub, .grant_jti = g.value.jti.?, .node = "e2e_cut", .nonce = &created.nonce, .kx_user = &user_kx, .now = now(io) });
    defer a.free(ok.sid);
    defer a.free(ok.kx_node);
    const keys = try eph.keys(try core.e2e.decodePublic(ok.kx_node), ok.sid, &user_kx, ok.kx_node);
    var rx: core.e2e.Opener = .{ .key = keys.down };
    var buf: [256]u8 = undefined;
    const out = try client.subscribe(try std.fmt.bufPrint(&buf, "out.e2e_cut.{s}.{s}.*", .{ &upub, ok.sid }));
    try client.flush(Conn.seconds(5));

    // While termgate answers, the session stays open past the grace time
    try io.sleep(.fromSeconds(4), .awake);
    try testing.expect(!ag.cut.load(.acquire));

    // termgate goes away: the user is told and the session ends
    t.serve_audit.store(false, .release);
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(a);
    while (true) {
        const m = try out.next(Conn.seconds(20));
        defer m.deinit(a);
        if (std.mem.endsWith(u8, m.subject, ".end")) break;
        const plain = rx.open(a, m.payload) catch continue;
        defer a.free(plain);
        try seen.appendSlice(a, plain);
    }
    try testing.expect(std.mem.indexOf(u8, seen.items, "termgate is not reachable") != null);
}

test "termgate not answering approvals: the session is refused" {
    const a = testing.allocator;
    const io = testing.io;
    var name_buf: [64]u8 = undefined;
    const me = try currentUser(&name_buf);
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();
    t.serve_authorize = false;

    const node_key = try KeyPair.fromRawSeed(.user, @splat(22));
    t.addNode(&node_key.publicKey().encode(), "e2e_lonely");
    const user = try KeyPair.fromRawSeed(.user, @splat(15));
    const upub = user.publicKey().encode();
    t.addUser(&upub);

    const ag = try startAgent(a, io, t, "e2e_lonely", node_key);
    defer ag.deinit();
    var agent_task = try io.concurrent(runAgent, .{ag});
    defer agent_task.cancel(io);
    try io.sleep(.fromMilliseconds(500), .awake);

    var inbox_buf: [80]u8 = undefined;
    const client = try connectUser(a, io, user, &inbox_buf);
    defer client.close();
    const grant_tok = try core.grant.issue(a, t.issuer, .{ .user = &upub, .nodes = &.{"e2e_*"}, .run_as = me, .max_uses = 1 }, now(io));
    defer a.free(grant_tok);
    const kx = core.e2e.Ephemeral.generate(io).publicText();
    const created = try core.session.create(a, io, user, grant_tok, "e2e_lonely", &kx, now(io));
    defer created.deinit(a);
    const reply = try client.request("session.open.e2e_lonely", created.body, Conn.seconds(30));
    defer reply.deinit(a);
    try testing.expect(std.mem.indexOf(u8, reply.payload, "termgate is offline") != null);
}

test "unknown keys only get ca.get" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();
    const stranger = try KeyPair.fromRawSeed(.user, @splat(99));
    var inbox_buf: [80]u8 = undefined;
    const conn = try connectUser(a, io, stranger, &inbox_buf);
    defer conn.close();
    const ca = try conn.request("ca.get", "", Conn.seconds(5));
    defer ca.deinit(a);
    try testing.expectEqualStrings(test_ca, ca.payload);
    try conn.publish("session.open.e2e_gw17", "{}");
    try conn.flush(Conn.seconds(5));
    try testing.expect(std.mem.indexOf(u8, conn.lastError(), "Permissions Violation") != null);
}

const register = @import("register.zig");

test "registration: CA check, waiting for approval, then serving" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();

    // The admin creates "e2e_newbox" in termgate and gets a node key
    const fp = try core.code.caFingerprint(a, test_ca);
    const node_key_text = try core.code.format(a, "127.0.0.1", tg.port, fp, @splat(0x5a));
    defer a.free(node_key_text);
    const parsed = try core.code.parse(node_key_text);
    t.expectRegistration(parsed.token, "e2e_newbox");

    // First run on the device
    var root = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer root.close(io);
    const hw = try KeyPair.fromRawSeed(.user, @splat(23));
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const cfg = try register.register(a, arena.allocator(), io, node_key_text, hw, root, .{ .poll = .fromMilliseconds(200) });
    try testing.expectEqualStrings("e2e_newbox", cfg.name);
    try testing.expectEqualStrings("127.0.0.1", cfg.relay_host);
    try testing.expectEqualStrings(&t.issuer_pub, cfg.issuer);
    try testing.expectEqualStrings(test_ca, cfg.ca_pem);
    try testing.expectEqual(@as(u32, 2), t.reg_requests); // pending once, then approved

    // With the stored config it now connects as the node
    const status_sub = try t.app.subscribe("status.e2e_newbox");
    try t.app.flush(Conn.seconds(5));
    const ag = try agent_mod.Agent.connect(a, io, cfg, hw, root);
    defer ag.deinit();
    var agent_task = try io.concurrent(runAgent, .{ag});
    defer agent_task.cancel(io);
    const st = try status_sub.next(Conn.seconds(5));
    st.deinit(a);
}

test "registration: a node key with the wrong CA fingerprint sends no token" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();
    const node_key_text = try core.code.format(a, "127.0.0.1", tg.port, @splat(0), @splat(0x5b));
    defer a.free(node_key_text);
    t.expectRegistration((try core.code.parse(node_key_text)).token, "e2e_other");

    var root = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer root.close(io);
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try testing.expectError(error.WrongCa, register.register(a, arena.allocator(), io, node_key_text, try KeyPair.fromRawSeed(.user, @splat(24)), root, .{}));
    try testing.expectEqual(@as(u32, 0), t.reg_requests);
}

test "registration: an unknown node key is refused" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try Termgate.start(a, io, test_ca);
    defer t.stop();
    const fp = try core.code.caFingerprint(a, test_ca);
    const node_key_text = try core.code.format(a, "127.0.0.1", tg.port, fp, @splat(0x5c));
    defer a.free(node_key_text);
    var root = try Io.Dir.openDirAbsolute(io, "/", .{});
    defer root.close(io);
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try testing.expectError(error.Refused, register.register(a, arena.allocator(), io, node_key_text, try KeyPair.fromRawSeed(.user, @splat(25)), root, .{}));
}
