//! termgate's relay service against the relay's real setup (nats-server with
//! TLS and auth callout, lib/core/testdata/nats-callout-tls.conf). Nodes and
//! users are played with raw connections, so every decision comes from the
//! service and its database. Run with `zig build test -Dnats-test`.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const KeyPair = core.nkeys.KeyPair;
const dbm = @import("db");
const service_mod = @import("service");
const Service = service_mod.Service;
const Recorder = @import("recorder").Recorder;
const test_ca = @embedFile("test_ca");

const port = 14227;

fn now() i64 {
    return @intCast(@divFloor(Io.Timestamp.now(testing.io, .real).nanoseconds, std.time.ns_per_s));
}

const Fixture = struct {
    db: dbm.Db,
    lock: Io.Mutex = .init,
    recorder: Recorder = undefined,
    service: *Service = undefined,

    fn start(f: *Fixture) !void {
        f.db = try dbm.Db.open(":memory:");
        f.db.setLogKey(testing.io, @splat(7));
        errdefer f.db.close();
        f.recorder = .init(testing.allocator, testing.io, &f.db, &f.lock);
        errdefer f.recorder.deinit();
        try f.startService();
    }

    fn startService(f: *Fixture) !void {
        f.service = try Service.start(testing.allocator, testing.io, .{
            .relay_host = "127.0.0.1",
            .relay_port = port,
            .ca_pem = test_ca,
            .issuer = try KeyPair.fromRawSeed(.account, @splat(0x1f)),
            .callout_user = try KeyPair.fromRawSeed(.user, @splat(0x1e)),
            .app_user = try KeyPair.fromRawSeed(.user, @splat(0x1d)),
            .system_user = try KeyPair.fromRawSeed(.user, @splat(0x1c)),
        }, &f.db, &f.lock, &f.recorder);
    }

    fn stop(f: *Fixture) void {
        f.service.stop();
        f.recorder.deinit();
        f.db.close();
    }

    fn connect(f: *Fixture, key: KeyPair, token: ?[]const u8, inbox_buf: []u8) !*Conn {
        _ = f;
        const kpub = key.publicKey().encode();
        return Conn.connect(testing.allocator, testing.io, .{
            .port = port,
            .key = key,
            .token = token,
            .inbox_prefix = try std.fmt.bufPrint(inbox_buf, "_INBOX.{s}", .{kpub}),
            .tls = .{ .ca_pem = test_ca },
        });
    }
};

/// Waits until node `id`'s online flag is `want`.
fn waitOnline(f: *Fixture, id: i64, want: bool) !void {
    var tries: u32 = 0;
    while (tries < 100) : (tries += 1) {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        f.lock.lockUncancelable(testing.io);
        const n = (try f.db.nodeGet(arena.allocator(), id)).?;
        f.lock.unlock(testing.io);
        if (n.online == want) return;
        try testing.io.sleep(.fromMilliseconds(50), .awake);
    }
    return error.OnlineNotUpdated;
}

test "online and offline follow the node's connection, without heartbeats" {
    var f: Fixture = .{ .db = undefined };
    try f.start();
    defer f.stop();
    const hw = try KeyPair.fromRawSeed(.user, @splat(0x62));
    const hw_pub = hw.publicKey().encode();
    const id = blk: {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const th = dbm.tokenHash("unused");
        const id = try f.db.nodeCreate("pres1", "", &th, now() + 3600, now());
        try f.db.nodeRecordRequest(id, &hw_pub, "{}", now());
        try f.db.nodeApprove(id);
        try f.db.nodeFinishRegistration(id);
        break :blk id;
    };

    var inbox: [32]u8 = undefined;
    const node = try Conn.connect(testing.allocator, testing.io, .{ .port = port, .key = hw, .inbox_prefix = try std.fmt.bufPrint(&inbox, "_INBOX.pres1", .{}), .tls = .{ .ca_pem = test_ca } });
    defer node.close();
    try waitOnline(&f, id, true);

    // termgate restarts while the node stays connected: the connection list
    // read at start finds it
    f.service.stop();
    try waitOnline(&f, id, false);
    try f.startService();
    try waitOnline(&f, id, true);

    // Disabling the node closes its connection
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        try f.db.nodeSetDisabled(id, true);
    }
    f.service.kickNode("pres1");
    try waitClosed(node);
    try waitOnline(&f, id, false);
}

/// A user with the role terminal_user (connects to nodes).
fn terminalUser(db: *dbm.Db, name: []const u8) !i64 {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const id = try db.userCreate(name, false, "!", now());
    for (try db.roleList(arena.allocator())) |r| if (std.mem.eql(u8, r.name, "terminal_user")) try db.userGrant(id, r.id);
    return id;
}

/// An open session in termgate's database with known end-to-end keys, as if
/// termgate had approved it. `tag` makes the user and grant unique.
fn addSession(f: *Fixture, comptime tag: []const u8, node: []const u8, user: []const u8, sid: []const u8, started: i64) !core.e2e.Keys {
    const keys: core.e2e.Keys = .{ .up = @splat(0x41), .down = @splat(0x42) };
    f.lock.lockUncancelable(testing.io);
    defer f.lock.unlock(testing.io);
    const th = dbm.tokenHash("tok-" ++ tag);
    const uid = try terminalUser(&f.db, "u-" ++ tag);
    try f.db.terminalInvite(uid, .{ .nodes = "*", .max_uses = 5 }, &th, now() + 60, now());
    try f.db.terminalRedeem(uid, user, "JTI-" ++ tag, "<grant>", 5, null);
    _ = try f.db.grantUse("JTI-" ++ tag, node, sid, user, started);
    try f.db.sessionSetKeys(sid, keys);
    return keys;
}

/// Publishes `plain` on `subject`, encrypted as `sealer`'s sender.
fn publishSealed(c: *Conn, sealer: *core.e2e.Sealer, subject: []const u8, plain: []const u8) !void {
    const m = try sealer.seal(testing.allocator, plain);
    defer testing.allocator.free(m);
    try c.publish(subject, m);
}

test "a tap gives the browser a session's output as records" {
    const a = testing.allocator;
    const io = testing.io;
    var f: Fixture = .{ .db = undefined };
    try f.start();
    defer f.stop();
    var inbox: [64]u8 = undefined;
    const node = try connectNode(&f, "tap1", 0x66, &inbox);
    defer node.close();
    const user = try connectOther();
    defer user.close();
    const keys = try addSession(&f, "tap", "tap1", "UUSER", "T1", now());
    var node_tx: core.e2e.Sealer = .{ .key = keys.down, .sender = .node };

    const tap = try service_mod.Tap.start(f.service, "tap1", "UUSER", "T1");
    defer tap.stop();
    var tries: u32 = 0;
    while (tap.state.load(.acquire) != .live and tries < 100) : (tries += 1) try io.sleep(.fromMilliseconds(20), .awake);
    try testing.expect(tap.state.load(.acquire) == .live);

    // The user's window size, then output; a forged clear message is dropped
    try user.publish("in.tap1.UUSER.T1.resize", &.{ 0, 100, 0, 30 });
    try user.flush(Conn.seconds(5));
    try io.sleep(.fromMilliseconds(300), .awake);
    try node.publish("out.tap1.UUSER.T1.data", "FORGED");
    try publishSealed(node, &node_tx, "out.tap1.UUSER.T1.data", "hello");
    try node.flush(Conn.seconds(5));

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(a);
    var offset: u64 = 0;
    tries = 0;
    while (got.items.len < 15 and tries < 100) : (tries += 1) {
        const chunk = try tap.read(a, offset, now());
        defer a.free(chunk.data);
        try got.appendSlice(a, chunk.data);
        offset = chunk.next;
        try io.sleep(.fromMilliseconds(50), .awake);
    }
    // 'r' cols rows, then 'd' length "hello"
    try testing.expectEqualSlices(u8, &.{ 'r', 0, 100, 0, 30, 'd', 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' }, got.items);
    try testing.expectEqual(@as(u64, 15), offset);

    try node.publish("out.tap1.UUSER.T1.end", "");
    try node.flush(Conn.seconds(5));
    tries = 0;
    while (tap.state.load(.acquire) != .ended and tries < 100) : (tries += 1) try io.sleep(.fromMilliseconds(50), .awake);
    try testing.expect(tap.state.load(.acquire) == .ended);

    // A session termgate has no keys for cannot be read
    const blind = try service_mod.Tap.start(f.service, "tap1", "UUSER", "NOKEYS");
    defer blind.stop();
    try testing.expect(blind.state.load(.acquire) == .unreadable);
}

/// A second connection with termgate's application key: plays the user's
/// side (a connection does not receive its own messages).
fn connectOther() !*Conn {
    return Conn.connect(testing.allocator, testing.io, .{ .port = port, .key = try KeyPair.fromRawSeed(.user, @splat(0x1d)), .tls = .{ .ca_pem = test_ca } });
}

/// An approved node "name" with hardware key seed `seed`, connected.
fn connectNode(f: *Fixture, name: []const u8, seed: u8, inbox: []u8) !*Conn {
    const hw = try KeyPair.fromRawSeed(.user, @splat(seed));
    const hw_pub = hw.publicKey().encode();
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const th = dbm.tokenHash(name);
        const id = try f.db.nodeCreate(name, "", &th, now() + 3600, now());
        try f.db.nodeRecordRequest(id, &hw_pub, "{}", now());
        try f.db.nodeApprove(id);
        try f.db.nodeFinishRegistration(id);
    }
    return Conn.connect(testing.allocator, testing.io, .{ .port = port, .key = hw, .inbox_prefix = try std.fmt.bufPrint(inbox, "_INBOX.{s}", .{name}), .tls = .{ .ca_pem = test_ca } });
}

test "session logs: commands and output recorded from the relay" {
    const a = testing.allocator;
    const io = testing.io;
    var f: Fixture = .{ .db = undefined };
    try f.start();
    defer f.stop();
    var inbox: [64]u8 = undefined;
    const node = try connectNode(&f, "log1", 0x64, &inbox);
    defer node.close();
    // The user's input, as tgterm sends it: encrypted end to end; termgate
    // reads it with the session keys it got at approval
    const user = try connectOther();
    defer user.close();
    const keys = try addSession(&f, "log", "log1", "UUSER", "L1", now());
    var node_tx: core.e2e.Sealer = .{ .key = keys.down, .sender = .node };
    var user_tx: core.e2e.Sealer = .{ .key = keys.up, .sender = .user };
    try publishSealed(node, &node_tx, "out.log1.UUSER.L1.data", "\x1b[32mali@log1\x1b[0m:~$ ");
    try node.flush(Conn.seconds(5));
    try io.sleep(.fromMilliseconds(200), .awake);
    try publishSealed(user, &user_tx, "in.log1.UUSER.L1.data", "uname -a\r");
    try user.flush(Conn.seconds(5));
    try io.sleep(.fromMilliseconds(200), .awake);
    try publishSealed(node, &node_tx, "out.log1.UUSER.L1.data", "uname -a\r\nLinux log1 6.1.0 armv6l\r\nali@log1:~$ ");
    try node.publish("out.log1.UUSER.L1.end", "");
    try node.flush(Conn.seconds(5));

    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    var tries: u32 = 0;
    while (tries < 100) : (tries += 1) {
        f.lock.lockUncancelable(io);
        const cmds = try f.db.commandsOf(arena.allocator(), "L1");
        f.lock.unlock(io);
        if (cmds.len == 2) {
            // As it went through the relay
            try testing.expectEqualStrings("\x1b[32mali@log1\x1b[0m:~$ ", cmds[0].output);
            try testing.expectEqualStrings("uname -a\r", cmds[1].line);
            try testing.expectEqualStrings("uname -a\r\nLinux log1 6.1.0 armv6l\r\nali@log1:~$ ", cmds[1].output);
            break;
        }
        try io.sleep(.fromMilliseconds(50), .awake);
    } else return error.NotLogged;
}

test "a session over the time limit is told and ended" {
    const io = testing.io;
    var f: Fixture = .{ .db = undefined };
    var inbox: [64]u8 = undefined;
    f.db = try dbm.Db.open(":memory:");
    f.db.setLogKey(io, @splat(7));
    f.recorder = .init(testing.allocator, io, &f.db, &f.lock);
    // A session that started 2 minutes ago, with a 1-minute limit
    try f.db.settingsSet(.{ .max_session_minutes = 1 });

    try f.startService();
    defer f.stop();
    const node = try connectNode(&f, "exp1", 0x65, &inbox);
    defer node.close();
    const in_sub = try node.subscribe("in.exp1.UEVE.E1.*");
    try node.flush(Conn.seconds(5));
    const user = try connectOther();
    defer user.close();
    const user_view = try user.subscribe("out.exp1.UEVE.E1.data");
    try user.flush(Conn.seconds(5));
    const keys = try addSession(&f, "exp", "exp1", "UEVE", "E1", now() - 120);

    // Housekeeping runs every 5 seconds
    const told = try user_view.next(Conn.seconds(8));
    defer told.deinit(testing.allocator);
    // Encrypted like the node's output, from termgate
    var user_rx: core.e2e.Opener = .{ .key = keys.down };
    const text = try user_rx.open(testing.allocator, told.payload);
    defer testing.allocator.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "time limit of 1 minutes") != null);
    const end = try in_sub.next(Conn.seconds(8));
    defer end.deinit(testing.allocator);
    try testing.expect(std.mem.endsWith(u8, end.subject, ".end"));
}

fn newCode(a: std.mem.Allocator, seed: u8) ![]u8 {
    const fp = try core.code.caFingerprint(a, test_ca);
    return core.code.format(a, "127.0.0.1", port, fp, @splat(seed));
}

test "registration, status, invitation, approvals with max_uses, audit" {
    const a = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    var f: Fixture = .{ .db = undefined };
    try f.start();
    defer f.stop();

    // --- The admin creates node "box1" and gets its node key
    const node_code_text = try newCode(a, 0x71);
    defer a.free(node_code_text);
    const node_code = try core.code.parse(node_code_text);
    const node_th = dbm.tokenHash(node_code.token);
    const node_id = blk: {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        break :blk try f.db.nodeCreate("box1", "test box", &node_th, now() + 3600, now());
    };

    // --- tgnode registers with it
    const hw = try KeyPair.fromRawSeed(.user, @splat(0x72));
    const hw_pub = hw.publicKey().encode();
    const reg_subject = try std.fmt.allocPrint(ar, "register.{s}", .{&core.code.tokenId(node_code.token)});
    const reg_body = try std.fmt.allocPrint(ar, "{{\"hardware_key\":\"{s}\",\"status\":{{\"hostname\":\"box\",\"cpus\":4}}}}", .{&hw_pub});
    var inbox: [80]u8 = undefined;
    {
        const reg = try f.connect(hw, node_code.token, &inbox);
        defer reg.close();
        const r1 = try reg.request(reg_subject, reg_body, Conn.seconds(5));
        defer r1.deinit(a);
        try testing.expectEqualStrings("{\"status\":\"pending\"}", r1.payload);
    }
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const n = (try f.db.nodeGet(ar, node_id)).?;
        try testing.expectEqual(dbm.NodeState.pending, n.state);
        try testing.expectEqualStrings(&hw_pub, n.request_key.?);
        try testing.expect(std.mem.indexOf(u8, n.status.?, "\"cpus\":4") != null);
        try f.db.nodeApprove(node_id); // the admin approves
    }
    {
        const reg = try f.connect(hw, node_code.token, &inbox);
        defer reg.close();
        const r2 = try reg.request(reg_subject, reg_body, Conn.seconds(5));
        defer r2.deinit(a);
        try testing.expect(std.mem.indexOf(u8, r2.payload, "\"status\":\"approved\"") != null);
        try testing.expect(std.mem.indexOf(u8, r2.payload, "\"name\":\"box1\"") != null);
    }
    // The node key is used up now
    try testing.expectError(error.ServerRejected, f.connect(hw, node_code.token, &inbox));

    // --- The node connects with its hardware key and sends its system info
    var node_inbox: [32]u8 = undefined;
    const node = try Conn.connect(a, testing.io, .{ .port = port, .key = hw, .inbox_prefix = try std.fmt.bufPrint(&node_inbox, "_INBOX.box1", .{}), .tls = .{ .ca_pem = test_ca } });
    defer node.close();
    try node.publish("status.box1", "{\"cpus\":8}");
    try node.flush(Conn.seconds(5));
    var waited: u32 = 0;
    while (waited < 50) : (waited += 1) {
        f.lock.lockUncancelable(testing.io);
        const st = (try f.db.nodeGet(ar, node_id)).?.status.?;
        f.lock.unlock(testing.io);
        if (std.mem.eql(u8, st, "{\"cpus\":8}")) break;
        try testing.io.sleep(.fromMilliseconds(50), .awake);
    } else return error.StatusNotRecorded;

    // --- The admin invites Ali to "box*", once
    const inv_text = try newCode(a, 0x73);
    defer a.free(inv_text);
    const inv = try core.code.parse(inv_text);
    const inv_th = dbm.tokenHash(inv.token);
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        try f.db.terminalInvite(try terminalUser(&f.db, "ali"), .{ .nodes = "box*", .max_uses = 1 }, &inv_th, now() + 3600, now());
    }
    const ali = try KeyPair.fromRawSeed(.user, @splat(0x74));
    const ali_pub = ali.publicKey().encode();
    const grant_tok = blk: {
        const c = try f.connect(ali, inv.token, &inbox);
        defer c.close();
        const subject = try std.fmt.allocPrint(ar, "invite.{s}", .{&core.code.tokenId(inv.token)});
        const body = try std.fmt.allocPrint(ar, "{{\"user_key\":\"{s}\"}}", .{&ali_pub});
        const r = try c.request(subject, body, Conn.seconds(5));
        defer r.deinit(a);
        const Ans = struct { grant: []const u8 };
        const ans = try std.json.parseFromSliceLeaky(Ans, ar, r.payload, .{ .allocate = .alloc_always });
        break :blk ans.grant;
    };
    // Ali's key alone now connects (user permissions); the invitation is used up
    {
        const c = try f.connect(ali, null, &inbox);
        c.close();
    }
    try testing.expectError(error.ServerRejected, f.connect(ali, inv.token, &inbox));

    // --- box1 asks for approval of Ali's sessions: once allowed, then refused
    const issuer_pub = (try KeyPair.fromRawSeed(.account, @splat(0x1f))).publicKey().encode();
    const g = try core.grant.verify(ar, grant_tok, .{ .issuers = &.{&issuer_pub}, .node = "box1", .user = &ali_pub, .now = now() });
    // Each request carries both session public keys and the session keys
    // sealed to termgate
    const issuer_key = try core.nkeys.PublicKey.decode(&issuer_pub);
    const sk: core.e2e.Keys = .{ .up = @splat(0x51), .down = @splat(0x52) };
    const box1 = try core.e2e.sealForTermgate(ar, testing.io, issuer_key, sk, "SID1", "KXU", "KXN");
    const req1: core.approval.Request = .{ .grant = grant_tok, .node = "box1", .nonce = "n1", .sid = "SID1", .kx_user = "KXU", .kx_node = "KXN", .keys = box1 };
    const ans1 = try node.request("authorize.box1", try std.json.Stringify.valueAlloc(ar, req1, .{}), Conn.seconds(5));
    defer ans1.deinit(a);
    try core.approval.verify(ar, ans1.payload, .{ .issuers = &.{&issuer_pub}, .request = req1, .user = &ali_pub, .grant_jti = g.value.jti.?, .now = now() });

    // termgate kept the session's keys
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        try testing.expectEqualSlices(u8, &sk.down, &(try f.db.sessionKeys("SID1")).?.down);
    }

    const box2 = try core.e2e.sealForTermgate(ar, testing.io, issuer_key, sk, "SID2", "KXU", "KXN");
    const req2: core.approval.Request = .{ .grant = grant_tok, .node = "box1", .nonce = "n2", .sid = "SID2", .kx_user = "KXU", .kx_node = "KXN", .keys = box2 };
    const ans2 = try node.request("authorize.box1", try std.json.Stringify.valueAlloc(ar, req2, .{}), Conn.seconds(5));
    defer ans2.deinit(a);
    const e2: core.approval.Expect = .{ .issuers = &.{&issuer_pub}, .request = req2, .user = &ali_pub, .grant_jti = g.value.jti.?, .now = now() };
    try testing.expectError(error.Denied, core.approval.verify(ar, ans2.payload, e2));
    try testing.expectEqualStrings("no uses left", try core.approval.denialReason(ar, ans2.payload, e2));

    // --- While the session is open the node asks whether termgate is there
    {
        const alive = try node.request("audit.box1", "{\"event\":\"alive\",\"sid\":\"\",\"at\":1}", Conn.seconds(5));
        defer alive.deinit(a);
        try testing.expectEqualStrings("ok", alive.payload);
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        try testing.expectEqual(@as(usize, 1), (try f.db.sessionsActive(ar)).len);
    }

    // --- The session ends; the node reports it
    const end = try node.request("audit.box1", "{\"event\":\"end\",\"sid\":\"SID1\",\"at\":1,\"status\":0}", Conn.seconds(5));
    end.deinit(a);
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const sessions = try f.db.sessionsRecent(ar, 10);
        try testing.expectEqual(@as(usize, 1), sessions.len);
        try testing.expectEqualStrings("ali", sessions[0].user);
        try testing.expectEqual(@as(?i64, 1), sessions[0].ended);
    }
}

/// Waits until `c` is closed by the relay.
fn waitClosed(c: *Conn) !void {
    var tries: u32 = 0;
    while (tries < 100) : (tries += 1) {
        if (c.isClosed()) return;
        try testing.io.sleep(.fromMilliseconds(50), .awake);
    }
    return error.NotClosed;
}

test "strangers get only the CA; revoked access closes the connection" {
    const a = testing.allocator;
    var f: Fixture = .{ .db = undefined };
    try f.start();
    defer f.stop();
    var inbox: [80]u8 = undefined;

    const stranger = try KeyPair.fromRawSeed(.user, @splat(0x75));
    const c = try f.connect(stranger, null, &inbox);
    defer c.close();
    const ca = try c.request("ca.get", "", Conn.seconds(5));
    defer ca.deinit(a);
    try testing.expectEqualStrings(test_ca, ca.payload);
    try c.publish("authorize.box1", "{}");
    try c.flush(Conn.seconds(5));
    try testing.expect(std.mem.indexOf(u8, c.lastError(), "Permissions Violation") != null);
    try testing.expectError(error.ServerRejected, f.connect(stranger, "not-a-code", &inbox));

    // Revoking a user's terminal access closes its open connection, and the
    // callout refuses them afterwards
    const th = dbm.tokenHash("TOK");
    const bob = try KeyPair.fromRawSeed(.user, @splat(0x76));
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const id = try terminalUser(&f.db, "bob");
        try f.db.terminalInvite(id, .{ .nodes = "*", .max_uses = 1 }, &th, now() + 60, now());
        try f.db.terminalRedeem(id, &bob.publicKey().encode(), "JTIBOB", "x", 1, null);
    }
    const ok = try f.connect(bob, null, &inbox);
    defer ok.close();
    {
        f.lock.lockUncancelable(testing.io);
        defer f.lock.unlock(testing.io);
        const p = (try f.db.terminalByKey(a, &bob.publicKey().encode())).?;
        defer {
            a.free(p.name);
            a.free(p.nodes);
            a.free(p.user_key.?);
        }
        try f.db.terminalRevoke(p.id);
    }
    f.service.kickUser(&bob.publicKey().encode());
    try waitClosed(ok);
    // Falls back to anonymous: connected, but may do nothing except ca.get
    const after = try f.connect(bob, null, &inbox);
    defer after.close();
    try after.publish("session.open.box1", "{}");
    try after.flush(Conn.seconds(5));
    try testing.expect(std.mem.indexOf(u8, after.lastError(), "Permissions Violation") != null);
}
