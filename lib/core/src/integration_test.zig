//! Tests against a real nats-server. Run with `zig build test -Dnats-test`
//! after starting the servers described in CLAUDE.md (testdata/).

const std = @import("std");
const testing = std.testing;
const nkeys = @import("nkeys.zig");
const Conn = @import("nats/Conn.zig");

/// testdata/nats-open.conf: no authentication
const open_port = 14222;
/// testdata/nats-nkey.conf: one nkey user, seed = 32 x 0x02
const nkey_port = 14223;
/// testdata/nats-tls.conf: TLS first, certificate signed by testdata/ca.pem
const tls_port = 14224;

const second = Conn.seconds(2);

test "publish and receive on an open server" {
    const c = try Conn.connect(testing.allocator, testing.io, .{ .port = open_port, .echo = true });
    defer c.close();

    const s = try c.subscribe("t.>");
    try c.publish("t.a", "hello");
    try c.publish("t.b", "line\r\nwith CRLF");
    try c.publish("other", "not for us");

    const m1 = try s.next(second);
    defer m1.deinit(testing.allocator);
    try testing.expectEqualStrings("t.a", m1.subject);
    try testing.expectEqualStrings("hello", m1.payload);

    const m2 = try s.next(second);
    defer m2.deinit(testing.allocator);
    try testing.expectEqualStrings("line\r\nwith CRLF", m2.payload);

    try testing.expectError(error.Timeout, s.next(Conn.millis(200)));
    s.unsubscribe();
    try c.flush(second);
}

test "large payload and reply subject" {
    const a = testing.allocator;
    const c = try Conn.connect(a, testing.io, .{ .port = open_port, .echo = true });
    defer c.close();

    const big = try a.alloc(u8, 900 * 1024);
    defer a.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);

    const s = try c.subscribe("big");
    try c.publishReply("big", "_INBOX.x.1", big);
    const m = try s.next(second);
    defer m.deinit(a);
    try testing.expectEqualStrings("_INBOX.x.1", m.reply.?);
    try testing.expectEqualSlices(u8, big, m.payload);
}

test "nkey authentication signs the server nonce" {
    const a = testing.allocator;
    const good = try nkeys.KeyPair.fromRawSeed(.user, @splat(2));
    const c = try Conn.connect(a, testing.io, .{ .port = nkey_port, .key = good });
    try c.flush(second);
    c.close();

    const bad = try nkeys.KeyPair.fromRawSeed(.user, @splat(3));
    try testing.expectError(error.ServerRejected, Conn.connect(a, testing.io, .{ .port = nkey_port, .key = bad }));
    try testing.expectError(error.ServerRejected, Conn.connect(a, testing.io, .{ .port = nkey_port }));
}

test "request and reply" {
    const a = testing.allocator;
    const server = try Conn.connect(a, testing.io, .{ .port = open_port });
    defer server.close();
    const client = try Conn.connect(a, testing.io, .{ .port = open_port, .inbox_prefix = "_INBOX.U1" });
    defer client.close();

    const s = try server.subscribe("session.open.gw17");
    try server.flush(second);

    // Answer one request from another task
    const Responder = struct {
        fn run(sub: *Conn.Sub, conn: *Conn) !void {
            const req = try sub.next(second);
            defer req.deinit(conn.gpa);
            try testing.expect(std.mem.startsWith(u8, req.reply.?, "_INBOX.U1."));
            try conn.publishReply(req.reply.?, null, "sid-1");
        }
    };
    var task = try testing.io.concurrent(Responder.run, .{ s, server });
    const reply = try client.request("session.open.gw17", "{}", second);
    defer reply.deinit(a);
    try testing.expectEqualStrings("sid-1", reply.payload);
    try task.await(testing.io);

    try testing.expectError(error.NoResponders, client.request("session.open.nobody", "{}", second));
}

test "TLS with the trusted CA" {
    const a = testing.allocator;
    const c = try Conn.connect(a, testing.io, .{ .port = tls_port, .echo = true, .tls = .{ .ca_pem = @embedFile("test_ca") } });
    defer c.close();
    const s = try c.subscribe("t.tls");
    const big = try a.alloc(u8, 900 * 1024);
    defer a.free(big);
    @memset(big, 'z');
    try c.publish("t.tls", big);
    const m = try s.next(second);
    defer m.deinit(a);
    try testing.expectEqualSlices(u8, big, m.payload);
}

test "TLS with another CA is refused" {
    try testing.expectError(error.TlsFailed, Conn.connect(testing.allocator, testing.io, .{
        .port = tls_port,
        .tls = .{ .ca_pem = @embedFile("test_other_ca") },
    }));
}

// ---------------------------------------------------------------------------
// Auth callout (testdata/nats-callout.conf)

const callout = @import("callout.zig");
const callout_port = 14226;

/// Stands in for termgate: answers authorization requests. Allows the key
/// with seed 32 x 0x28 or a connection whose token is "node-key-1"; refuses
/// everything else.
fn calloutService(svc: *Conn, sub: *Conn.Sub, issuer: nkeys.KeyPair, served: *std.atomic.Value(u32)) !void {
    const a = testing.allocator;
    const known = (try nkeys.KeyPair.fromRawSeed(.user, @splat(0x28))).publicKey().encode();
    while (true) {
        const m = sub.next(Conn.millis(200)) catch |e| switch (e) {
            error.Timeout => continue,
            else => return,
        };
        defer m.deinit(a);
        const req = try callout.decodeRequest(a, m.payload, t_now_live());
        defer req.deinit();
        const r = req.value.nats;
        const decision: callout.Decision = blk: {
            const key = callout.clientKey(r) catch break :blk .{ .deny = "no valid key" };
            const by_key = std.mem.eql(u8, &key.encode(), &known);
            const by_token = if (r.connect_opts.auth_token) |t| std.mem.eql(u8, t, "node-key-1") else false;
            if (!by_key and !by_token) break :blk .{ .deny = "unknown" };
            break :blk .{ .allow = .{
                .name = "gw17",
                .account = "APP",
                .permissions = .{
                    .@"pub" = .{ .allow = &.{ "hello.gw17", "_INBOX.>" } },
                    .sub = .{ .allow = &.{ "hello.gw17", "_INBOX.>" } },
                },
            } };
        };
        const resp = try callout.respond(a, issuer, r, decision, t_now_live());
        defer a.free(resp);
        try svc.publish(m.reply.?, resp);
        _ = served.fetchAdd(1, .release);
    }
}

fn t_now_live() i64 {
    return @intCast(@divFloor(std.Io.Timestamp.now(testing.io, .real).nanoseconds, std.time.ns_per_s));
}

test "auth callout: termgate decides every connection" {
    const a = testing.allocator;
    const svc_key = try nkeys.KeyPair.fromRawSeed(.user, @splat(0x1e));
    const issuer = try nkeys.KeyPair.fromRawSeed(.account, @splat(0x1f));

    // termgate's own connection bypasses the callout
    const svc = try Conn.connect(a, testing.io, .{ .port = callout_port, .key = svc_key });
    defer svc.close();
    const sub = try svc.subscribe(callout.subject);
    try svc.flush(second);
    var served: std.atomic.Value(u32) = .init(0);
    var task = try testing.io.concurrent(calloutService, .{ svc, sub, issuer, &served });
    defer task.cancel(testing.io) catch {};

    // A known key gets in, with exactly the permissions termgate gave
    const known = try nkeys.KeyPair.fromRawSeed(.user, @splat(0x28));
    const c1 = try Conn.connect(a, testing.io, .{ .port = callout_port, .key = known });
    try c1.publish("hello.gw17", "hi");
    try c1.flush(second);
    try testing.expectEqualStrings("", c1.lastError());
    try c1.publish("hello.gw18", "not allowed");
    try c1.flush(second);
    try testing.expect(std.mem.indexOf(u8, c1.lastError(), "Permissions Violation") != null);
    c1.close();

    // A new key with a valid node key (token) gets in
    const fresh = try nkeys.KeyPair.fromRawSeed(.user, @splat(0x29));
    const c2 = try Conn.connect(a, testing.io, .{ .port = callout_port, .key = fresh, .token = "node-key-1" });
    try c2.flush(second);
    c2.close();

    // Unknown key, wrong token, no key: refused
    try testing.expectError(error.ServerRejected, Conn.connect(a, testing.io, .{ .port = callout_port, .key = fresh }));
    try testing.expectError(error.ServerRejected, Conn.connect(a, testing.io, .{ .port = callout_port, .key = fresh, .token = "wrong" }));
    try testing.expectError(error.ServerRejected, Conn.connect(a, testing.io, .{ .port = callout_port, .token = "node-key-1" }));
    try testing.expect(served.load(.acquire) >= 5);
}

test "CA fingerprint of the test CA" {
    const code = @import("code.zig");
    const fp = try code.caFingerprint(testing.allocator, @embedFile("test_ca"));
    // openssl x509 -in testdata/ca.pem -outform der | sha256sum
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "d0292ed433f7687a8c3d1355e8ffb9ebfd7fafa991c7756e9d877b34094d0e40");
    try testing.expectEqualSlices(u8, &want, &fp);
    const other = try code.caFingerprint(testing.allocator, @embedFile("test_other_ca"));
    try testing.expect(!std.mem.eql(u8, &fp, &other));
}

test "TLS without verification (registration's first step)" {
    const c = try Conn.connect(testing.allocator, testing.io, .{ .port = tls_port, .tls = .{ .ca_pem = "", .insecure = true } });
    defer c.close();
    try c.flush(second);
}
