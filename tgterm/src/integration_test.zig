//! Terminal access key tests against the relay's real setup (TLS + auth callout,
//! lib/core/testdata/nats-callout-tls.conf) with core.standin standing in for
//! termgate. Run with `zig build test -Dnats-test`.

const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Conn = core.nats.Conn;
const tg = core.standin;
const access_key = @import("access_key.zig");
const test_ca = @embedFile("test_ca");

test "an access key gives a key and user permissions; it works once" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try tg.Termgate.start(a, io, test_ca);
    defer t.stop();

    // The admin gives someone an access key
    const fp = try core.code.caFingerprint(a, test_ca);
    const access_key_text = try core.code.format(a, "127.0.0.1", tg.port, fp, @splat(0x61));
    defer a.free(access_key_text);
    t.expectAccessKey((try core.code.parse(access_key_text)).token);

    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const p = try access_key.use(a, arena.allocator(), io, access_key_text);
    try testing.expectEqualStrings("127.0.0.1", p.relay_host);
    try testing.expectEqualStrings(test_ca, p.ca_pem);

    // termgate's issuer key, which signs the approvals; nothing else
    try testing.expectEqualStrings(&t.issuer_pub, p.issuer);
    const key = try core.nkeys.KeyPair.decodeSeed(p.seed);
    const kpub = key.publicKey().encode();

    // From now on the key alone is enough, with user permissions
    var inbox_buf: [80]u8 = undefined;
    const conn = try Conn.connect(a, io, .{
        .port = tg.port,
        .key = key,
        .inbox_prefix = try std.fmt.bufPrint(&inbox_buf, "_INBOX.{s}", .{kpub}),
        .tls = .{ .ca_pem = p.ca_pem },
    });
    defer conn.close();
    _ = try conn.subscribe(try std.fmt.allocPrint(arena.allocator(), "out.*.{s}.>", .{kpub}));
    try conn.flush(Conn.seconds(5));
    try testing.expectEqualStrings("", conn.lastError());

    // The access key cannot be used a second time
    try testing.expectError(error.Refused, access_key.use(a, arena.allocator(), io, access_key_text));
}

test "an access key for a different relay CA sends no token" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try tg.Termgate.start(a, io, test_ca);
    defer t.stop();
    const access_key_text = try core.code.format(a, "127.0.0.1", tg.port, @splat(7), @splat(0x62));
    defer a.free(access_key_text);
    t.expectAccessKey((try core.code.parse(access_key_text)).token);
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try testing.expectError(error.WrongCa, access_key.use(a, arena.allocator(), io, access_key_text));
    // The token was never presented, so the access key is still open
    try testing.expect(t.access_token != null);
}
