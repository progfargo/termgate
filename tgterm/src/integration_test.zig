//! Invitation tests against the relay's real setup (TLS + auth callout,
//! lib/core/testdata/nats-callout-tls.conf) with core.standin standing in for
//! termgate. Run with `zig build test -Dnats-test`.

const std = @import("std");
const testing = std.testing;
const core = @import("core");
const Conn = core.nats.Conn;
const tg = core.standin;
const invite = @import("invite.zig");
const test_ca = @embedFile("test_ca");

test "an invitation gives a key and user permissions; it works once" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try tg.Termgate.start(a, io, test_ca);
    defer t.stop();

    // The admin invites someone
    const fp = try core.code.caFingerprint(a, test_ca);
    const invitation = try core.code.format(a, "127.0.0.1", tg.port, fp, @splat(0x61));
    defer a.free(invitation);
    t.expectInvitation((try core.code.parse(invitation)).token);

    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const p = try invite.redeem(a, arena.allocator(), io, invitation);
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

    // The invitation cannot be used a second time
    try testing.expectError(error.Refused, invite.redeem(a, arena.allocator(), io, invitation));
}

test "an invitation for a different relay CA sends no token" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try tg.Termgate.start(a, io, test_ca);
    defer t.stop();
    const invitation = try core.code.format(a, "127.0.0.1", tg.port, @splat(7), @splat(0x62));
    defer a.free(invitation);
    t.expectInvitation((try core.code.parse(invitation)).token);
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try testing.expectError(error.WrongCa, invite.redeem(a, arena.allocator(), io, invitation));
    // The token was never presented, so the invitation is still open
    try testing.expect(t.invite_token != null);
}
