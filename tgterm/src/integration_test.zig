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

fn now() i64 {
    return @intCast(@divFloor(std.Io.Timestamp.now(testing.io, .real).nanoseconds, std.time.ns_per_s));
}

test "an invitation gives a key, a grant and user permissions; it works once" {
    const a = testing.allocator;
    const io = testing.io;
    const t = try tg.Termgate.start(a, io, test_ca);
    defer t.stop();

    // The admin invites someone to "ist_*" for 3 sessions
    const fp = try core.code.caFingerprint(a, test_ca);
    const invitation = try core.code.format(a, "127.0.0.1", tg.port, fp, @splat(0x61));
    defer a.free(invitation);
    t.expectInvitation((try core.code.parse(invitation)).token, .{ .user = "", .nodes = &.{"ist_*"}, .run_as = "root", .max_uses = 3 });

    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const p = try invite.redeem(a, arena.allocator(), io, invitation);
    try testing.expectEqualStrings("127.0.0.1", p.relay_host);
    try testing.expectEqualStrings(test_ca, p.ca_pem);

    // The grant is for the key tgterm generated
    const key = try core.nkeys.KeyPair.decodeSeed(p.seed);
    const kpub = key.publicKey().encode();
    const g = try core.grant.verify(a, p.grant, .{ .issuers = &.{&t.issuer_pub}, .node = "ist_kadikoy_gw01", .user = &kpub, .now = now() });
    defer g.deinit();
    try testing.expectEqual(@as(?u32, 3), g.value.nats.max_uses);

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
    t.expectInvitation((try core.code.parse(invitation)).token, .{ .user = "", .nodes = &.{"*"}, .run_as = "root", .max_uses = 1 });
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    try testing.expectError(error.WrongCa, invite.redeem(a, arena.allocator(), io, invitation));
    // The token was never presented, so the invitation is still open
    try testing.expect(t.invite_token != null);
}
