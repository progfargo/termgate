//! Using a terminal access key (tgterm --access-key tg1-...).
//!
//! 1. Generate the user's key pair; the private key never leaves this machine.
//! 2. Fetch termgate's CA and check it against the access key's fingerprint
//!    (core.bootstrap.fetchCa); nothing secret is sent before that.
//! 3. Connect, verifying the relay, with the access key's token as auth token,
//!    and send the public key to access.<token id>. termgate binds the key to
//!    the user, uses up the token and answers with its issuer key (which
//!    signs session approvals).
//! 4. Return the profile to store.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const Profile = @import("profile.zig").Profile;

pub const Error = error{
    /// termgate refused the access key (unknown, used or expired)
    Refused,
};

/// Uses a terminal access key. Connections use `gpa`; strings of the returned profile
/// live in `arena`.
pub fn use(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, access_key: []const u8) !Profile {
    const code = try core.code.parse(access_key);
    const key = try core.nkeys.KeyPair.generate(.user, io);
    const kpub = key.publicKey().encode();
    const inbox = try std.fmt.allocPrint(arena, "_INBOX.{s}", .{kpub});

    const ca_pem = try core.bootstrap.fetchCa(gpa, arena, io, code, key, inbox, "tgterm");

    const conn = Conn.connect(gpa, io, .{
        .host = code.host,
        .port = code.port,
        .key = key,
        .token = code.token,
        .name = "tgterm",
        .inbox_prefix = inbox,
        .tls = .{ .ca_pem = ca_pem },
    }) catch |e| switch (e) {
        error.ServerRejected => return error.Refused,
        else => return e,
    };
    defer conn.close();

    const token_id = core.code.tokenId(code.token);
    var subj_buf: [64]u8 = undefined;
    const subject = try std.fmt.bufPrint(&subj_buf, "access.{s}", .{&token_id});
    const body = try std.json.Stringify.valueAlloc(arena, .{ .user_key = @as([]const u8, &kpub) }, .{});
    const m = conn.request(subject, body, Conn.seconds(15)) catch |e| switch (e) {
        error.NoResponders, error.Timeout => return error.TermgateOffline,
        else => return e,
    };
    defer m.deinit(gpa);
    const Answer = struct { issuer: ?[]const u8 = null, @"error": ?[]const u8 = null };
    const ans = std.json.parseFromSliceLeaky(Answer, arena, m.payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch
        return error.Refused;
    const issuer = ans.issuer orelse return error.Refused;

    const seed = key.encodeSeed();
    return .{
        .relay_host = try arena.dupe(u8, code.host),
        .relay_port = code.port,
        .ca_pem = ca_pem,
        .seed = try arena.dupe(u8, &seed),
        .issuer = issuer,
    };
}
