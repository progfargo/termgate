//! What each kind of connection may publish and subscribe to. termgate puts
//! these into its auth callout answers; this file is the single source of the
//! permission table in docs/architecture.md.

const std = @import("std");
const jwt = @import("jwt.zig");

/// A registered node, `name`, by its hardware key `key`. Strings live in
/// `arena`. It may also ask for the CA (ca.get, answered to the inbox of
/// its key), as anyone may: running the registration again with a used node
/// key then hears the key refused instead of waiting for an answer.
pub fn node(arena: std.mem.Allocator, name: []const u8, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 5);
    pubs[0] = try std.fmt.allocPrint(arena, "status.{s}", .{name});
    pubs[1] = try std.fmt.allocPrint(arena, "authorize.{s}", .{name});
    pubs[2] = try std.fmt.allocPrint(arena, "audit.{s}", .{name});
    pubs[3] = try std.fmt.allocPrint(arena, "out.{s}.>", .{name});
    pubs[4] = "ca.get";
    const subs = try arena.alloc([]const u8, 6);
    subs[0] = try std.fmt.allocPrint(arena, "session.open.{s}", .{name});
    subs[1] = try std.fmt.allocPrint(arena, "status.req.{s}", .{name});
    subs[2] = "status.req.all";
    subs[3] = try std.fmt.allocPrint(arena, "in.{s}.>", .{name});
    subs[4] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{name});
    subs[5] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{key});
    // Replies to session.open requests go to the requester's inbox
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs }, .resp = .{ .max = 1 } };
}

/// A user, by its public key ("U...").
pub fn user(arena: std.mem.Allocator, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 2);
    pubs[0] = "session.open.*";
    pubs[1] = try std.fmt.allocPrint(arena, "in.*.{s}.>", .{key});
    const subs = try arena.alloc([]const u8, 2);
    subs[0] = try std.fmt.allocPrint(arena, "out.*.{s}.>", .{key});
    subs[1] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{key});
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs } };
}

/// A node that is registering: it may only send its registration request
/// (subject register.<token id>) and read the answer.
pub fn registering(arena: std.mem.Allocator, token_id: []const u8, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 1);
    pubs[0] = try std.fmt.allocPrint(arena, "register.{s}", .{token_id});
    const subs = try arena.alloc([]const u8, 1);
    subs[0] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{key});
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs } };
}

/// Someone using an access key: may only send their public key to
/// access.<token id> and read the answer (termgate's issuer key).
pub fn usingAccessKey(arena: std.mem.Allocator, token_id: []const u8, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 1);
    pubs[0] = try std.fmt.allocPrint(arena, "access.{s}", .{token_id});
    const subs = try arena.alloc([]const u8, 1);
    subs[0] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{key});
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs } };
}

/// Anyone with a valid nonce signature: may only ask for termgate's CA
/// certificate (ca.get), which a registering node needs before it can verify
/// the relay. The CA certificate is public.
pub fn anonymous(arena: std.mem.Allocator, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 1);
    pubs[0] = "ca.get";
    const subs = try arena.alloc([]const u8, 1);
    subs[0] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{key});
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs } };
}

/// termgate's own connection to the application account.
pub fn termgate() jwt.UserNats {
    return .{ .@"pub" = .{ .allow = &.{">"} }, .sub = .{ .allow = &.{">"} } };
}
