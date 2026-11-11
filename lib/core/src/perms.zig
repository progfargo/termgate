//! What each kind of connection may publish and subscribe to. termgate puts
//! these into its auth callout answers; this file is the single source of the
//! permission table in docs/architecture.md.

const std = @import("std");
const jwt = @import("jwt.zig");

/// Strings live in `arena`.
pub fn node(arena: std.mem.Allocator, name: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 4);
    pubs[0] = try std.fmt.allocPrint(arena, "status.{s}", .{name});
    pubs[1] = try std.fmt.allocPrint(arena, "authorize.{s}", .{name});
    pubs[2] = try std.fmt.allocPrint(arena, "audit.{s}", .{name});
    pubs[3] = try std.fmt.allocPrint(arena, "out.{s}.>", .{name});
    const subs = try arena.alloc([]const u8, 5);
    subs[0] = try std.fmt.allocPrint(arena, "session.open.{s}", .{name});
    subs[1] = try std.fmt.allocPrint(arena, "status.req.{s}", .{name});
    subs[2] = "status.req.all";
    subs[3] = try std.fmt.allocPrint(arena, "in.{s}.>", .{name});
    subs[4] = try std.fmt.allocPrint(arena, "_INBOX.{s}.>", .{name});
    // Replies to session.open requests go to the requester's inbox
    return .{ .@"pub" = .{ .allow = pubs }, .sub = .{ .allow = subs }, .resp = .{ .max = 1 } };
}

/// A person or bot, by their public key ("U...").
pub fn user(arena: std.mem.Allocator, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 4);
    pubs[0] = "session.open.*";
    pubs[1] = try std.fmt.allocPrint(arena, "in.*.{s}.>", .{key});
    pubs[2] = try std.fmt.allocPrint(arena, "bot.status.{s}", .{key});
    pubs[3] = try std.fmt.allocPrint(arena, "bot.ask.{s}", .{key});
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

/// Someone using an invitation: may only send their public key to
/// invite.<token id> and read the answer (their grant).
pub fn redeeming(arena: std.mem.Allocator, token_id: []const u8, key: []const u8) !jwt.UserNats {
    const pubs = try arena.alloc([]const u8, 1);
    pubs[0] = try std.fmt.allocPrint(arena, "invite.{s}", .{token_id});
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
