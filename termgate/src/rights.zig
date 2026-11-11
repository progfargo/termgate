//! The rights a role can give: a module and one of its actions. Stored in
//! roleRight as two texts; written "module:action" where one string is
//! handier. The server checks them on every call; the panel shows only
//! what the signed-in user may do.

const std = @import("std");

pub const Action = struct {
    name: []const u8,
    title: []const u8,
};

pub const Module = struct {
    name: []const u8,
    title: []const u8,
    actions: []const Action,
};

const browse: Action = .{ .name = "browse", .title = "Browse" };
const insert: Action = .{ .name = "insert", .title = "Insert" };
const update: Action = .{ .name = "update", .title = "Update" };
const delete: Action = .{ .name = "delete", .title = "Delete" };

pub const modules = [_]Module{
    // Signing in to this panel; a user without it (a terminal user, a bot)
    // cannot
    .{ .name = "panel", .title = "Panel", .actions = &.{.{ .name = "login", .title = "Sign in" }} },
    .{ .name = "node", .title = "Nodes", .actions = &.{ browse, insert, update, delete } },
    .{ .name = "session", .title = "Sessions", .actions = &.{
        browse,
        .{ .name = "watch", .title = "Watch" },
        .{ .name = "log", .title = "Read logs" },
        .{ .name = "end", .title = "End" },
    } },
    .{ .name = "audit", .title = "Audit", .actions = &.{browse} },
    // As in our earlier project: each user and role operation is its own right
    .{ .name = "user", .title = "Users", .actions = &.{
        browse,
        insert,
        update,
        .{ .name = "update_pass", .title = "Reset password" },
        delete,
        .{ .name = "select", .title = "Act as another user" },
        .{ .name = "unselect", .title = "Stop acting as another user" },
        .{ .name = "role_browse", .title = "See roles" },
        .{ .name = "role_grant", .title = "Give roles" },
        .{ .name = "role_revoke", .title = "Take roles" },
        .{ .name = "access", .title = "Give terminal access" },
    } },
    .{ .name = "role", .title = "Roles", .actions = &.{
        browse,
        insert,
        update,
        delete,
        .{ .name = "role_right", .title = "Change rights" },
    } },
    .{ .name = "profile", .title = "Profile", .actions = &.{
        browse,
        .{ .name = "update_password", .title = "Change own password" },
    } },
    .{ .name = "config", .title = "Configuration", .actions = &.{ browse, update } },
    // Opening terminal sessions on nodes with tgterm (the user's terminal
    // access says which nodes and as whom)
    .{ .name = "terminal", .title = "Terminal", .actions = &.{.{ .name = "connect", .title = "Connect to nodes" }} },
};

/// Is module:action in the list above.
pub fn exists(module: []const u8, action: []const u8) bool {
    for (modules) |m| {
        if (!std.mem.eql(u8, m.name, module)) continue;
        for (m.actions) |ac| if (std.mem.eql(u8, ac.name, action)) return true;
    }
    return false;
}

/// Splits "module:action"; null if it is not a right in the list.
pub fn parse(right: []const u8) ?struct { module: []const u8, action: []const u8 } {
    const colon = std.mem.indexOfScalar(u8, right, ':') orelse return null;
    if (!exists(right[0..colon], right[colon + 1 ..])) return null;
    return .{ .module = right[0..colon], .action = right[colon + 1 ..] };
}

/// Is "module:action" in `list`.
pub fn has(list: []const []const u8, module: []const u8, action: []const u8) bool {
    for (list) |r| {
        if (r.len == module.len + 1 + action.len and std.mem.startsWith(u8, r, module) and r[module.len] == ':' and std.mem.endsWith(u8, r, action)) return true;
    }
    return false;
}

test "exists, parse, has" {
    try std.testing.expect(exists("user", "role_grant"));
    try std.testing.expect(!exists("user", "fly"));
    try std.testing.expect(!exists("ship", "browse"));
    try std.testing.expectEqualStrings("watch", parse("session:watch").?.action);
    try std.testing.expect(parse("session") == null);
    try std.testing.expect(parse("session:fly") == null);
    try std.testing.expect(has(&.{ "node:browse", "user:role_grant" }, "user", "role_grant"));
    try std.testing.expect(!has(&.{"node:browse"}, "node", "brow"));
}
