//! The panel's API as in our earlier project: POST /api/<page>/<function>, JSON in
//! and out. Each path stands for one of termgate's calls (auth.zig for
//! users, roles, profile and signing in; panel.zig for nodes, people,
//! sessions, audit and configuration), so the rules and their tests stay
//! in one place; this file gives them our earlier project's paths and answers.
//!
//! The answer is the call's JSON object with `messages` added (name, type
//! error/warning/info/success, lines), as our earlier project's ctx.Render. A rule
//! that refuses (a name taken, the last admin) is a warning with status
//! 200; a missing right is 400, a missing record 404, not being signed in
//! 401.

const std = @import("std");
const auth_mod = @import("auth.zig");

/// A path and the call it stands for.
const Route = struct { path: []const u8, call: []const u8 };

const routes = [_]Route{
    // Signing in and out
    .{ .path = "login", .call = "login" },
    .{ .path = "login/code", .call = "login2" },
    .{ .path = "logout", .call = "logout" },
    // Users (auth.zig)
    .{ .path = "user/browse", .call = "users.list" },
    .{ .path = "user/insert", .call = "users.create" },
    .{ .path = "user/update", .call = "users.update" },
    .{ .path = "user/update_pass", .call = "users.reset" },
    .{ .path = "user/delete", .call = "users.delete" },
    .{ .path = "user/role_grant", .call = "users.grant" },
    .{ .path = "user/role_revoke", .call = "users.revoke" },
    .{ .path = "user/select", .call = "users.select" },
    .{ .path = "user/unselect", .call = "users.unselect" },
    // Roles
    .{ .path = "role/browse", .call = "roles.list" },
    .{ .path = "role/get", .call = "roles.get" },
    .{ .path = "role/insert", .call = "roles.insert" },
    .{ .path = "role/update", .call = "roles.update" },
    .{ .path = "role/delete", .call = "roles.delete" },
    // Profile
    .{ .path = "profile/update_pass", .call = "profile.password" },
};

/// The call a panel path stands for; null if it is not one.
pub fn route(path: []const u8) ?[]const u8 {
    for (routes) |r| if (std.mem.eql(u8, path, r.path)) return r.call;
    return null;
}

pub const Answer = struct { status: std.http.Status, body: []const u8, ok: bool };

/// init: who is signed in (null: nobody) and its rights, as `me`; and
/// whether signing in asks for the second step.
pub fn init(auth: *auth_mod.Auth, a: std.mem.Allocator, token: ?[]const u8, now: i64) ![]const u8 {
    const me = (try auth_mod.call(auth, a, "me", "{}", token, now)).?;
    const user: std.json.Value = if (me.status == .ok)
        try std.json.parseFromSliceLeaky(std.json.Value, a, me.body, .{})
    else
        .null;
    return try std.json.Stringify.valueAlloc(a, .{
        .user = user,
        .second_step = auth_mod.second_step,
        .messages = &[_]Message{},
    }, .{});
}

pub const Message = struct {
    name: []const u8,
    type: []const u8,
    lines: []const []const u8,
};

/// A call's answer in our earlier project's form: its object with `messages`. The
/// calls answer {"error": text} (auth.zig) or {"ok": value} / {"err":
/// Name} (the database calls); an error becomes a message, `ok` the
/// answer's `data`.
pub fn answer(a: std.mem.Allocator, status: std.http.Status, body: []const u8) !Answer {
    var obj: std.json.ObjectMap = .empty;
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch std.json.Value{ .null = {} };
    if (parsed == .object) {
        var it = parsed.object.iterator();
        while (it.next()) |e| try obj.put(a, e.key_ptr.*, e.value_ptr.*);
    }
    var text: ?[]const u8 = null;
    if (obj.fetchSwapRemove("error")) |e| text = if (e.value == .string) e.value.string else null;
    if (obj.fetchSwapRemove("err")) |e| text = if (e.value == .string) errText(e.value.string) else null;
    if (obj.fetchSwapRemove("ok")) |e| if (e.value != .bool) try obj.put(a, "data", e.value);

    // our earlier project's statuses: a refused rule is a warning on a good answer
    const out_status: std.http.Status = switch (status) {
        .ok => .ok,
        .conflict, .bad_request, .too_many_requests => .ok,
        .forbidden => .bad_request,
        else => status,
    };
    const failed = text != null or status != .ok;
    var messages: std.json.Array = .init(a);
    if (text) |t| {
        var m: std.json.ObjectMap = .empty;
        try m.put(a, "name", .{ .string = @tagName(status) });
        try m.put(a, "type", .{ .string = if (status == .ok or out_status == .ok) "warning" else "error" });
        var lines: std.json.Array = .init(a);
        try lines.append(.{ .string = sentence(a, t) });
        try m.put(a, "lines", .{ .array = lines });
        try messages.append(.{ .object = m });
    }
    try obj.put(a, "messages", .{ .array = messages });
    return .{
        .status = out_status,
        .body = try std.json.Stringify.valueAlloc(a, std.json.Value{ .object = obj }, .{}),
        .ok = !failed,
    };
}

/// The database calls' error names in words.
fn errText(name: []const u8) []const u8 {
    const map = [_]struct { []const u8, []const u8 }{
        .{ "Duplicate", "this name is taken" },
        .{ "NotFound", "the record could not be found" },
        .{ "InvalidName", "the name is not valid" },
        .{ "InvalidSpec", "check the fields: something is missing or not valid" },
        .{ "InUse", "the record is in use" },
    };
    for (map) |m| if (std.mem.eql(u8, m[0], name)) return m[1];
    return name;
}

/// "this name is taken" -> "This name is taken."
fn sentence(a: std.mem.Allocator, text: []const u8) []const u8 {
    if (text.len == 0) return text;
    const s = std.fmt.allocPrint(a, "{s}{s}", .{ text, if (text[text.len - 1] == '.') "" else "." }) catch return text;
    s[0] = std.ascii.toUpper(s[0]);
    return s;
}

test "answers in our earlier project's form" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const ok = try answer(a, .ok, "{\"ok\":true,\"id\":3}");
    try std.testing.expectEqualStrings("{\"id\":3,\"messages\":[]}", ok.body);
    const refused = try answer(a, .conflict, "{\"error\":\"the last admin cannot be deleted\"}");
    try std.testing.expectEqual(std.http.Status.ok, refused.status);
    try std.testing.expect(!refused.ok);
    try std.testing.expect(std.mem.indexOf(u8, refused.body, "\"lines\":[\"The last admin cannot be deleted.\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, refused.body, "\"type\":\"warning\"") != null);
    const no_right = try answer(a, .forbidden, "{\"error\":\"you do not have the right to do this\"}");
    try std.testing.expectEqual(std.http.Status.bad_request, no_right.status);
    const data = try answer(a, .ok, "{\"ok\":[1,2]}");
    try std.testing.expectEqualStrings("{\"data\":[1,2],\"messages\":[]}", data.body);
    const db_err = try answer(a, .ok, "{\"err\":\"Duplicate\"}");
    try std.testing.expect(std.mem.indexOf(u8, db_err.body, "This name is taken.") != null);
}
