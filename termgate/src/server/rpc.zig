//! The calls the panel's screens make (POST /api/<name>, JSON).
//!
//! `db.<method>`: one of termgate's database functions, by name. Only the
//! functions listed here can be called, each with the right it names
//! (rights.zig). The body is a JSON array of the function's arguments
//! (without the database and the allocator); the answer is {"ok": result}
//! or {"err": "ErrorName"}.
//!
//! `log.commands`: a session's log. Logged bytes are whatever the terminal
//! carried, not always text, so they travel as base64.
//!
//! Rights are checked here, on the server; what the panel shows or hides
//! is only convenience.

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");

pub const Rpc = struct {
    io: Io,
    db: *dbm.Db,
    lock: *Io.Mutex,
};

const Caller = @import("auth.zig").Caller;

const DbCall = struct {
    name: []const u8,
    module: []const u8,
    action: []const u8,
    /// Recorded with who made it (panel.zig)
    changes: bool = false,
};

/// The database functions the panel may call, and the right each needs.
const db_calls = [_]DbCall{
    .{ .name = "nodeList", .module = "node", .action = "browse" },
    .{ .name = "nodeGet", .module = "node", .action = "browse" },
    .{ .name = "nodeSearch", .module = "node", .action = "browse" },
    .{ .name = "nodeSummary", .module = "node", .action = "browse" },
    .{ .name = "sessionsSearch", .module = "session", .action = "browse" },
    .{ .name = "actionsSearch", .module = "audit", .action = "browse" },
    .{ .name = "sessionsActive", .module = "session", .action = "browse" },
    .{ .name = "sessionsRecent", .module = "session", .action = "browse" },
    .{ .name = "sessionsOfNode", .module = "session", .action = "browse" },
    .{ .name = "settingsGet", .module = "config", .action = "browse" },
    .{ .name = "actionsRecent", .module = "audit", .action = "browse" },
    .{ .name = "nodeCreate", .module = "node", .action = "insert", .changes = true },
    .{ .name = "nodeNewToken", .module = "node", .action = "insert", .changes = true },
    .{ .name = "nodeApprove", .module = "node", .action = "update", .changes = true },
    .{ .name = "nodeReject", .module = "node", .action = "update", .changes = true },
    .{ .name = "nodeSetDisabled", .module = "node", .action = "update", .changes = true },
    .{ .name = "nodeDelete", .module = "node", .action = "delete", .changes = true },
    .{ .name = "settingsSet", .module = "config", .action = "update", .changes = true },
};

/// Whether `name` (an API call) is a database call that changes something.
pub fn changes(name: []const u8) bool {
    if (!std.mem.startsWith(u8, name, "db.")) return false;
    inline for (db_calls) |c| {
        if (c.changes and std.mem.eql(u8, name["db.".len..], c.name)) return true;
    }
    return false;
}

pub const Result = union(enum) {
    /// JSON for the caller, in the call's arena
    body: []const u8,
    forbidden,
    bad_request,
};

/// Handles db.* and log.*; null if `name` is neither.
pub fn call(rpc: *Rpc, a: std.mem.Allocator, name: []const u8, body: []const u8, who: *const Caller) !?Result {
    if (std.mem.eql(u8, name, "log.commands")) {
        if (!who.can("session", "log")) return .forbidden;
        const args = std.json.parseFromSliceLeaky(struct { []const u8 }, a, body, .{}) catch return .bad_request;
        rpc.lock.lockUncancelable(rpc.io);
        defer rpc.lock.unlock(rpc.io);
        const cmds = rpc.db.commandsOf(a, args[0]) catch |e| return .{ .body = try errBody(a, e) };
        const Wire = struct { seq: i64, at: i64, line: []const u8, output: []const u8, output_chars: i64, intact: bool };
        const out = try a.alloc(Wire, cmds.len);
        for (cmds, out) |c, *w| w.* = .{ .seq = c.seq, .at = c.at, .line = try b64(a, c.line), .output = try b64(a, c.output), .output_chars = c.output_chars, .intact = c.intact };
        return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .ok = out }, .{}) };
    }
    if (!std.mem.startsWith(u8, name, "db.")) return null;
    const method = name["db.".len..];
    inline for (db_calls) |c| {
        if (std.mem.eql(u8, method, c.name)) {
            if (!who.can(c.module, c.action)) return .forbidden;
            return try invoke(rpc, a, c.name, body);
        }
    }
    return null;
}

fn invoke(rpc: *Rpc, a: std.mem.Allocator, comptime method: []const u8, body: []const u8) !Result {
    const f = @field(dbm.Db, method);
    const Args = std.meta.ArgsTuple(@TypeOf(f));
    const values = std.json.parseFromSliceLeaky([]const std.json.Value, a, body, .{}) catch return .bad_request;
    var args: Args = undefined;
    args[0] = rpc.db;
    var next: usize = 0;
    inline for (@typeInfo(Args).@"struct".field_types, 0..) |T, i| {
        if (i == 0) continue;
        if (T == std.mem.Allocator) {
            args[i] = a;
        } else {
            if (next >= values.len) return .bad_request;
            args[i] = std.json.parseFromValueLeaky(T, a, values[next], .{ .ignore_unknown_fields = true }) catch return .bad_request;
            next += 1;
        }
    }
    if (next != values.len) return .bad_request;

    rpc.lock.lockUncancelable(rpc.io);
    defer rpc.lock.unlock(rpc.io);
    const r = @call(.auto, f, args) catch |e| return .{ .body = try errBody(a, e) };
    if (@TypeOf(r) == void) return .{ .body = "{\"ok\":null}" };
    return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .ok = r }, .{}) };
}

fn errBody(a: std.mem.Allocator, e: anyerror) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, .{ .err = @errorName(e) }, .{});
}

fn b64(a: std.mem.Allocator, bytes: []const u8) ![]const u8 {
    const enc = std.base64.standard.Encoder;
    const out = try a.alloc(u8, enc.calcSize(bytes.len));
    return enc.encode(out, bytes);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "database calls by name, with the right checked" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try dbm.Db.open(":memory:");
    defer db.close();
    db.setLogKey(testing.io, @splat(7));
    var lock: Io.Mutex = .init;
    var rpc: Rpc = .{ .io = testing.io, .db = &db, .lock = &lock };
    const admin: *const Caller = &.{ .id = 1, .name = "admin", .is_superuser = true };
    const auditor: *const Caller = &.{ .id = 2, .name = "reader", .rights = &.{ "node:browse", "config:browse", "session:log" } };
    const nobody: *const Caller = &.{ .id = 3, .name = "new" };

    // Creating a node needs node:insert
    const th = dbm.tokenHash("T");
    const create = try std.fmt.allocPrint(a, "[\"gw01\",\"pump\",\"{s}\",2000,1000]", .{&th});
    try testing.expectEqual(Result.forbidden, (try call(&rpc, a, "db.nodeCreate", create, auditor)).?);
    try testing.expectEqualStrings("{\"ok\":1}", (try call(&rpc, a, "db.nodeCreate", create, admin)).?.body);
    // Errors come back by name
    try testing.expectEqualStrings("{\"err\":\"Duplicate\"}", (try call(&rpc, a, "db.nodeCreate", create, admin)).?.body);
    try testing.expectEqualStrings("{\"err\":\"NotFound\"}", (try call(&rpc, a, "db.nodeDelete", "[99]", admin)).?.body);

    // Reading needs the module's browse right
    const list = (try call(&rpc, a, "db.nodeList", "[]", auditor)).?.body;
    try testing.expect(std.mem.indexOf(u8, list, "\"name\":\"gw01\"") != null);
    try testing.expect(std.mem.indexOf(u8, list, "\"state\":\"waiting\"") != null);
    try testing.expectEqualStrings("{\"ok\":null}", (try call(&rpc, a, "db.nodeGet", "[99]", auditor)).?.body);
    try testing.expect(std.mem.indexOf(u8, (try call(&rpc, a, "db.settingsGet", "[]", auditor)).?.body, "\"max_command_output\":10000") != null);
    try testing.expectEqual(Result.forbidden, (try call(&rpc, a, "db.settingsSet", "[{\"max_command_output\":1,\"max_session_minutes\":1,\"log_days\":1}]", auditor)).?);
    try testing.expectEqualStrings("{\"ok\":null}", (try call(&rpc, a, "db.settingsSet", "[{\"max_command_output\":1,\"max_session_minutes\":2,\"log_days\":3}]", admin)).?.body);
    try testing.expectEqual(@as(i64, 2), (try db.settingsGet()).max_session_minutes);

    // Without a role: nothing, not even reading
    try testing.expectEqual(Result.forbidden, (try call(&rpc, a, "db.nodeList", "[]", nobody)).?);
    try testing.expectEqual(Result.forbidden, (try call(&rpc, a, "log.commands", "[\"S1\"]", nobody)).?);
    try testing.expectEqual(Result.forbidden, (try call(&rpc, a, "db.sessionsActive", "[]", auditor)).?);

    // Wrong arguments, and functions that are not listed
    try testing.expectEqual(Result.bad_request, (try call(&rpc, a, "db.nodeGet", "[]", admin)).?);
    try testing.expectEqual(Result.bad_request, (try call(&rpc, a, "db.nodeGet", "[1,2]", admin)).?);
    try testing.expectEqual(Result.bad_request, (try call(&rpc, a, "db.nodeGet", "[\"x\"]", admin)).?);
    try testing.expect(try call(&rpc, a, "db.userSetPassword", "[1,\"h\"]", admin) == null);
    try testing.expect(try call(&rpc, a, "db.sessionKeys", "[\"S\"]", admin) == null);
    try testing.expect(try call(&rpc, a, "db.webSessionGet", "[\"x\",0]", admin) == null);

    // Logs travel as base64: they are not always text
    try db.commandAdd("S1", .{ .seq = 1, .at = 5, .line = "ls\r", .output = "\x1b[31m\xff\xfe", .output_chars = 3 });
    const log = (try call(&rpc, a, "log.commands", "[\"S1\"]", auditor)).?.body;
    try testing.expect(std.mem.indexOf(u8, log, "\"line\":\"bHMN\"") != null);
    try testing.expect(std.mem.indexOf(u8, log, "\"output\":\"G1szMW3//g==\"") != null);
}
