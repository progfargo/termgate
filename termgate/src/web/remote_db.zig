//! The panel's stand-in for termgate's database: functions with the names
//! and types of the server's (db.zig), each one a call to the
//! server (db.<method>, see server/rpc.zig). The server decides what the
//! signed-in user may do.

const std = @import("std");
const types = @import("db_types");
const rpc = @import("rpc");

pub const Error = types.Error;
pub const NodeState = types.NodeState;
pub const Person = types.Person;
pub const Session = types.Session;
pub const Settings = types.Settings;
pub const Role = types.Role;
pub const rights = types.rights;
pub const Command = types.Command;
pub const Node = types.Node;
pub const tokenHash = types.tokenHash;
pub const Action = types.Action;

pub const Db = struct {
    pub const NodeError = types.NodeError;
    pub const PersonError = types.PersonError;
    pub const Invitation = types.Invitation;
    const A = std.mem.Allocator;
    /// What a failed call (no connection, signed out, refused) looks like
    const down = error.SqliteError;

    pub fn nodeList(_: *Db, a: A) Error![]Node {
        return rpc.result([]Node, Error, down, a, "db.nodeList", .{});
    }
    pub fn nodeGet(_: *Db, a: A, id: i64) Error!?Node {
        return rpc.result(?Node, Error, down, a, "db.nodeGet", .{id});
    }
    pub fn nodeCreate(_: *Db, name: []const u8, description: []const u8, token_hash: []const u8, token_expires: i64, now: i64) NodeError!i64 {
        var buf: [2048]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        return rpc.result(i64, NodeError, down, fba.allocator(), "db.nodeCreate", .{ name, description, token_hash, token_expires, now });
    }
    pub fn nodeNewToken(_: *Db, id: i64, token_hash: []const u8, token_expires: i64) NodeError!void {
        return change(NodeError, "db.nodeNewToken", .{ id, token_hash, token_expires });
    }
    pub fn nodeApprove(_: *Db, id: i64) NodeError!void {
        return change(NodeError, "db.nodeApprove", .{id});
    }
    pub fn nodeReject(_: *Db, id: i64) NodeError!void {
        return change(NodeError, "db.nodeReject", .{id});
    }
    pub fn nodeSetDisabled(_: *Db, id: i64, disabled: bool) NodeError!void {
        return change(NodeError, "db.nodeSetDisabled", .{ id, disabled });
    }
    pub fn nodeDelete(_: *Db, id: i64) NodeError!void {
        return change(NodeError, "db.nodeDelete", .{id});
    }

    pub fn personList(_: *Db, a: A) Error![]Person {
        return rpc.result([]Person, Error, down, a, "db.personList", .{});
    }
    pub fn personGet(_: *Db, a: A, id: i64) Error!?Person {
        return rpc.result(?Person, Error, down, a, "db.personGet", .{id});
    }
    pub fn personInvite(_: *Db, inv: Invitation, token_hash: []const u8, token_expires: i64, now: i64) PersonError!i64 {
        var buf: [4096]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        return rpc.result(i64, PersonError, down, fba.allocator(), "db.personInvite", .{ inv, token_hash, token_expires, now });
    }
    pub fn personRevoke(_: *Db, id: i64) PersonError!void {
        return change(PersonError, "db.personRevoke", .{id});
    }

    pub fn sessionsActive(_: *Db, a: A) Error![]Session {
        return rpc.result([]Session, Error, down, a, "db.sessionsActive", .{});
    }
    pub fn sessionsRecent(_: *Db, a: A, limit: i64) Error![]Session {
        return rpc.result([]Session, Error, down, a, "db.sessionsRecent", .{limit});
    }
    pub fn sessionsOfNode(_: *Db, a: A, node: []const u8, limit: i64) Error![]Session {
        return rpc.result([]Session, Error, down, a, "db.sessionsOfNode", .{ node, limit });
    }

    pub fn actionsRecent(_: *Db, a: A, limit: i64) Error![]Action {
        return rpc.result([]Action, Error, down, a, "db.actionsRecent", .{limit});
    }

    pub fn settingsGet(_: *Db) Error!Settings {
        var buf: [1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        return rpc.result(Settings, Error, down, fba.allocator(), "db.settingsGet", .{});
    }
    pub fn settingsSet(_: *Db, v: Settings) Error!void {
        return change(Error, "db.settingsSet", .{v});
    }

    /// A session's log; the bytes come as base64.
    pub fn commandsOf(_: *Db, a: A, sid: []const u8) Error![]Command {
        const Wire = struct { seq: i64, at: i64, line: []const u8, output: []const u8, output_chars: i64, intact: bool };
        const wire = try rpc.result([]Wire, Error, down, a, "log.commands", .{sid});
        const out = try a.alloc(Command, wire.len);
        for (wire, out) |w, *c| c.* = .{
            .seq = w.seq,
            .at = w.at,
            .line = rpc.decodeBase64(a, w.line) catch "",
            .output = rpc.decodeBase64(a, w.output) catch "",
            .output_chars = w.output_chars,
            .intact = w.intact,
        };
        return out;
    }

    fn change(comptime E: type, name: []const u8, args: anytype) E!void {
        var buf: [2048]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        return rpc.result(void, E, down, fba.allocator(), name, args);
    }
};
