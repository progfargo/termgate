//! What a signed-in panel may call besides sign-in itself: the database
//! functions (rpc.zig), the relay's address for node keys and invitations,
//! actions on the relay (end a session, close connections, ask nodes for
//! their status) and watching a session.
//!
//! Each call needs a right (rights.zig): watching a session needs
//! session:watch, ending one session:end, and so on.

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");
const core = @import("core");
const service_mod = @import("service");
const rpc_mod = @import("rpc.zig");
const Caller = @import("auth.zig").Caller;

/// A tap nobody has read for this long belongs to a closed browser tab.
const tap_idle_s = 30;

pub const Panel = struct {
    gpa: std.mem.Allocator,
    io: Io,
    rpc: rpc_mod.Rpc,
    relay_host: []const u8,
    relay_port: u16,
    ca_fingerprint: [32]u8,
    /// Guards `service` and `taps`
    lock: Io.Mutex = .init,
    /// null while the relay connection is down
    service: ?*service_mod.Service = null,
    taps: std.AutoHashMapUnmanaged(u64, *service_mod.Tap) = .empty,
    next_tap: u64 = 1,

    /// The relay connection is up (or, with null, about to be closed: the
    /// taps read through it and are stopped first).
    pub fn setService(p: *Panel, s: ?*service_mod.Service) void {
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        if (s == null) p.stopTaps();
        p.service = s;
    }

    pub fn deinit(p: *Panel) void {
        p.stopTaps();
        p.taps.deinit(p.gpa);
    }

    fn stopTaps(p: *Panel) void {
        var it = p.taps.valueIterator();
        while (it.next()) |t| t.*.stop();
        p.taps.clearRetainingCapacity();
    }

    fn pruneTaps(p: *Panel, now: i64) void {
        var it = p.taps.iterator();
        while (it.next()) |kv| {
            if (now - kv.value_ptr.*.last_read.load(.acquire) > tap_idle_s) {
                kv.value_ptr.*.stop();
                p.taps.removeByPtr(kv.key_ptr);
                it = p.taps.iterator();
            }
        }
    }
};

pub const Reply = struct { status: std.http.Status = .ok, body: []const u8 };

/// Whether a call changes something, so that it is recorded with who
/// made it (see record).
pub fn changes(name: []const u8) bool {
    if (rpc_mod.changes(name)) return true;
    inline for (.{ "svc.endSession", "svc.kickNode", "users.create", "users.update", "users.reset", "users.delete", "users.grant", "users.revoke", "users.select", "users.unselect", "nodes.create", "nodes.newKey", "terminal.invite", "terminal.revoke", "roles.insert", "roles.update", "roles.rights", "roles.delete", "profile.password" }) |n| {
        if (std.mem.eql(u8, name, n)) return true;
    }
    return false;
}

/// What a changing call is about, in words: the node or user it
/// names. Looked up before the call runs (afterwards a deleted node has
/// no name any more). Only names and ids are taken from the arguments:
/// profile.password carries passwords, which are never recorded.
pub fn describe(p: *Panel, a: std.mem.Allocator, name: []const u8, body: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return "";
    if (v == .object) {
        // users.* and roles.*: {"id": ..., "name": ..., "role": ..., ...}.
        // The name is the one given, or looked up by the id.
        const is_role = std.mem.startsWith(u8, name, "roles.");
        const is_node = std.mem.startsWith(u8, name, "nodes.");
        const id: ?i64 = if (v.object.get("id")) |n| (if (n == .integer) n.integer else null) else null;
        var who: []const u8 = if (v.object.get("name")) |n| (if (n == .string) n.string else "") else "";
        var role: []const u8 = "";
        {
            p.rpc.lock.lockUncancelable(p.io);
            defer p.rpc.lock.unlock(p.io);
            if (id) |i| {
                if (is_node) {
                    if (p.rpc.db.nodeGet(a, i) catch null) |n| who = n.name;
                } else if (is_role) {
                    if (p.rpc.db.roleGet(a, i) catch null) |r| who = if (who.len == 0 or std.mem.eql(u8, who, r.name)) r.name else (std.fmt.allocPrint(a, "{s} -> {s}", .{ r.name, who }) catch who);
                } else if (p.rpc.db.userGet(a, i) catch null) |u| who = if (who.len == 0 or std.mem.eql(u8, who, u.name)) u.name else (std.fmt.allocPrint(a, "{s} -> {s}", .{ u.name, who }) catch who);
                if (who.len == 0) who = std.fmt.allocPrint(a, "id {d}", .{i}) catch "";
            }
            if (v.object.get("role")) |r| if (r == .integer) {
                role = if (p.rpc.db.roleGet(a, r.integer) catch null) |x| x.name else "?";
            };
        }
        if (role.len > 0) return std.fmt.allocPrint(a, "{s} ({s})", .{ who, role }) catch who;
        if (v.object.get("disabled")) |d| if (d == .bool and d.bool) return std.fmt.allocPrint(a, "{s} (blocked)", .{who}) catch who;
        return who;
    }
    if (v != .array or v.array.items.len == 0) return "";
    const first = v.array.items[0];
    const is_node = std.mem.startsWith(u8, name, "db.node");
    if (first == .integer and is_node) {
        p.rpc.lock.lockUncancelable(p.io);
        defer p.rpc.lock.unlock(p.io);
        if (p.rpc.db.nodeGet(a, first.integer) catch null) |n| return n.name;
        return std.fmt.allocPrint(a, "id {d}", .{first.integer}) catch "";
    }
    if (first == .string) {
        // A name (node, session's node) comes first
        if (std.mem.eql(u8, name, "svc.endSession") and v.array.items.len == 3 and v.array.items[2] == .string)
            return std.fmt.allocPrint(a, "session {s} on {s}", .{ v.array.items[2].string, first.string }) catch first.string;
        return first.string;
    }
    if (first == .object) {
        // db.settingsSet: the settings
        if (first.object.get("name")) |n| if (n == .string) return n.string;
        return std.json.Stringify.valueAlloc(a, first, .{}) catch "";
    }
    return "";
}

/// Records what a user did.
pub fn record(p: *Panel, at: i64, user: []const u8, name: []const u8, detail: []const u8, ok: bool) void {
    p.rpc.lock.lockUncancelable(p.io);
    defer p.rpc.lock.unlock(p.io);
    p.rpc.db.actionAdd(at, user, name, detail[0..@min(detail.len, 300)], ok) catch {};
}

fn err(status: std.http.Status, comptime msg: []const u8) Reply {
    return .{ .status = status, .body = "{\"error\":\"" ++ msg ++ "\"}" };
}

/// Handles a call of a signed-in user; null if the name is unknown.
pub fn call(p: *Panel, a: std.mem.Allocator, name: []const u8, body: []const u8, who: *const Caller, now: i64) !?Reply {
    if (try rpc_mod.call(&p.rpc, a, name, body, who)) |r| return switch (r) {
        .body => |b| .{ .body = b },
        .forbidden => err(.forbidden, "no right"),
        .bad_request => err(.bad_request, "bad arguments"),
    };
    if (std.mem.eql(u8, name, "nodes.create") or std.mem.eql(u8, name, "nodes.newKey") or std.mem.eql(u8, name, "terminal.invite"))
        return try keyCall(p, a, name, body, who, now);
    if (std.mem.eql(u8, name, "terminal.revoke")) {
        if (!who.can("user", "access")) return err(.forbidden, "no right");
        const Req = struct { id: i64 = 0 };
        const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return err(.bad_request, "bad arguments");
        {
            p.rpc.lock.lockUncancelable(p.io);
            defer p.rpc.lock.unlock(p.io);
            p.rpc.db.terminalRevoke(req.id) catch |e| return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .err = @errorName(e) }, .{}) };
        }
        enforceTerminal(p);
        return .{ .body = "{\"ok\":null}" };
    }
    if (std.mem.eql(u8, name, "relay.info")) {
        return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .ok = .{
            .host = p.relay_host,
            .port = p.relay_port,
            .ca_fingerprint = @as([]const u8, &std.fmt.bytesToHex(p.ca_fingerprint, .lower)),
        } }, .{}) };
    }
    const is_svc = std.mem.startsWith(u8, name, "svc.");
    const is_watch = std.mem.startsWith(u8, name, "watch.");
    if (!is_svc and !is_watch) return null;
    // The right each of these needs
    const allowed = if (is_watch) who.can("session", "watch") else if (std.mem.eql(u8, name, "svc.requestStatus") or std.mem.eql(u8, name, "svc.requestStatusOf"))
        who.can("node", "browse")
    else if (std.mem.eql(u8, name, "svc.endSession"))
        who.can("session", "end")
    else if (std.mem.eql(u8, name, "svc.kickNode"))
        who.can("node", "update") or who.can("node", "delete")
    else
        return null;
    if (!allowed) return err(.forbidden, "no right");

    const args = std.json.parseFromSliceLeaky([]const std.json.Value, a, body, .{}) catch return err(.bad_request, "bad arguments");
    const str = struct {
        fn f(v: []const std.json.Value, i: usize) ?[]const u8 {
            return if (i < v.len and v[i] == .string) v[i].string else null;
        }
    }.f;
    const int = struct {
        fn f(v: []const std.json.Value, i: usize) ?u64 {
            return if (i < v.len and v[i] == .integer and v[i].integer >= 0) @intCast(v[i].integer) else null;
        }
    }.f;

    p.lock.lockUncancelable(p.io);
    defer p.lock.unlock(p.io);
    const s = p.service orelse return .{ .body = "{\"err\":\"NotConnected\"}" };
    const ok: Reply = .{ .body = "{\"ok\":null}" };

    if (is_svc) {
        const what = name["svc.".len..];
        if (std.mem.eql(u8, what, "requestStatus")) {
            s.requestStatus();
            return ok;
        }
        if (std.mem.eql(u8, what, "requestStatusOf")) {
            s.requestStatusOf(str(args, 0) orelse return err(.bad_request, "bad arguments"));
            return ok;
        }
        if (std.mem.eql(u8, what, "endSession")) {
            s.endSession(str(args, 0) orelse return err(.bad_request, "bad arguments"), str(args, 1) orelse return err(.bad_request, "bad arguments"), str(args, 2) orelse return err(.bad_request, "bad arguments")) catch
                return .{ .body = "{\"err\":\"NotConnected\"}" };
            return ok;
        }
        if (std.mem.eql(u8, what, "kickNode")) {
            s.kickNode(str(args, 0) orelse return err(.bad_request, "bad arguments"));
            return ok;
        }
        return null;
    }

    const what = name["watch.".len..];
    p.pruneTaps(now);
    if (std.mem.eql(u8, what, "start")) {
        const t = service_mod.Tap.start(s, str(args, 0) orelse return err(.bad_request, "bad arguments"), str(args, 1) orelse return err(.bad_request, "bad arguments"), str(args, 2) orelse return err(.bad_request, "bad arguments")) catch
            return .{ .body = "{\"err\":\"NotConnected\"}" };
        const id = p.next_tap;
        p.next_tap += 1;
        p.taps.put(p.gpa, id, t) catch {
            t.stop();
            return error.OutOfMemory;
        };
        return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .ok = id }, .{}) };
    }
    const id = int(args, 0) orelse return err(.bad_request, "bad arguments");
    if (std.mem.eql(u8, what, "stop")) {
        if (p.taps.fetchRemove(id)) |kv| kv.value.stop();
        return ok;
    }
    if (std.mem.eql(u8, what, "read")) {
        const t = p.taps.get(id) orelse return .{ .body = "{\"err\":\"NotFound\"}" };
        const chunk = try t.read(a, int(args, 1) orelse 0, now);
        const enc = std.base64.standard.Encoder;
        const data = try a.alloc(u8, enc.calcSize(chunk.data.len));
        return .{ .body = try std.json.Stringify.valueAlloc(a, .{ .ok = .{ .data = enc.encode(data, chunk.data), .next = chunk.next, .state = @tagName(chunk.state) } }, .{}) };
    }
    return null;
}

/// A node key lasts this long unless used
const node_key_lifetime_s = 24 * 3600;
/// An invitation lasts this long unless used
const invitation_lifetime_s = 7 * 86400;

/// nodes.create {name, description}, nodes.newKey {id}, terminal.invite
/// {id (the user), bot, nodes: [...], run_as, uses, days}: a node key or
/// an invitation, made here: a random token, of which only the hash is
/// stored; the text (tg1-<relay>-<CA fingerprint>-<token>) is answered
/// once, to be handed over.
fn keyCall(p: *Panel, a: std.mem.Allocator, name: []const u8, body: []const u8, who: *const Caller, now: i64) !Reply {
    const invite = std.mem.eql(u8, name, "terminal.invite");
    if (!(if (invite) who.can("user", "access") else who.can("node", "insert"))) return err(.forbidden, "no right");
    const Req = struct {
        id: i64 = 0,
        name: []const u8 = "",
        description: []const u8 = "",
        bot: bool = false,
        nodes: []const []const u8 = &.{},
        run_as: []const u8 = "",
        uses: ?u32 = null,
        days: ?u32 = null,
    };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return err(.bad_request, "bad arguments");

    var tok: [32]u8 = undefined;
    p.io.random(&tok);
    const text = try core.code.format(a, p.relay_host, p.relay_port, p.ca_fingerprint, tok);
    const th = dbm.tokenHash((core.code.parse(text) catch return error.InvalidCode).token);
    const answer = struct {
        fn ok(al: std.mem.Allocator, id: i64, code: []const u8) !Reply {
            return .{ .body = try std.json.Stringify.valueAlloc(al, .{ .ok = .{ .id = id, .code = code } }, .{}) };
        }
        fn dbErr(al: std.mem.Allocator, e: anyerror) !Reply {
            return .{ .body = try std.json.Stringify.valueAlloc(al, .{ .err = @errorName(e) }, .{}) };
        }
    };

    p.rpc.lock.lockUncancelable(p.io);
    defer p.rpc.lock.unlock(p.io);
    const db = p.rpc.db;
    if (std.mem.eql(u8, name, "nodes.create")) {
        const id = db.nodeCreate(std.mem.trim(u8, req.name, " "), std.mem.trim(u8, req.description, " "), &th, now + node_key_lifetime_s, now) catch |e| return answer.dbErr(a, e);
        return answer.ok(a, id, text);
    }
    if (std.mem.eql(u8, name, "nodes.newKey")) {
        db.nodeNewToken(req.id, &th, now + node_key_lifetime_s) catch |e| return answer.dbErr(a, e);
        return answer.ok(a, req.id, text);
    }
    if (req.uses == null and req.days == null) return .{ .body = "{\"err\":\"InvalidSpec\"}" };
    db.terminalInvite(req.id, .{
        .kind = if (req.bot) .bot else .human,
        .nodes = std.mem.join(a, ",", req.nodes) catch return error.OutOfMemory,
        .run_as = std.mem.trim(u8, req.run_as, " "),
        .max_uses = req.uses,
        .grant_exp = if (req.days) |d| now + @as(i64, d) * 86400 else null,
    }, &th, now + invitation_lifetime_s, now) catch |e| return answer.dbErr(a, e);
    return answer.ok(a, req.id, text);
}

/// Closes the connections of users who may not connect any more: their
/// access revoked, blocked, or without terminal:connect (a role taken, a
/// role's rights changed). Called after every change made in the panel.
pub fn enforceTerminal(p: *Panel) void {
    var arena: std.heap.ArenaAllocator = .init(p.gpa);
    defer arena.deinit();
    const keys = blk: {
        p.rpc.lock.lockUncancelable(p.io);
        defer p.rpc.lock.unlock(p.io);
        break :blk p.rpc.db.terminalKeysDenied(arena.allocator()) catch return;
    };
    if (keys.len == 0) return;
    p.lock.lockUncancelable(p.io);
    defer p.lock.unlock(p.io);
    const s = p.service orelse return;
    for (keys) |k| s.kickUser(k);
}

test "changing calls are known and described in words" {
    const testing = std.testing;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try dbm.Db.open(":memory:");
    defer db.close();
    db.setLogKey(testing.io, @splat(7));
    var lock: Io.Mutex = .init;
    var p: Panel = .{ .gpa = testing.allocator, .io = testing.io, .rpc = .{ .io = testing.io, .db = &db, .lock = &lock }, .relay_host = "r", .relay_port = 1, .ca_fingerprint = @splat(0) };
    defer p.deinit();

    try testing.expect(changes("db.nodeDelete") and changes("svc.endSession") and changes("users.create"));
    try testing.expect(!changes("db.nodeSearch") and !changes("watch.start") and !changes("users.list") and !changes("svc.requestStatus"));

    const th = dbm.tokenHash("T");
    const id = try db.nodeCreate("pump07", "", &th, 2000, 1000);
    try testing.expectEqual(@as(i64, 1), id);
    // Looked up before the call: the name is known although the node goes
    try testing.expectEqualStrings("pump07", describe(&p, a, "db.nodeDelete", "[1]"));
    try testing.expectEqualStrings("id 9", describe(&p, a, "db.nodeDelete", "[9]"));
    try testing.expectEqualStrings("gw02", describe(&p, a, "nodes.create", "{\"name\":\"gw02\"}"));
    try testing.expectEqualStrings("session S1 on pump07", describe(&p, a, "svc.endSession", "[\"pump07\",\"UKEY\",\"S1\"]"));
    try testing.expectEqualStrings("veli", describe(&p, a, "users.create", "{\"name\":\"veli\"}"));
    const uid = try db.userCreate("veli", false, "h", 1);
    try testing.expectEqualStrings("veli (auditor)", describe(&p, a, "users.grant", try std.fmt.allocPrint(a, "{{\"id\":{d},\"role\":2}}", .{uid})));
    try testing.expectEqualStrings("veli (blocked)", describe(&p, a, "users.update", try std.fmt.allocPrint(a, "{{\"id\":{d},\"name\":\"veli\",\"disabled\":true}}", .{uid})));
    try testing.expectEqualStrings("veli -> veli2", describe(&p, a, "users.update", try std.fmt.allocPrint(a, "{{\"id\":{d},\"name\":\"veli2\",\"disabled\":false}}", .{uid})));
    try testing.expectEqualStrings("auditor", describe(&p, a, "roles.delete", "{\"id\":2}"));
    try testing.expect(changes("roles.update") and changes("users.grant") and !changes("roles.list"));

    record(&p, 5, "admin", "db.nodeDelete", "pump07", true);
    record(&p, 6, "", "login", "ghost", false);
    const list = try db.actionsRecent(a, 10);
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqualStrings("ghost", list[0].detail);
    try testing.expect(!list[0].ok);
    try testing.expectEqualStrings("admin", list[1].user);
}

test "node keys and invitations are made on the server" {
    const testing = std.testing;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try dbm.Db.open(":memory:");
    defer db.close();
    db.setLogKey(testing.io, @splat(7));
    var lock: Io.Mutex = .init;
    var p: Panel = .{ .gpa = testing.allocator, .io = testing.io, .rpc = .{ .io = testing.io, .db = &db, .lock = &lock }, .relay_host = "relay.example", .relay_port = 4222, .ca_fingerprint = @splat(5) };
    defer p.deinit();
    const admin: *const Caller = &.{ .id = 1, .name = "admin", .is_superuser = true };
    const reader: *const Caller = &.{ .id = 2, .name = "reader", .rights = &.{"node:browse"} };

    try testing.expectEqual(std.http.Status.forbidden, (try call(&p, a, "nodes.create", "{\"name\":\"gw01\"}", reader, 1000)).?.status);
    const made = (try call(&p, a, "nodes.create", "{\"name\":\"gw01\",\"description\":\"pump\"}", admin, 1000)).?;
    const Answer = struct { ok: struct { id: i64, code: []const u8 } };
    const ans = try std.json.parseFromSliceLeaky(Answer, a, made.body, .{});
    // The code names the relay; the database has only its token's hash
    const code = try core.code.parse(ans.ok.code);
    try testing.expectEqualStrings("relay.example", code.host);
    try testing.expectEqual(ans.ok.id, (try db.nodeByToken(a, &dbm.tokenHash(code.token), 1000)).?.id);
    try testing.expectEqualStrings("{\"err\":\"Duplicate\"}", (try call(&p, a, "nodes.create", "{\"name\":\"gw01\"}", admin, 1000)).?.body);

    // Terminal access for a user: needs uses, days or both
    const ali = try db.userCreate("ali", false, "!", 1000);
    try db.userGrant(ali, (try db.roleList(a))[2].id);
    const ali_body = try std.fmt.allocPrint(a, "{{\"id\":{d},\"nodes\":[\"gw*\",\"pump?\"],\"run_as\":\"root\"", .{ali});
    try testing.expectEqualStrings("{\"err\":\"InvalidSpec\"}", (try call(&p, a, "terminal.invite", try std.mem.concat(a, u8, &.{ ali_body, "}" }), admin, 1000)).?.body);
    const inv = try std.json.parseFromSliceLeaky(Answer, a, (try call(&p, a, "terminal.invite", try std.mem.concat(a, u8, &.{ ali_body, ",\"uses\":2}" }), admin, 1000)).?.body, .{});
    const t = (try db.terminalByToken(a, &dbm.tokenHash((try core.code.parse(inv.ok.code)).token), 1000)).?;
    try testing.expectEqualStrings("gw*,pump?", t.nodes);
    try testing.expectEqualStrings("ali", t.name);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&p, a, "terminal.revoke", try std.fmt.allocPrint(a, "{{\"id\":{d}}}", .{ali}), reader, 1000)).?.status);
    try testing.expectEqualStrings("{\"ok\":null}", (try call(&p, a, "terminal.revoke", try std.fmt.allocPrint(a, "{{\"id\":{d}}}", .{ali}), admin, 1000)).?.body);
    try testing.expect((try db.terminalGet(a, ali)).?.revoked);
}
