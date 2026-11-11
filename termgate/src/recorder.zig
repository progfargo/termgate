//! Records every session as it is: termgate approves each one, so it
//! follows each from its first byte. The service hands it what the relay
//! carries (out.*.*.*.data|end, in.*.*.*.data); nothing is interpreted or
//! changed. The log is exactly what went through the relay.
//!
//! A command is what the user typed up to Enter, raw; its output is what
//! the node sent until the next Enter, raw (escape sequences included), cut
//! at Settings.max_command_output characters (code points; the full count
//! is stored).
//!
//! Only the current command is held in memory. The recorder lives as long
//! as termgate (it survives relay reconnects).

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");

/// A session with no traffic for this long is forgotten (its end was
/// missed, e.g. while the relay connection was down); what it had is logged.
pub const idle_s = 24 * 3600;

/// Typed input kept per command line (bytes)
const max_line = 4096;

const Session = struct {
    /// Typed since the last Enter
    typed: std.ArrayList(u8) = .empty,
    cur: dbm.Command,
    /// cur.output while it grows
    output: std.ArrayList(u8) = .empty,
    next_seq: i64 = 1,
    last_seen: i64,

    fn deinit(s: *Session, gpa: std.mem.Allocator) void {
        s.typed.deinit(gpa);
        s.output.deinit(gpa);
        gpa.free(s.cur.line);
    }
};

pub const Recorder = struct {
    gpa: std.mem.Allocator,
    io: Io,
    db: *dbm.Db,
    /// The database lock (shared with the UI and the service). Never taken
    /// while `lock` is held.
    db_lock: *Io.Mutex,
    lock: Io.Mutex = .init,
    /// Key: session id (owned)
    sessions: std.StringHashMapUnmanaged(Session) = .empty,
    /// Settings.max_command_output, refreshed by the service
    max_output: std.atomic.Value(i64) = .init(10_000),

    pub fn init(gpa: std.mem.Allocator, io: Io, db: *dbm.Db, db_lock: *Io.Mutex) Recorder {
        return .{ .gpa = gpa, .io = io, .db = db, .db_lock = db_lock };
    }

    pub fn deinit(r: *Recorder) void {
        var it = r.sessions.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.deinit(r.gpa);
            r.gpa.free(kv.key_ptr.*);
        }
        r.sessions.deinit(r.gpa);
    }

    /// Session `sid`, created if needed. `lock` held.
    fn session(r: *Recorder, sid: []const u8, now: i64) !*Session {
        const gop = try r.sessions.getOrPut(r.gpa, sid);
        if (!gop.found_existing) {
            gop.key_ptr.* = r.gpa.dupe(u8, sid) catch |e| {
                r.sessions.removeByPtr(gop.key_ptr);
                return e;
            };
            // Before the first command: the login banner, as command 0
            gop.value_ptr.* = .{ .cur = .{ .seq = 0, .at = now, .line = &.{}, .output = &.{}, .output_chars = 0 }, .last_seen = now };
        }
        gop.value_ptr.last_seen = now;
        return gop.value_ptr;
    }

    /// termgate approved session `sid`: record it from the start.
    pub fn open(r: *Recorder, sid: []const u8, now: i64) void {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        _ = r.session(sid, now) catch {};
    }

    /// Keys the user typed (in.<node>.<user>.<sid>.data). Enter ends the
    /// command line.
    pub fn input(r: *Recorder, sid: []const u8, bytes: []const u8, now: i64) void {
        var done: std.ArrayList(Finished) = .empty;
        defer r.storeAll(&done);
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const s = r.session(sid, now) catch return;
        for (bytes) |b| {
            if (s.typed.items.len < max_line) s.typed.append(r.gpa, b) catch {};
            if (b != '\r' and b != '\n') continue;
            const line = s.typed.toOwnedSlice(r.gpa) catch continue;
            if (r.finish(s, sid)) |f| done.append(r.gpa, f) catch {};
            s.cur = .{ .seq = s.next_seq, .at = now, .line = line, .output = &.{}, .output_chars = 0 };
            s.next_seq += 1;
        }
    }

    /// Terminal output (out.<node>.<user>.<sid>.data), kept as it is up to
    /// the limit; the characters are counted in all.
    pub fn output(r: *Recorder, sid: []const u8, bytes: []const u8, now: i64) void {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const s = r.session(sid, now) catch return;
        const max = r.max_output.load(.acquire);
        for (bytes) |b| {
            if ((b & 0xC0) != 0x80) s.cur.output_chars += 1;
            if (s.cur.output_chars <= max) s.output.append(r.gpa, b) catch return;
        }
    }

    /// The session is over (out.<node>.<user>.<sid>.end): its last command
    /// is logged and it is forgotten.
    pub fn end(r: *Recorder, sid: []const u8) void {
        var done: std.ArrayList(Finished) = .empty;
        defer r.storeAll(&done);
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        const kv = r.sessions.getEntry(sid) orelse return;
        if (r.finish(kv.value_ptr, sid)) |f| done.append(r.gpa, f) catch {};
        kv.value_ptr.deinit(r.gpa);
        r.gpa.free(kv.key_ptr.*);
        r.sessions.removeByPtr(kv.key_ptr);
    }

    /// A command to write to the database (outside `lock`).
    const Finished = struct { sid: []u8, cmd: dbm.Command };

    /// Takes the current command out of `s`, null if there is nothing to
    /// log. `lock` held; `s.cur` must be replaced afterwards.
    fn finish(r: *Recorder, s: *Session, sid: []const u8) ?Finished {
        const out = s.output.toOwnedSlice(r.gpa) catch &.{};
        var cmd = s.cur;
        cmd.output = out;
        s.cur.line = &.{};
        if (cmd.line.len == 0 and out.len == 0) return null;
        const sid_copy = r.gpa.dupe(u8, sid) catch {
            r.gpa.free(cmd.line);
            r.gpa.free(out);
            return null;
        };
        return .{ .sid = sid_copy, .cmd = cmd };
    }

    fn storeAll(r: *Recorder, done: *std.ArrayList(Finished)) void {
        defer done.deinit(r.gpa);
        if (done.items.len == 0) return;
        {
            r.db_lock.lockUncancelable(r.io);
            defer r.db_lock.unlock(r.io);
            for (done.items) |f| r.db.commandAdd(f.sid, f.cmd) catch {};
        }
        for (done.items) |f| {
            r.gpa.free(f.sid);
            r.gpa.free(f.cmd.line);
            r.gpa.free(f.cmd.output);
        }
    }

    /// Sessions with no traffic for idle_s (their ids, in `a`).
    fn idle(r: *Recorder, a: std.mem.Allocator, now: i64) ![]const []const u8 {
        r.lock.lockUncancelable(r.io);
        defer r.lock.unlock(r.io);
        var list: std.ArrayList([]const u8) = .empty;
        var it = r.sessions.iterator();
        while (it.next()) |kv| if (now - kv.value_ptr.last_seen > idle_s) try list.append(a, try a.dupe(u8, kv.key_ptr.*));
        return list.toOwnedSlice(a);
    }

    /// Ends sessions with no traffic for idle_s.
    pub fn prune(r: *Recorder, now: i64) void {
        var arena: std.heap.ArenaAllocator = .init(r.gpa);
        defer arena.deinit();
        const list = r.idle(arena.allocator(), now) catch return;
        for (list) |sid| r.end(sid);
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "the session is logged as it is, command by command" {
    const a = testing.allocator;
    var db = try dbm.Db.open(":memory:");
    defer db.close();
    db.setLogKey(testing.io, @splat(7));
    var db_lock: Io.Mutex = .init;
    var r: Recorder = .init(a, testing.io, &db, &db_lock);
    defer r.deinit();
    r.max_output.store(40, .release);
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const ar = arena.allocator();

    r.open("S1", 100);
    r.output("S1", "Welcome\r\n\x1b[32mali@box\x1b[0m:~$ ", 100);
    r.input("S1", "lx", 101);
    r.output("S1", "lx", 101);
    r.input("S1", "\x7fs\r", 102);
    r.output("S1", "\x08 \x08s\r\nbin  etc\r\nali@box:~$ ", 102);
    r.input("S1", "seq 1 20\r", 103);
    r.output("S1", "seq 1 20\r\n1\r\n2\r\n3\r\n4\r\n5\r\n6\r\n7\r\n8\r\n9\r\n10\r\n", 103);
    r.end("S1");

    db_lock.lockUncancelable(testing.io);
    const cmds = try db.commandsOf(ar, "S1");
    db_lock.unlock(testing.io);
    try testing.expectEqual(@as(usize, 3), cmds.len);
    try testing.expectEqualStrings("Welcome\r\n\x1b[32mali@box\x1b[0m:~$ lx", cmds[0].output);
    try testing.expectEqualStrings("lx\x7fs\r", cmds[1].line);
    try testing.expectEqualStrings("\x08 \x08s\r\nbin  etc\r\nali@box:~$ ", cmds[1].output);
    try testing.expectEqualStrings("seq 1 20\r", cmds[2].line);
    // 40 characters kept, all counted
    try testing.expectEqual(@as(usize, 40), cmds[2].output.len);
    try testing.expectEqual(@as(i64, 41), cmds[2].output_chars);
    try testing.expectEqual(@as(usize, 0), r.sessions.count());

    // A session whose end was missed is logged and forgotten when idle
    r.output("S2", "boot", 200);
    r.prune(200 + idle_s);
    try testing.expectEqual(@as(usize, 1), r.sessions.count());
    r.prune(201 + idle_s);
    try testing.expectEqual(@as(usize, 0), r.sessions.count());
    db_lock.lockUncancelable(testing.io);
    defer db_lock.unlock(testing.io);
    try testing.expectEqualStrings("boot", (try db.commandsOf(ar, "S2"))[0].output);
}
