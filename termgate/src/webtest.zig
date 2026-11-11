//! `zig build web-test`: the panel's browser test, with one command.
//!
//! In a fresh folder it sets termgate up and starts it, opens the panel in
//! headless Chrome with ?test (web/spa/test.js: signing in with the second
//! step, every page, what an admin does with forms, acting as another
//! user, the last admin, signing out) and reads the result from the page's
//! title. Then it reads the server's database to see that the forms
//! arrived there. termgate (and the relay it runs) is stopped at the end.
//!
//! Arguments: the termgate binary, the folder to work in (emptied first).

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");

const relay_addr = "127.0.0.1:14262";
const panel_port = 18084;
const panel_addr = "127.0.0.1:18084";
const browsers = [_][]const u8{ "google-chrome", "chromium", "chromium-browser" };

var failed: usize = 0;

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("web-test: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn check(ok: bool, comptime fmt: []const u8, args: anytype) void {
    std.debug.print("  {s}  " ++ fmt ++ "\n", .{if (ok) "ok    " else "FAILED"} ++ args);
    if (!ok) failed += 1;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) fail("usage: web-test TERMGATE-BINARY WORK-FOLDER", .{});
    // Absolute: termgate is started in the work folder
    var here_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const here = here_buf[0..try std.process.currentPath(io, &here_buf)];
    const termgate = try std.fs.path.resolve(arena, &.{ here, args[1] });
    const work = try std.fs.path.resolve(arena, &.{ here, args[2] });

    // A fresh home
    const cwd = Io.Dir.cwd();
    cwd.deleteTree(io, work) catch |e| fail("cannot empty {s}: {s}", .{ work, @errorName(e) });
    cwd.createDirPath(io, work) catch |e| fail("cannot create {s}: {s}", .{ work, @errorName(e) });

    const set_up = std.process.run(arena, io, .{
        .argv = &.{ termgate, "init", "--relay", relay_addr },
        .cwd = .{ .path = work },
    }) catch |e| fail("cannot run {s}: {s}", .{ termgate, @errorName(e) });
    if (!set_up.term.success()) fail("termgate init failed:\n{s}", .{set_up.stderr});
    const password = passwordIn(set_up.stderr) orelse fail("no password in termgate init's output:\n{s}", .{set_up.stderr});

    // termgate, writing to termgate.log in the folder
    const log_path = try std.fs.path.join(arena, &.{ work, "termgate.log" });
    const log = try cwd.createFile(io, log_path, .{});
    defer log.close(io);
    var server = std.process.spawn(io, .{
        .argv = &.{ termgate, "run", "--listen", panel_addr },
        .cwd = .{ .path = work },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    }) catch |e| fail("cannot start termgate: {s}", .{@errorName(e)});
    // Ends the relay too (termgate stops nats-server when it is told to stop)
    defer server.kill(io);
    if (!listening(io)) {
        server.kill(io);
        fail("termgate does not answer on {s}; see {s}", .{ panel_addr, log_path });
    }

    std.debug.print("web-test: the panel in headless Chrome ({s})\n", .{work});
    const profile = try std.fs.path.join(arena, &.{ work, "profile" });
    const url = try std.fmt.allocPrint(arena, "http://" ++ panel_addr ++ "/?test&password={s}", .{password});
    const title = pageTitle(arena, io, profile, url);
    check(std.mem.eql(u8, title, "test: ok (scenario)"), "the panel as an admin uses it: {s}", .{title});

    // What the page left in the database
    const db_path = try std.fmt.allocPrintSentinel(arena, "{s}/data/termgate.db", .{work}, 0);
    var db = dbm.Db.open(db_path) catch fail("cannot open {s}", .{db_path});
    defer db.close();
    check(named(try db.nodeList(arena), "web_gw01"), "database: node web_gw01", .{});
    const veli = try db.userByName(arena, "veli");
    check(veli != null, "database: user veli", .{});
    if (veli) |u| {
        var roles: std.ArrayList(u8) = .empty;
        for (try db.userRoles(arena, u.id)) |r| try roles.print(arena, "{s} ", .{r.name});
        check(std.mem.eql(u8, roles.items, "admin terminal_user "), "database: veli has the roles admin and terminal_user ({s})", .{roles.items});
        const t = try db.terminalGet(arena, u.id);
        check(t != null and std.mem.eql(u8, t.?.nodes, "web_*") and t.?.max_uses == 2, "database: veli's terminal access: web_* , 2 sessions", .{});
    }
    var operator_ok = false;
    for (try db.roleList(arena)) |r| {
        if (!std.mem.eql(u8, r.name, "operator")) continue;
        const have = try db.roleRights(arena, r.id);
        operator_ok = have.len == 2 and dbm.rights.has(have, "node", "browse") and dbm.rights.has(have, "session", "watch");
    }
    check(operator_ok, "database: role operator with node:browse and session:watch", .{});
    const minutes = (try db.settingsGet()).max_session_minutes;
    check(minutes == 90, "database: session length {d} minutes", .{minutes});
    var acted = false;
    var back = false;
    var refused = false;
    for (try db.actionsRecent(arena, 200)) |x| {
        if (std.mem.eql(u8, x.call, "users.select") and std.mem.eql(u8, x.user, "superuser") and std.mem.eql(u8, x.detail, "veli")) acted = true;
        if (std.mem.eql(u8, x.call, "users.unselect") and std.mem.eql(u8, x.user, "superuser as veli")) back = true;
        if (std.mem.eql(u8, x.call, "users.delete") and !x.ok) refused = true;
    }
    check(acted and back, "database: the audit has superuser acting as veli and back", .{});
    check(refused, "database: the audit has deleting the last admin refused", .{});

    if (failed != 0) {
        server.kill(io);
        fail("{d} failed; termgate's output is in {s}", .{ failed, log_path });
    }
    std.debug.print("web-test: all passed\n", .{});
}

/// The password `termgate init` prints for the superuser.
fn passwordIn(output: []const u8) ?[]const u8 {
    const key = "password:";
    const at = std.mem.indexOf(u8, output, key) orelse return null;
    const rest = output[at + key.len ..];
    const line = rest[0 .. std.mem.indexOfScalar(u8, rest, '\n') orelse rest.len];
    const pw = std.mem.trim(u8, line, " \t\r");
    return if (pw.len == 0) null else pw;
}

/// Waits until the panel's port accepts a connection (10 seconds at most).
fn listening(io: Io) bool {
    const addr = Io.net.IpAddress.parse("127.0.0.1", panel_port) catch unreachable;
    for (0..100) |_| {
        if (addr.connect(io, .{ .mode = .stream })) |stream| {
            stream.close(io);
            return true;
        } else |_| {}
        io.sleep(.fromMilliseconds(100), .awake) catch return false;
    }
    return false;
}

fn named(rows: anytype, name: []const u8) bool {
    for (rows) |r| if (std.mem.eql(u8, r.name, name)) return true;
    return false;
}

/// Opens the page in headless Chrome and returns its title once the test
/// in it has run (the virtual time lets it run to the end).
fn pageTitle(a: std.mem.Allocator, io: Io, profile: []const u8, url: []const u8) []const u8 {
    const profile_arg = std.fmt.allocPrint(a, "--user-data-dir={s}", .{profile}) catch @panic("OOM");
    for (browsers) |exe| {
        const r = std.process.run(a, io, .{ .argv = &.{
            exe,                           "--headless=new", "--no-sandbox", "--disable-gpu",
            "--virtual-time-budget=60000", profile_arg,      "--dump-dom",   url,
        } }) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => fail("cannot run {s}: {s}", .{ exe, @errorName(e) }),
        };
        const dom = r.stdout;
        const open = "<title>";
        const start = (std.mem.indexOf(u8, dom, open) orelse return "(the page has no title)") + open.len;
        const end = std.mem.indexOfPos(u8, dom, start, "</title>") orelse return "(the page has no title)";
        return dom[start..end];
    }
    fail("no Chrome found (looked for google-chrome, chromium, chromium-browser)", .{});
}
