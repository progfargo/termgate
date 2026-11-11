//! `zig build web-test`: the panel's self-tests in headless Chrome, with one
//! command.
//!
//! In a fresh folder it sets termgate up, starts it, and opens the panel's
//! test pages (web/loader.js, `?test`): the sign-in screen, signing in, each
//! page, and what an admin does with forms (`&scenario`). Then it reads the
//! server's database to see that the forms arrived there. termgate (and the
//! relay it runs) is stopped at the end.
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
    const gpa = init.gpa;
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

    const profile = try std.fs.path.join(arena, &.{ work, "profile" });
    var browser: Browser = .{ .gpa = gpa, .io = io, .arena = arena, .profile = profile };

    std.debug.print("web-test: the panel in headless Chrome ({s})\n", .{work});
    const base = "http://" ++ panel_addr ++ "/index.html?test";

    var title = browser.title(base);
    check(std.mem.eql(u8, title, "test: ok (sign-in screen)"), "sign-in screen, a wrong password is refused: {s}", .{title});

    title = browser.title(try std.fmt.allocPrint(arena, base ++ "&setup&name=superuser&password={s}", .{password}));
    check(std.mem.eql(u8, title, "test: ok (setup screen)"), "first sign-in shows the setup key and its QR code: {s}", .{title});

    title = browser.title(try std.fmt.allocPrint(arena, base ++ "&name=superuser&password={s}", .{password}));
    check(std.mem.startsWith(u8, title, "test: ok (signed in"), "signing in with the second step: {s}", .{title});

    inline for (.{ "Nodes", "People", "Sessions", "Audit", "Users", "Roles", "Configuration", "Help", "Profile" }, 0..) |name, n| {
        title = browser.title(std.fmt.comptimePrint(base ++ "&page={d}", .{n}));
        check(std.mem.startsWith(u8, title, "test: ok (signed in"), "page " ++ name ++ ": {s}", .{title});
    }

    // The theme: the box in the panel at the top right switches it
    title = browser.title(base ++ "&page=4&tap=7,43");
    check(std.mem.startsWith(u8, title, "test: ok (signed in, dark)"), "the dark theme is switched on: {s}", .{title});

    title = browser.title(base ++ "&scenario");
    check(std.mem.eql(u8, title, "test: ok (scenario)"), "forms (node, invitation, roles, user with a role, setting, sign out): {s}", .{title});

    title = browser.title(base);
    check(std.mem.eql(u8, title, "test: ok (sign-in screen)"), "signed out: {s}", .{title});

    // What the forms left in the database
    const db_path = try std.fmt.allocPrintSentinel(arena, "{s}/data/termgate.db", .{work}, 0);
    var db = dbm.Db.open(db_path) catch fail("cannot open {s}", .{db_path});
    defer db.close();
    check(named(try db.nodeList(arena), "web_gw01"), "database: node web_gw01", .{});
    check(named(try db.personList(arena), "Veli"), "database: person Veli", .{});
    const users = try db.userList(arena);
    check(named(users, "veli"), "database: user veli", .{});
    for (users) |u| {
        if (!std.mem.eql(u8, u.name, "veli")) continue;
        const roles = try db.userRoles(arena, u.id);
        check(roles.len == 1 and std.mem.eql(u8, roles[0].name, "admin"), "database: veli has the role admin", .{});
    }
    const roles = try db.roleList(arena);
    check(named(roles, "operator") and !named(roles, "zz-temp"), "database: role operator is there, zz-temp was deleted", .{});
    for (roles) |r| {
        if (!std.mem.eql(u8, r.name, "operator")) continue;
        const have = try db.roleRights(arena, r.id);
        check(have.len == 2 and dbm.rights.has(have, "node", "browse") and dbm.rights.has(have, "session", "watch"), "database: operator has node:browse and session:watch", .{});
    }
    // Acting as veli is in the audit, and what was done meanwhile names both
    var acted = false;
    var back = false;
    for (try db.actionsRecent(arena, 200)) |act| {
        if (std.mem.eql(u8, act.call, "users.select") and std.mem.eql(u8, act.user, "superuser") and std.mem.eql(u8, act.detail, "veli")) acted = true;
        if (std.mem.eql(u8, act.call, "users.unselect") and std.mem.eql(u8, act.user, "superuser as veli")) back = true;
    }
    check(acted and back, "database: the audit has superuser acting as veli and back", .{});
    const minutes = (try db.settingsGet()).max_session_minutes;
    check(minutes == 90, "database: session length {d} minutes", .{minutes});

    if (failed != 0) {
        server.kill(io);
        fail("{d} failed; termgate's output is in {s}", .{ failed, log_path });
    }
    std.debug.print("web-test: all passed\n", .{});
}

/// The password `termgate init` prints for the first admin.
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

const Browser = struct {
    gpa: std.mem.Allocator,
    io: Io,
    arena: std.mem.Allocator,
    profile: []const u8,
    /// Which of `browsers` is installed, once known
    exe: ?[]const u8 = null,

    /// Opens the page and returns its title once the test in it has run.
    /// The profile folder keeps the session between the pages.
    fn title(b: *Browser, url: []const u8) []const u8 {
        const dom = b.dump(url);
        const open = "<title>";
        const start = (std.mem.indexOf(u8, dom, open) orelse return "(the page has no title)") + open.len;
        const end = std.mem.indexOfPos(u8, dom, start, "</title>") orelse return "(the page has no title)";
        return dom[start..end];
    }

    fn dump(b: *Browser, url: []const u8) []const u8 {
        const profile_arg = std.fmt.allocPrint(b.arena, "--user-data-dir={s}", .{b.profile}) catch @panic("OOM");
        const candidates: []const []const u8 = if (b.exe) |e| &.{e} else &browsers;
        for (candidates) |exe| {
            const r = std.process.run(b.arena, b.io, .{ .argv = &.{
                exe,                           "--headless=new", "--no-sandbox", "--disable-gpu",
                "--virtual-time-budget=15000", profile_arg,      "--dump-dom",   url,
            } }) catch |e| switch (e) {
                error.FileNotFound => continue,
                else => fail("cannot run {s}: {s}", .{ exe, @errorName(e) }),
            };
            b.exe = exe;
            return r.stdout;
        }
        fail("no Chrome found (looked for google-chrome, chromium, chromium-browser)", .{});
    }
};
