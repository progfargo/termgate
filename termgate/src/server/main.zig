//! termgate, the server program. The authority (auth callout, node
//! registration, access keys, session approvals, session logs, audit) runs
//! here around the clock, and the web panel is served from here: the UI
//! (WASM, zig-out/web) and the API it calls. HTTPS is nginx's job; termgate
//! listens on localhost.
//!
//! One program to install: termgate also runs the relay, the official
//! nats-server, from the relay kit in its data and keeps it running. When
//! termgate stops, the relay stops with it.
//!
//! No folders are asked for on the command line. termgate works in the
//! folder it is started in: its data (database, keys, CA, relay kit) is
//! ./data there. The panel's files are next to the binary, in ../web.
//!
//! Usage:
//!   termgate init --relay HOST[:PORT]
//!       first start: keys, CA, relay kit. HOST is the address gateways and
//!       users reach the relay at
//!   termgate run [--listen ADDR:PORT] [--nats PATH]
//!       run termgate and the relay
//!   termgate service [--listen ADDR:PORT] [--nats PATH]
//!       install and start the systemd service for this folder (root)
//! Defaults: listen 127.0.0.1:8080, nats-server next to the binary or on
//! PATH.

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");
const service_mod = @import("service");
const Recorder = @import("recorder").Recorder;
const setup = @import("setup");
const http = @import("http.zig");
const systemd = @import("systemd.zig");
const natsd = @import("core").natsd;
const auth_mod = @import("auth.zig");
const panel_mod = @import("panel.zig");

const log = std.log.scoped(.termgate);

const usage =
    \\usage:
    \\  termgate init --relay HOST[:PORT]               first start: keys, CA and the relay kit
    \\  termgate run [--listen ADDR:PORT] [--nats PATH]  run termgate and the relay
    \\  termgate service [same options as run]           install and start the systemd service (root)
    \\termgate works in the folder it is started in: its data is ./data there.
    \\defaults: --listen 127.0.0.1:8080, nats-server next to termgate or on PATH
    \\
;

const Options = struct {
    command: []const u8,
    /// The data folder; set from the current folder at start
    home: []const u8 = "",
    relay: ?[]const u8 = null,
    listen: []const u8 = "127.0.0.1:8080",
    nats: ?[]const u8 = null,
};

fn parseArgs(args: []const [:0]const u8) ?Options {
    if (args.len < 2) return null;
    var o: Options = .{ .command = args[1] };
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const k = args[i];
        if (i + 1 >= args.len) return null;
        i += 1;
        const v = args[i];
        if (std.mem.eql(u8, k, "--relay")) o.relay = v else if (std.mem.eql(u8, k, "--listen")) o.listen = v else if (std.mem.eql(u8, k, "--nats")) o.nats = v else return null;
    }
    return o;
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("termgate: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

fn now(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// The data folder and the database: readable by termgate's user only.
fn restrictData(arena: std.mem.Allocator, home: []const u8) void {
    for ([_][]const u8{ "", "/keys", "/relay-kit" }) |sub| {
        const path = std.fmt.allocPrintSentinel(arena, "{s}{s}", .{ home, sub }, 0) catch continue;
        _ = std.c.chmod(path, 0o700);
    }
    for ([_][]const u8{ "termgate.db", "termgate.db-wal", "termgate.db-shm", "ca.pem" }) |name| {
        const path = std.fmt.allocPrintSentinel(arena, "{s}/{s}", .{ home, name }, 0) catch continue;
        _ = std.c.chmod(path, 0o600);
    }
}

fn isLoopback(host: []const u8) bool {
    return std.mem.eql(u8, host, "127.0.0.1") or std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1");
}

/// "host" or "host:port"
fn splitHostPort(text: []const u8, default_port: u16) ?struct { host: []const u8, port: u16 } {
    const i = std.mem.lastIndexOfScalar(u8, text, ':') orelse return .{ .host = text, .port = default_port };
    const port = std.fmt.parseInt(u16, text[i + 1 ..], 10) catch return null;
    return .{ .host = text[0..i], .port = port };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var o = parseArgs(args) orelse {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    };
    // Everything termgate writes (database, keys, relay kit) is for its own
    // user only
    _ = std.c.umask(0o077);
    // termgate's data: ./data in the folder termgate is started in
    var cwd_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const work_dir = cwd_buf[0..try std.process.currentPath(io, &cwd_buf)];
    o.home = try std.fs.path.join(arena, &.{ work_dir, "data" });

    if (std.mem.eql(u8, o.command, "init")) {
        const r = splitHostPort(o.relay orelse fail("init needs --relay HOST[:PORT]", .{}), 4222) orelse fail("invalid --relay", .{});
        setup.create(gpa, io, o.home, .{ .relay_host = r.host, .relay_port = r.port }, now(io)) catch |e| fail("{s}", .{switch (e) {
            error.AlreadySetUp => "already set up (relay.json exists in the home)",
            error.InvalidHost => "the relay address must be a DNS name or an IP address",
            error.AccessDenied => "permission denied for the home folder",
            else => @errorName(e),
        }});
        // The first admin of the panel
        const db_path0 = try std.fmt.allocPrintSentinel(arena, "{s}/termgate.db", .{o.home}, 0);
        var db0 = dbm.Db.open(db_path0) catch fail("cannot open {s}", .{db_path0});
        defer db0.close();
        db0.setLogKey(io, setup.logKey(io, o.home) catch |e| fail("cannot read the session log key: {s}", .{@errorName(e)}));
        var lock0: Io.Mutex = .init;
        var auth0: auth_mod.Auth = .{ .gpa = gpa, .io = io, .db = &db0, .lock = &lock0 };
        const pw = (try auth_mod.firstSuperuser(&auth0, "superuser", now(io))) orelse fail("there are users already", .{});
        std.debug.print(
            \\termgate: set up in {s}
            \\
            \\panel user: superuser
            \\password:   {s}
            \\(shown once; at the first sign-in the panel sets up the second step)
            \\
            \\next: termgate run (or termgate service). The relay listens on port {d}: open it to gateways and users.
            \\
        , .{ o.home, &pw, r.port });
        return;
    }
    const as_service = std.mem.eql(u8, o.command, "service");
    if (!as_service and !std.mem.eql(u8, o.command, "run")) {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    }

    var self_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const self_n = std.process.executablePath(io, &self_buf) catch 0;
    const self_path = self_buf[0..self_n];
    const self_dir = std.fs.path.dirname(self_path) orelse ".";

    // The relay: nats-server with the kit in the home
    const kit_dir = try std.fs.path.join(arena, &.{ o.home, "relay-kit" });
    var nats_path: []const u8 = natsd.findNatsServer(arena, io, o.nats, self_dir, init.environ_map.get("PATH")) catch
        fail("nats-server not found; put it next to termgate, on PATH, or give --nats", .{});
    if (!std.fs.path.isAbsolute(nats_path)) nats_path = try std.fs.path.join(arena, &.{ work_dir, nats_path });
    if (natsd.checkConfig(gpa, io, nats_path, kit_dir) catch |e| fail("cannot check the relay configuration in {s}: {s} (run termgate init first)", .{ kit_dir, @errorName(e) })) |msg|
        fail("the relay configuration in {s} is not valid:\n{s}", .{ kit_dir, msg });

    if (as_service) {
        if (self_n == 0) fail("cannot find termgate's own path", .{});
        systemd.install(gpa, io, .{ .termgate = self_path, .dir = work_dir, .listen = o.listen, .nats = nats_path }) catch |e| fail("{s}", .{switch (e) {
            error.AccessDenied => "permission denied: run as root",
            else => @errorName(e),
        }});
        std.debug.print("termgate: service installed and started ({s}); see: systemctl status termgate\n", .{systemd.unit_path});
        return;
    }

    var relay: natsd.Supervisor = .{ .io = io, .nats_server = nats_path, .home = kit_dir };
    // Stopped by a signal (kill, Ctrl+C, systemd): the relay stops too
    stopping_relay = &relay;
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onStopSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
    var relay_task = try io.concurrent(runRelay, .{&relay});
    defer {
        relay.stop();
        relay_task.cancel(io);
    }

    // Configuration, keys and data, for termgate's user only (also in a
    // folder made before termgate did so)
    restrictData(arena, o.home);
    const cfg_path = try std.fs.path.join(arena, &.{ o.home, "relay.json" });
    var loaded = service_mod.loadConfig(gpa, io, cfg_path) catch |e| fail("cannot read {s}: {s} (run termgate init first)", .{ cfg_path, @errorName(e) });
    defer loaded.deinit();
    const db_path = try std.fmt.allocPrintSentinel(arena, "{s}/termgate.db", .{o.home}, 0);
    var db = dbm.Db.open(db_path) catch fail("cannot open {s}", .{db_path});
    defer db.close();
    db.setLogKey(io, setup.logKey(io, o.home) catch |e| fail("cannot read the session log key: {s}", .{@errorName(e)}));
    var db_lock: Io.Mutex = .init;
    var recorder: Recorder = .init(gpa, io, &db, &db_lock);
    defer recorder.deinit();

    // The web panel
    const web_dir = try std.fs.path.join(arena, &.{ self_dir, "..", "web" });
    const l = splitHostPort(o.listen, 8080) orelse fail("invalid --listen", .{});
    var auth: auth_mod.Auth = .{ .gpa = gpa, .io = io, .db = &db, .lock = &db_lock };
    // Without the second step (a debug build) the panel is for this
    // machine only
    if (!auth.second_step and !isLoopback(l.host))
        fail("this build signs in without the second step (a debug build): it listens on 127.0.0.1 or localhost only; build with -Doptimize=ReleaseSafe for a server", .{});
    var panel: panel_mod.Panel = .{
        .gpa = gpa,
        .io = io,
        .rpc = .{ .io = io, .db = &db, .lock = &db_lock },
        .relay_host = loaded.cfg.relay_host,
        .relay_port = loaded.cfg.relay_port,
        .ca_fingerprint = loaded.ca_fingerprint,
    };
    defer panel.deinit();
    var state: http.State = .{ .gpa = gpa, .io = io, .web_dir = web_dir, .auth = &auth, .panel = &panel };
    var web = http.listen(&state, l.host, l.port) catch |e| fail("cannot listen on {s}: {s}", .{ o.listen, @errorName(e) });
    defer web.stop();
    log.info("web panel on http://{s}:{d} (files: {s})", .{ l.host, l.port, web_dir });
    if (!auth.second_step) log.warn("a debug build: the panel signs in with the name and password alone; a release build asks for the authenticator code too", .{});

    // termgate on the relay, for ever: a lost connection is made again
    var service: ?*service_mod.Service = null;
    defer if (service) |sv| {
        panel.setService(null);
        sv.stop();
    };
    while (true) {
        if (service) |sv| if (!sv.alive()) {
            log.warn("lost the relay connection; reconnecting", .{});
            panel.setService(null);
            sv.stop();
            service = null;
        };
        if (service == null) {
            if (service_mod.Service.start(gpa, io, loaded.cfg, &db, &db_lock, &recorder)) |sv| {
                service = sv;
                panel.setService(sv);
                log.info("connected to the relay {s}:{d}", .{ loaded.cfg.relay_host, loaded.cfg.relay_port });
            } else |e| log.warn("cannot connect to the relay {s}:{d}: {s}", .{ loaded.cfg.relay_host, loaded.cfg.relay_port, @errorName(e) });
        }
        try io.sleep(.fromSeconds(5), .awake);
    }
}

var stopping_relay: ?*natsd.Supervisor = null;

/// Ends nats-server and termgate. Only async-signal-safe calls (kill, exit).
fn onStopSignal(_: std.posix.SIG) callconv(.c) void {
    if (stopping_relay) |r| {
        r.stopping.store(true, .release);
        const pid = r.pid.load(.acquire);
        if (pid > 0) std.posix.kill(pid, .TERM) catch {};
    }
    std.process.exit(0);
}

fn runRelay(sup: *natsd.Supervisor) void {
    sup.run() catch |e| log.err("the relay stopped: {s}", .{@errorName(e)});
}

test {
    _ = http;
    _ = systemd;
    _ = @import("auth.zig");
    _ = @import("rpc.zig");
    _ = @import("api.zig");
    _ = @import("qr.zig");
    _ = panel_mod;
}

test "arguments" {
    const o = parseArgs(&.{ "termgate", "run", "--listen", "0.0.0.0:9000" }).?;
    try std.testing.expectEqualStrings("0.0.0.0:9000", o.listen);
    try std.testing.expect(parseArgs(&.{ "termgate", "run", "--listen" }) == null);
    // No folders on the command line
    try std.testing.expect(parseArgs(&.{ "termgate", "run", "--home", "/tmp/h" }) == null);
    try std.testing.expect(parseArgs(&.{ "termgate", "run", "--web", "/tmp/w" }) == null);
    try std.testing.expect(parseArgs(&.{"termgate"}) == null);
    const r = splitHostPort("relay.example.com:4333", 4222).?;
    try std.testing.expectEqual(@as(u16, 4333), r.port);
    try std.testing.expectEqualStrings("relay.example.com", splitHostPort("relay.example.com", 4222).?.host);
}
