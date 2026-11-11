//! Running the official nats-server: finding the binary, checking a
//! configuration, and keeping the server running. termgate runs its relay
//! with this.
//!
//! The supervisor starts nats-server in a home folder that holds
//! nats-server.conf, and when it exits starts it again after a pause that
//! grows from 1 to 30 seconds (and starts from 1 again after a minute of
//! good running).
//!
//! Stopping: under systemd the stop signal reaches both the supervising
//! program and nats-server (one control group); interactively Ctrl+C reaches
//! both too. stop() is for embedding and tests.

const std = @import("std");
const Io = std.Io;

const log = std.log.scoped(.natsd);


pub const Supervisor = struct {
    io: Io,
    nats_server: []const u8,
    home: []const u8,
    stopping: std.atomic.Value(bool) = .init(false),
    /// pid of the running nats-server, 0 when none
    pid: std.atomic.Value(i32) = .init(0),
    /// How many times nats-server was started
    starts: std.atomic.Value(u32) = .init(0),
    min_backoff_ms: u64 = 1000,

    pub fn run(s: *Supervisor) !void {
        var backoff_ms: u64 = s.min_backoff_ms;
        while (!s.stopping.load(.acquire)) {
            const started = Io.Clock.Timestamp.now(s.io, .awake);
            var child = try std.process.spawn(s.io, .{
                .argv = &.{ s.nats_server, "-c", "nats-server.conf" },
                .cwd = .{ .path = s.home },
            });
            s.pid.store(child.id.?, .release);
            _ = s.starts.fetchAdd(1, .release);
            log.info("nats-server started (pid {d})", .{child.id.?});
            const term = child.wait(s.io) catch |e| {
                s.pid.store(0, .release);
                return e;
            };
            s.pid.store(0, .release);
            if (s.stopping.load(.acquire)) break;
            log.warn("nats-server ended ({any}); starting again in {d} ms", .{ term, backoff_ms });

            const ran_ms = @divTrunc(started.durationTo(Io.Clock.Timestamp.now(s.io, .awake)).raw.nanoseconds, std.time.ns_per_ms);
            if (ran_ms > 60_000) backoff_ms = s.min_backoff_ms;
            try s.io.sleep(.fromMilliseconds(@intCast(backoff_ms)), .awake);
            backoff_ms = @min(backoff_ms * 2, 30_000);
        }
    }

    /// Stops supervising and ends nats-server (SIGTERM).
    pub fn stop(s: *Supervisor) void {
        s.stopping.store(true, .release);
        const pid = s.pid.load(.acquire);
        if (pid > 0) std.posix.kill(pid, .TERM) catch {};
    }
};

/// Finds the nats-server binary: the given path, next to the program, or on PATH.
/// The caller owns the result.
pub fn findNatsServer(gpa: std.mem.Allocator, io: Io, explicit: ?[]const u8, self_dir: ?[]const u8, path_env: ?[]const u8) ![]u8 {
    const cwd = Io.Dir.cwd();
    if (explicit) |p| {
        _ = try cwd.statFile(io, p, .{});
        return gpa.dupe(u8, p);
    }
    if (self_dir) |d| {
        const p = try std.fs.path.join(gpa, &.{ d, "nats-server" });
        if (cwd.statFile(io, p, .{})) |_| return p else |_| gpa.free(p);
    }
    var it = std.mem.splitScalar(u8, path_env orelse "", ':');
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const p = try std.fs.path.join(gpa, &.{ dir, "nats-server" });
        if (cwd.statFile(io, p, .{})) |_| return p else |_| gpa.free(p);
    }
    return error.NatsServerNotFound;
}

/// Runs "nats-server -t -c nats-server.conf" in `home`. Returns the server's
/// message when the configuration is invalid.
pub fn checkConfig(gpa: std.mem.Allocator, io: Io, nats_server: []const u8, home: []const u8) !?[]u8 {
    const r = try std.process.run(gpa, io, .{
        .argv = &.{ nats_server, "-t", "-c", "nats-server.conf" },
        .cwd = .{ .path = home },
    });
    defer gpa.free(r.stdout);
    if (r.term.success()) {
        gpa.free(r.stderr);
        return null;
    }
    return r.stderr;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn tmpPath(tmp: *testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(testing.io, buf);
    return buf[0..n];
}

test "nats-server lookup order" {
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "bin1");
    try tmp.dir.createDirPath(io, "bin2");
    try tmp.dir.writeFile(io, .{ .sub_path = "bin2/nats-server", .data = "" });
    var buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const root = try tmpPath(&tmp, &buf);
    const path_env = try std.fmt.allocPrint(a, "{s}/bin1:{s}/bin2", .{ root, root });
    defer a.free(path_env);

    const found = try findNatsServer(a, io, null, null, path_env);
    defer a.free(found);
    try testing.expect(std.mem.endsWith(u8, found, "/bin2/nats-server"));
    try testing.expectError(error.NatsServerNotFound, findNatsServer(a, io, null, null, "/nonexistent"));
}
