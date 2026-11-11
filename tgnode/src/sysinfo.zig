//! System information for the asset screen, sent on status.<node> (Linux).
//!
//! Text sources are read under a root directory (/ in production, a fake tree
//! in tests); kernel and disk figures come from uname() and statvfs() (via
//! src/sys_helpers.c).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const c = @import("c");
const files = @import("files.zig");

// src/sys_helpers.c
extern fn tgnode_disk_space(path: [*:0]const u8, total: *c_ulonglong, avail: *c_ulonglong) c_int;

pub const Status = struct {
    /// tgnode version
    version: []const u8,
    hostname: []const u8,
    /// PRETTY_NAME from /etc/os-release
    os: []const u8,
    kernel: []const u8,
    arch: []const u8,
    cpus: u32,
    uptime_s: u64,
    load: [3]f64,
    mem_total_kb: u64,
    mem_available_kb: u64,
    disk_total_bytes: u64,
    disk_free_bytes: u64,
    /// The sessions open on the node now (filled in by the agent): termgate
    /// ends those it still has open but the node does not
    sessions: []const []const u8 = &.{},
};

pub const version = "0.0.0";

/// Collects the current status. Strings live in `arena`.
pub fn collect(arena: std.mem.Allocator, io: Io, root: Io.Dir, disk_path: [:0]const u8) !Status {
    var s: Status = .{
        .version = version,
        .hostname = "",
        .os = try osName(arena, io, root),
        .kernel = "",
        .arch = @tagName(builtin.cpu.arch),
        .cpus = try cpuCount(arena, io, root),
        .uptime_s = try uptime(arena, io, root),
        .load = try loadAvg(arena, io, root),
        .mem_total_kb = 0,
        .mem_available_kb = 0,
        .disk_total_bytes = 0,
        .disk_free_bytes = 0,
    };
    const mem = try memInfo(arena, io, root);
    s.mem_total_kb = mem.total;
    s.mem_available_kb = mem.available;

    var uts: c.struct_utsname = undefined;
    if (c.uname(&uts) == 0) {
        s.hostname = try arena.dupe(u8, std.mem.sliceTo(&uts.nodename, 0));
        s.kernel = try arena.dupe(u8, std.mem.sliceTo(&uts.release, 0));
    }
    var total: c_ulonglong = 0;
    var avail: c_ulonglong = 0;
    if (tgnode_disk_space(disk_path.ptr, &total, &avail) == 0) {
        s.disk_total_bytes = total;
        s.disk_free_bytes = avail;
    }
    return s;
}

fn osName(arena: std.mem.Allocator, io: Io, root: Io.Dir) ![]const u8 {
    const data = try files.readTrim(arena, io, root, "etc/os-release");
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "PRETTY_NAME=")) {
            return std.mem.trim(u8, line["PRETTY_NAME=".len..], "\"'");
        }
    }
    return "";
}

fn cpuCount(arena: std.mem.Allocator, io: Io, root: Io.Dir) !u32 {
    const data = try files.readTrim(arena, io, root, "proc/cpuinfo");
    var n: u32 = 0;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, "processor")) n += 1;
    }
    return n;
}

fn uptime(arena: std.mem.Allocator, io: Io, root: Io.Dir) !u64 {
    const data = try files.readTrim(arena, io, root, "proc/uptime");
    var it = std.mem.tokenizeScalar(u8, data, ' ');
    const first = it.next() orelse return 0;
    const secs = std.fmt.parseFloat(f64, first) catch return 0;
    return @intFromFloat(@max(secs, 0));
}

fn loadAvg(arena: std.mem.Allocator, io: Io, root: Io.Dir) ![3]f64 {
    const data = try files.readTrim(arena, io, root, "proc/loadavg");
    var out: [3]f64 = @splat(0);
    var it = std.mem.tokenizeScalar(u8, data, ' ');
    for (&out) |*v| v.* = std.fmt.parseFloat(f64, it.next() orelse break) catch 0;
    return out;
}

fn memInfo(arena: std.mem.Allocator, io: Io, root: Io.Dir) !struct { total: u64, available: u64 } {
    const data = try files.readTrim(arena, io, root, "proc/meminfo");
    var total: u64 = 0;
    var available: u64 = 0;
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        const value = files.afterColon(line);
        var num = std.mem.tokenizeScalar(u8, value, ' ');
        const kb = std.fmt.parseInt(u64, num.next() orelse continue, 10) catch continue;
        if (std.mem.startsWith(u8, line, "MemTotal:")) total = kb;
        if (std.mem.startsWith(u8, line, "MemAvailable:")) available = kb;
    }
    return .{ .total = total, .available = available };
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "status from a fake machine" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try files.writeTree(io, tmp.dir, &.{
        .{ "etc/os-release", "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n" },
        .{ "proc/cpuinfo", "processor\t: 0\nmodel name\t: ARMv7\n\nprocessor\t: 1\nmodel name\t: ARMv7\n" },
        .{ "proc/uptime", "86461.53 170000.10\n" },
        .{ "proc/loadavg", "0.15 0.30 0.25 1/123 4567\n" },
        .{ "proc/meminfo", "MemTotal:        1009032 kB\nMemFree:          100000 kB\nMemAvailable:     512016 kB\n" },
    });
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const s = try collect(arena.allocator(), io, tmp.dir, "/");
    try testing.expectEqualStrings("Debian GNU/Linux 12 (bookworm)", s.os);
    try testing.expectEqual(@as(u32, 2), s.cpus);
    try testing.expectEqual(@as(u64, 86461), s.uptime_s);
    try testing.expectApproxEqAbs(@as(f64, 0.30), s.load[1], 0.001);
    try testing.expectEqual(@as(u64, 1009032), s.mem_total_kb);
    try testing.expectEqual(@as(u64, 512016), s.mem_available_kb);
    // uname and statvfs come from the machine running the test
    try testing.expect(s.kernel.len > 0);
    try testing.expect(s.disk_total_bytes >= s.disk_free_bytes and s.disk_total_bytes > 0);
}

test "missing sources give zeros and empty strings" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const s = try collect(arena.allocator(), io, tmp.dir, "/nonexistent-path");
    try testing.expectEqualStrings("", s.os);
    try testing.expectEqual(@as(u32, 0), s.cpus);
    try testing.expectEqual(@as(u64, 0), s.mem_total_kb);
    try testing.expectEqual(@as(u64, 0), s.disk_total_bytes);
}
