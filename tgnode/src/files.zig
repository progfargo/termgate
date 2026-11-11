//! Small helpers for reading /proc, /sys and /etc files.

const std = @import("std");
const Io = std.Io;

/// File contents without surrounding whitespace; "" if it cannot be read.
/// Reads to end of file instead of trusting the size: /proc and /sys files
/// report a size of 0. Cancellation is passed on, never swallowed: a task is
/// told to stop only once, at its next cancelable call.
pub fn readTrim(arena: std.mem.Allocator, io: Io, root: Io.Dir, path: []const u8) ![]const u8 {
    var file = root.openFile(io, path, .{}) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return "",
    };
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var reader = file.readerStreaming(io, &buf);
    const data = reader.interface.allocRemaining(arena, .limited(1024 * 1024)) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ReadFailed => if (reader.err) |re| (if (re == error.Canceled) return error.Canceled else return "") else return "",
        else => return "",
    };
    return std.mem.trim(u8, data, " \t\r\n");
}

/// Value after the first ':' of a "key: value" line, trimmed.
pub fn afterColon(line: []const u8) []const u8 {
    const i = std.mem.indexOfScalar(u8, line, ':') orelse return "";
    return std.mem.trim(u8, line[i + 1 ..], " \t\r");
}

/// Test helper: creates files (path, contents) under `dir`.
pub fn writeTree(io: Io, dir: Io.Dir, tree: []const [2][]const u8) !void {
    for (tree) |f| {
        if (std.fs.path.dirname(f[0])) |d| try dir.createDirPath(io, d);
        try dir.writeFile(io, .{ .sub_path = f[0], .data = f[1] });
    }
}
