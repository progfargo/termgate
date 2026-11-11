//! The local terminal: raw mode and window size (POSIX).

const std = @import("std");
const c = @import("c");

pub const Size = struct { cols: u16, rows: u16 };

/// Puts the terminal on `fd` into raw mode; restore() puts it back.
pub const Raw = struct {
    fd: c_int,
    saved: c.struct_termios,

    pub fn enter(fd: c_int) !Raw {
        var t: c.struct_termios = undefined;
        if (c.tcgetattr(fd, &t) != 0) return error.NotATerminal;
        const saved = t;
        c.cfmakeraw(&t);
        if (c.tcsetattr(fd, c.TCSANOW, &t) != 0) return error.NotATerminal;
        return .{ .fd = fd, .saved = saved };
    }

    pub fn restore(r: Raw) void {
        _ = c.tcsetattr(r.fd, c.TCSANOW, &r.saved);
    }
};

pub fn isTerminal(fd: c_int) bool {
    return c.isatty(fd) == 1;
}

/// Window size of the terminal on `fd`, or null if it is not a terminal.
pub fn size(fd: c_int) ?Size {
    var ws: c.struct_winsize = undefined;
    if (c.ioctl(fd, c.TIOCGWINSZ, &ws) != 0 or ws.ws_col == 0) return null;
    return .{ .cols = ws.ws_col, .rows = ws.ws_row };
}

/// The resize message tgnode expects: cols, rows as 16-bit big-endian.
pub fn encodeSize(s: Size) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u16, b[0..2], s.cols, .big);
    std.mem.writeInt(u16, b[2..4], s.rows, .big);
    return b;
}

/// Watches typed input for the escape sequence "~." at the start of a line
/// (as in ssh), which ends the session.
pub const Escape = struct {
    /// 0: not at line start, 1: at line start, 2: saw "~" at line start
    state: u8 = 1,

    /// Returns true when the input completes "~.". Bytes are still sent as
    /// typed, except that the session ends at that point.
    pub fn feed(e: *Escape, byte: u8) bool {
        switch (e.state) {
            2 => {
                if (byte == '.') return true;
                e.state = if (byte == '\r' or byte == '\n') 1 else 0;
            },
            1 => e.state = if (byte == '~') 2 else if (byte == '\r' or byte == '\n') 1 else 0,
            else => e.state = if (byte == '\r' or byte == '\n') 1 else 0,
        }
        return false;
    }
};

test "resize message" {
    try std.testing.expectEqualSlices(u8, &.{ 0, 120, 0, 40 }, &encodeSize(.{ .cols = 120, .rows = 40 }));
}

test "escape sequence ~. only at the start of a line" {
    var e: Escape = .{};
    for ("~.") |b| if (e.feed(b)) return;
    return error.TestExpectedEscape;
}

test "~. inside a line is ordinary input" {
    var e: Escape = .{};
    for ("ls ~.\r") |b| try std.testing.expect(!e.feed(b));
    var f: Escape = .{};
    for ("ls\r~") |b| try std.testing.expect(!f.feed(b));
    try std.testing.expect(f.feed('.'));
}
