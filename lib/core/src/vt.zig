//! A terminal screen (libghostty-vt): termgate keeps one per watched
//! session, fed with the session's output from the moment watching starts.

const std = @import("std");
const gvt = @import("ghostty-vt");

pub const Screen = struct {
    gpa: std.mem.Allocator,
    term: gvt.Terminal,
    /// Points into `term`, so a Screen never moves (create/destroy)
    stream: gvt.TerminalStream,
    /// Reused by grid()
    render: gvt.RenderState = .empty,

    pub fn create(gpa: std.mem.Allocator, io: std.Io, width: u16, height: u16) !*Screen {
        const s = try gpa.create(Screen);
        errdefer gpa.destroy(s);
        s.gpa = gpa;
        // No scrollback: only what is on the screen matters
        s.term = try .init(io, gpa, .{ .cols = @max(width, 1), .rows = @max(height, 1), .max_scrollback_bytes = 0 });
        s.stream = s.term.vtStream();
        s.render = .empty;
        return s;
    }

    pub fn destroy(s: *Screen) void {
        s.render.deinit(s.gpa);
        s.stream.deinit();
        s.term.deinit(s.gpa);
        s.gpa.destroy(s);
    }

    /// Terminal output, as the shell wrote it.
    pub fn feed(s: *Screen, bytes: []const u8) void {
        s.stream.nextSlice(bytes);
    }

    pub fn resize(s: *Screen, width: u16, height: u16) void {
        if (width == 0 or height == 0) return;
        s.term.resize(s.gpa, .{ .cols = width, .rows = height }) catch {};
    }

    pub fn cols(s: *const Screen) u16 {
        return @intCast(s.term.cols);
    }

    pub fn rows(s: *const Screen) u16 {
        return @intCast(s.term.rows);
    }

    /// The visible screen as plain text, one line per row ("\n" between
    /// rows). Caller owns it.
    pub fn text(s: *Screen, gpa: std.mem.Allocator) ![]const u8 {
        return s.term.plainString(gpa);
    }

    pub const Cursor = struct { x: u16, y: u16 };

    pub const Rgb = struct {
        r: u8,
        g: u8,
        b: u8,

        pub fn hex(c: Rgb) u32 {
            return @as(u32, c.r) << 16 | @as(u32, c.g) << 8 | c.b;
        }
    };

    /// One cell as it is drawn: colors resolved (palette, bold as bright,
    /// inverse, faint), `cp` 0 for the second half of a wide character.
    pub const Cell = struct {
        cp: u21,
        fg: Rgb,
        bg: Rgb,
        bold: bool,
        underline: bool,
    };

    pub const Grid = struct {
        cols: u16,
        rows: u16,
        /// rows * cols, row by row
        cells: []Cell,
        /// The terminal's default background
        background: Rgb,
        /// null when the cursor is hidden
        cursor: ?Cursor,
    };

    /// The visible screen cell by cell, for drawing. Cells live in `a`.
    pub fn grid(s: *Screen, a: std.mem.Allocator) !Grid {
        const rs = &s.render;
        try rs.update(s.gpa, &s.term);
        const fg_default: Rgb = .{ .r = rs.colors.foreground.r, .g = rs.colors.foreground.g, .b = rs.colors.foreground.b };
        const bg_default: Rgb = .{ .r = rs.colors.background.r, .g = rs.colors.background.g, .b = rs.colors.background.b };
        const w: usize = rs.cols;
        const h: usize = rs.rows;
        const out = try a.alloc(Cell, w * h);
        @memset(out, .{ .cp = ' ', .fg = fg_default, .bg = bg_default, .bold = false, .underline = false });

        const range = rs.rowDataRange();
        const row_cells = rs.row_data.items(.cells);
        var y: usize = 0;
        for (range.start..range.end) |i| {
            if (y >= h) break;
            defer y += 1;
            const raws = row_cells[i].items(.raw);
            const styles = row_cells[i].items(.style);
            for (raws, 0..) |raw, x| {
                if (x >= w) break;
                const style: gvt.Style = if (raw.hasStyling()) styles[x] else .{};
                const fg = style.fg(.{ .default = rs.colors.foreground, .palette = &rs.colors.palette, .bold = .bright });
                const bg = style.bg(&raw, &rs.colors.palette) orelse rs.colors.background;
                var f: Rgb = .{ .r = fg.r, .g = fg.g, .b = fg.b };
                var b: Rgb = .{ .r = bg.r, .g = bg.g, .b = bg.b };
                if (style.flags.inverse) std.mem.swap(Rgb, &f, &b);
                if (style.flags.faint) f = .{ .r = f.r / 2 + b.r / 2, .g = f.g / 2 + b.g / 2, .b = f.b / 2 + b.b / 2 };
                out[y * w + x] = .{
                    .cp = if (raw.wide == .spacer_tail) 0 else if (raw.hasText()) raw.codepoint() else ' ',
                    .fg = f,
                    .bg = b,
                    .bold = style.flags.bold,
                    .underline = style.flags.underline != .none,
                };
            }
        }
        const cur: ?Cursor = if (rs.cursor.visible) if (rs.cursor.viewport) |v| .{ .x = @intCast(v.x), .y = @intCast(v.y) } else null else null;
        return .{ .cols = @intCast(w), .rows = @intCast(h), .cells = out, .background = bg_default, .cursor = cur };
    }

    pub fn cursor(s: *const Screen) Cursor {
        const c = s.term.screens.active.cursor;
        return .{ .x = @intCast(c.x), .y = @intCast(c.y) };
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "output, resize and a full-screen program" {
    const a = testing.allocator;
    const scr = try Screen.create(a, testing.io, 40, 10);
    defer scr.destroy();
    scr.feed("hello\r\n\x1b[1;31mred\x1b[0m world\r\n\x1b[5;10Hthere");
    {
        const t = try scr.text(a);
        defer a.free(t);
        try testing.expect(std.mem.indexOf(u8, t, "red world") != null);
        try testing.expectEqual(Screen.Cursor{ .x = 14, .y = 4 }, scr.cursor());
    }
    scr.resize(100, 30);
    try testing.expectEqual(@as(u16, 100), scr.cols());
    try testing.expectEqual(@as(u16, 30), scr.rows());

    // The alternate screen hides the shell until the program leaves it
    scr.feed("\x1b[?1049h\x1b[2J\x1b[Htop-like");
    {
        const t = try scr.text(a);
        defer a.free(t);
        try testing.expect(std.mem.indexOf(u8, t, "top-like") != null);
        try testing.expect(std.mem.indexOf(u8, t, "hello") == null);
    }
    scr.feed("\x1b[?1049l");
    const t = try scr.text(a);
    defer a.free(t);
    try testing.expect(std.mem.indexOf(u8, t, "hello") != null);
}

test "the grid has the colors" {
    const a = testing.allocator;
    const scr = try Screen.create(a, testing.io, 20, 3);
    defer scr.destroy();
    scr.feed("a\x1b[31mb\x1b[0m\x1b[7mc\x1b[0m\x1b[48;2;1;2;3md");
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const g = try scr.grid(arena.allocator());
    try testing.expectEqual(@as(u16, 20), g.cols);
    const c = g.cells;
    try testing.expectEqual(@as(u21, 'a'), c[0].cp);
    try testing.expect(c[1].fg.hex() != c[0].fg.hex()); // red
    try testing.expectEqual(c[0].fg.hex(), c[2].bg.hex()); // inverse
    try testing.expectEqual(c[0].bg.hex(), c[2].fg.hex());
    try testing.expectEqual(@as(u32, 0x010203), c[3].bg.hex());
    try testing.expectEqual(g.background.hex(), c[10].bg.hex());
    try testing.expectEqual(Screen.Cursor{ .x = 4, .y = 0 }, g.cursor.?);
}
