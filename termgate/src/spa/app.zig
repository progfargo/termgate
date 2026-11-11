//! What every part of the single-page app uses: the allocator of the
//! current event (reset when the page's next event starts) and a buffer
//! for HTML, as our earlier project's util.Buf.

const std = @import("std");
const builtin = @import("builtin");

/// Lives as long as the page (the tests run natively)
pub const gpa = if (builtin.cpu.arch == .wasm32) std.heap.wasm_allocator else std.heap.page_allocator;

var event_arena: std.heap.ArenaAllocator = .init(gpa);

/// For one event (a click, a hash change): freed when the next one starts.
pub fn arena() std.mem.Allocator {
    return event_arena.allocator();
}

pub fn beginEvent() void {
    _ = event_arena.reset(.retain_capacity);
}

/// HTML written piece by piece. `add` formats; text from users goes in
/// through `{f}` with `esc(text)`, which escapes it.
pub const Buf = struct {
    list: std.ArrayList(u8) = .empty,

    pub fn add(b: *Buf, comptime fmt: []const u8, args: anytype) void {
        b.list.print(arena(), fmt, args) catch {};
    }

    pub fn raw(b: *Buf, text: []const u8) void {
        b.list.appendSlice(arena(), text) catch {};
    }

    pub fn str(b: *const Buf) []const u8 {
        return b.list.items;
    }
};

/// Text escaped for HTML, for `{f}` in Buf.add.
pub fn esc(text: []const u8) Escaped {
    return .{ .text = text };
}

pub const Escaped = struct {
    text: []const u8,

    pub fn format(e: Escaped, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (e.text) |ch| switch (ch) {
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '&' => try w.writeAll("&amp;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&#39;"),
            else => try w.writeByte(ch),
        };
    }
};

/// The query of a hash ("id=3&key=x"): a value by name, "" if not there.
pub fn queryValue(query: []const u8, name: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
    }
    return "";
}

pub fn queryInt(query: []const u8, name: []const u8) i64 {
    return std.fmt.parseInt(i64, queryValue(query, name), 10) catch 0;
}

test "escaping" {
    var b: Buf = .{};
    b.add("<td>{f}</td>", .{esc("<a href=\"x\">&'")});
    try std.testing.expectEqualStrings("<td>&lt;a href=&quot;x&quot;&gt;&amp;&#39;</td>", b.str());
}
