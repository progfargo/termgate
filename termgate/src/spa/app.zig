//! What every part of the single-page app uses: the allocator of the
//! current event (reset when the page's next event starts) and a buffer
//! for HTML, as our earlier project's util.Buf.

const std = @import("std");
const builtin = @import("builtin");

/// Lives as long as the page (the tests run natively)
pub const gpa = if (builtin.cpu.arch == .wasm32) std.heap.wasm_allocator else std.heap.page_allocator;

var event_arena: std.heap.ArenaAllocator = .init(gpa);

/// A run of a job waits for an answer (fetch.zig): the rest of the run
/// changes nothing on the page (dom, state, router leave it).
pub var waiting = false;

/// For one event (a click, a hash change): freed when the next one starts.
pub fn arena() std.mem.Allocator {
    return event_arena.allocator();
}

pub fn beginEvent() void {
    _ = event_arena.reset(.retain_capacity);
}

// web/spa/boot.js
extern "env" fn tg_now() f64;

/// Unix seconds, from the browser's clock.
pub fn now() i64 {
    if (builtin.cpu.arch != .wasm32) return 0;
    return @intFromFloat(tg_now() / 1000);
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

/// The query of a hash ("id=3&key=x"): a value by name, "" if not there;
/// %xx decoded. Pages read their address with lib/cargo.zig, which uses
/// this.
pub fn queryValue(query: []const u8, name: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return urlDecode(kv[eq + 1 ..]);
    }
    return "";
}

/// A value for an address's query: letters, digits and -_.~ as they are,
/// everything else %xx.
pub fn urlEncode(text: []const u8) []const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (text) |ch| {
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == '~') {
            out.append(arena(), ch) catch return "";
        } else out.print(arena(), "%{X:0>2}", .{ch}) catch return "";
    }
    return out.items;
}

fn urlDecode(text: []const u8) []const u8 {
    if (std.mem.indexOfAny(u8, text, "%+") == null) return text;
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (text[i] == '%' and i + 2 < text.len + 0 and i + 2 <= text.len - 1) {
            const v = std.fmt.parseInt(u8, text[i + 1 .. i + 3], 16) catch {
                out.append(arena(), '%') catch return text;
                continue;
            };
            out.append(arena(), v) catch return text;
            i += 2;
        } else out.append(arena(), if (text[i] == '+') ' ' else text[i]) catch return text;
    }
    return out.items;
}

test "addresses" {
    try std.testing.expectEqualStrings("ist%20gw%26x", urlEncode("ist gw&x"));
    try std.testing.expectEqualStrings("ist gw&x", queryValue("pn=2&key=ist%20gw%26x", "key"));
    try std.testing.expectEqualStrings("2", queryValue("pn=2&key=x", "pn"));
}

test "escaping" {
    var b: Buf = .{};
    b.add("<td>{f}</td>", .{esc("<a href=\"x\">&'")});
    try std.testing.expectEqualStrings("<td>&lt;a href=&quot;x&quot;&gt;&amp;&#39;</td>", b.str());
}

test {
    _ = @import("lib/cargo.zig");
}
