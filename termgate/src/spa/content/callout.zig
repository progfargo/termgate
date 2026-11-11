//! A box of notes: our earlier project's content/callout.

const std = @import("std");
const app = @import("../app.zig");

pub const Callout = struct {
    class: []const u8 = "Primary",
    title: []const u8 = "",
    items: std.ArrayList([]const u8) = .empty,

    pub fn setClass(c: *Callout, class: []const u8) *Callout {
        c.class = class;
        return c;
    }

    pub fn setTitle(c: *Callout, title: []const u8) *Callout {
        c.title = title;
        return c;
    }

    /// A paragraph, as HTML (text from users escaped by the caller)
    pub fn add(c: *Callout, comptime fmt: []const u8, args: anytype) *Callout {
        c.items.append(app.arena(), std.fmt.allocPrint(app.arena(), fmt, args) catch "") catch {};
        return c;
    }

    pub fn render(c: *const Callout, b: *app.Buf) void {
        b.add("<div class=\"callout callout{s}\"><h4>{s}</h4>", .{ c.class, c.title });
        for (c.items.items) |item| b.add("<p>{s}</p>", .{item});
        b.raw("</div>");
    }
};
