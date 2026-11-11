//! A page's title: our earlier project's content/page_title. Its parts joined by
//! an arrow (an earlier part may be a link).

const std = @import("std");
const app = @import("../app.zig");

pub const PageTitle = struct {
    items: std.ArrayList([]const u8) = .empty,

    /// A part, as HTML (text from users escaped by the caller)
    pub fn add(pt: *PageTitle, comptime fmt: []const u8, args: anytype) *PageTitle {
        pt.items.append(app.arena(), std.fmt.allocPrint(app.arena(), fmt, args) catch "") catch {};
        return pt;
    }

    pub fn render(pt: *const PageTitle, b: *app.Buf) void {
        b.raw("<div class=\"page-title primary\"><h3>");
        for (pt.items.items, 0..) |item, i| {
            if (i > 0) b.raw(" <i class=\"fa fa-fw fa-angle-right\"></i> ");
            b.raw(item);
        }
        b.raw("</h3></div>");
    }
};
