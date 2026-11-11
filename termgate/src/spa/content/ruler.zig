//! The page numbers under a list: our earlier project's content/ruler, as it is.
//! First, <<, the numbers around the current page, >>, Last; each a
//! button with `action` and its page number (data-pn).

const std = @import("std");
const app = @import("../app.zig");

/// How many numbers on each side of the current page (our earlier project's
/// rulerLen, 4 by default)
const ruler_len = 4;

pub fn render(b: *app.Buf, total_pages: i64, page_no: i64, action: []const u8) void {
    if (total_pages < 2) return;

    var start = page_no - ruler_len;
    if (start < 1) start = 1;

    var end = start + ruler_len * 2;
    if (end > total_pages) {
        start -= end - total_pages;
        if (start < 1) start = 1;
        end = total_pages;
    }

    b.raw("<div class=\"pagination\"><ul class=\"clear\">");

    // First, <<
    if (start > 1) {
        renderItem(b, action, 1, "First", false);
        renderItem(b, action, @max(1, page_no - ruler_len), "&lt;&lt;", false);
    }

    // Page numbers
    var i = start;
    while (i <= end) : (i += 1) renderItem(b, action, i, std.fmt.allocPrint(app.arena(), "{d}", .{i}) catch "", i == page_no);

    // >>, Last
    if (end < total_pages) {
        renderItem(b, action, @min(total_pages, page_no + ruler_len), "&gt;&gt;", false);
        renderItem(b, action, total_pages, "Last", false);
    }

    b.raw("</ul></div>");
}

fn renderItem(b: *app.Buf, action: []const u8, pn: i64, label: []const u8, active: bool) void {
    b.raw(if (active) "<li class=\"active\">" else "<li>");
    b.add("<button type=\"button\" data-action=\"{s}\" data-pn=\"{d}\">{s}</button></li>", .{ action, pn, label });
}
