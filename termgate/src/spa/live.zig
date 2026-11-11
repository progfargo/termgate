//! The part of a page that shows what changes by itself (a node going
//! online or offline, a session opening or ending): the page puts it in
//! `<div id="live">` and gives its drawing function here. Every 5 seconds
//! (main.zig's tick) the function draws it again from fresh answers, and
//! the part is replaced only when it changed; the rest of the page, the
//! search box and the address stay as they are.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");

pub const id = "live";

/// Draws the part, or null while an answer has not come.
pub const Draw = *const fn () ?[]const u8;

var draw: ?Draw = null;
/// Counts the pages that put a live part: a tick started for one page
/// must not draw into the next
var page: u32 = 0;
/// The part as last shown, and when it was last asked
var shown: []u8 = &.{};
var asked: i64 = 0;

/// The page's live part in `b`, drawn by `f`; call it while building the
/// page.
pub fn put(b: *app.Buf, f: Draw, html: []const u8) void {
    b.add("<div id=\"" ++ id ++ "\">{s}</div>", .{html});
    if (app.waiting) return;
    draw = f;
    page +%= 1;
    remember(html);
}

/// The page the tick is for (main.zig gives it back to tick).
pub fn current() u32 {
    return page;
}

fn remember(html: []const u8) void {
    app.gpa.free(shown);
    shown = app.gpa.dupe(u8, html) catch &.{};
    asked = app.now();
}

/// Whether the page on the screen has a live part due a fresh look.
pub fn due() bool {
    return draw != null and app.now() - asked >= 5 and dom.exists(id);
}

/// Draws the part again; replaces it when it changed.
pub fn tick(for_page: u32) void {
    if (for_page != page) return;
    const f = draw orelse return;
    const html = f() orelse return;
    if (app.waiting or for_page != page) return;
    asked = app.now();
    if (std.mem.eql(u8, html, shown)) return;
    dom.setHtml(id, html);
    remember(html);
}
