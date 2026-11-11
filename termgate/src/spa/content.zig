//! Pieces every page uses, as our earlier project's content packages: the page
//! title with its path, the command row, a label for a status.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");
const state = @import("state.zig");

/// The page's content is `b`: set, with the messages above it and the
/// focus in its first field.
pub fn show(b: *const app.Buf) void {
    dom.setHtml("main-content", b.str());
    _ = state.renderMessages();
    dom.focusFirstField();
}

/// A page of a list as the server answers it (db.Page)
pub fn Page(comptime T: type) type {
    return struct { rows: []const T = &.{}, total: i64 = 0, page: i64 = 1, pages: i64 = 1 };
}

/// The search box in the header (our earlier project's content.Search): its word is
/// `key`; the button is `action`. Pages without a search leave it empty
/// (layout.renderDefault clears it).
pub fn search(action: []const u8, key: []const u8) void {
    var b: app.Buf = .{};
    b.add("<form class=\"form-inline form-search\"><input type=\"text\" id=\"key\" placeholder=\"search word...\" value=\"{f}\">", .{app.esc(key)});
    b.add("<button type=\"button\" data-action=\"{s}\" class=\"button button-primary button-sm\">Search</button></form>", .{action});
    dom.setHtml("search", b.str());
}

/// The page numbers under a list, in their row (content/ruler.zig).
pub fn ruler(b: *app.Buf, total_pages: i64, page_no: i64, action: []const u8) void {
    if (total_pages < 2) return;
    b.raw("<div class=\"row row-command\"><div class=\"col\">");
    @import("content/ruler.zig").render(b, total_pages, page_no, action);
    b.raw("</div></div>");
}

/// `text` with the search word marked (our earlier project's content.Find).
pub fn find(b: *app.Buf, text: []const u8, key: []const u8) void {
    if (key.len == 0) return b.add("{f}", .{app.esc(text)});
    var rest = text;
    while (std.ascii.findIgnoreCase(rest, key)) |i| {
        b.add("{f}<span class=\"find\">{f}</span>", .{ app.esc(rest[0..i]), app.esc(rest[i .. i + key.len]) });
        rest = rest[i + key.len ..];
    }
    b.add("{f}", .{app.esc(rest)});
}

/// The page title in its row (content/page_title.zig): its parts joined
/// by an arrow, the earlier ones links. Each part: (text, link or "").
pub fn header(b: *app.Buf, parts: []const [2][]const u8) void {
    var pt: @import("content/page_title.zig").PageTitle = .{};
    for (parts) |p| {
        if (p[1].len > 0) _ = pt.add("<a href=\"{s}\">{f}</a>", .{ p[1], app.esc(p[0]) }) else _ = pt.add("{f}", .{app.esc(p[0])});
    }
    b.raw("<div class=\"row row-header\"><div class=\"col\">");
    pt.render(b);
    b.raw("</div></div>");
}

/// The row of buttons above or below a page's content.
pub fn commandStart(b: *app.Buf) void {
    b.raw("<div class=\"row row-command\"><div class=\"col\"><div class=\"button-group-fixed\">");
}

pub fn commandEnd(b: *app.Buf) void {
    b.raw("</div></div></div>");
}

/// The end of the command row with an info column on its right (counts,
/// a state): plain text, away from the buttons.
pub fn commandEndNote(b: *app.Buf, comptime fmt: []const u8, args: anytype) void {
    b.raw("</div></div><div class=\"col col-info\">");
    b.add(fmt, args);
    b.raw("</div></div>");
}

pub fn contentStart(b: *app.Buf) void {
    b.raw("<div class=\"row row-content\"><div class=\"col\">");
}

pub fn contentEnd(b: *app.Buf) void {
    b.raw("</div></div>");
}

/// A colored label (our earlier project's statusToLabel): kind is primary,
/// success, warning, error or default.
pub fn label(b: *app.Buf, kind: []const u8, text: []const u8) void {
    b.add("<span class=\"label label-{s}\">{f}</span>", .{ kind, app.esc(text) });
}

/// A form field: label, input; `help` under it.
pub fn field(b: *app.Buf, id: []const u8, name: []const u8, value: []const u8, opts: struct { required: bool = false, max: usize = 100, help: []const u8 = "", password: bool = false }) void {
    b.add("<div class=\"form-group\"><label{s}>{f}</label>", .{ if (opts.required) " class=\"required\"" else "", app.esc(name) });
    b.add("<input type=\"{s}\" id=\"{s}\" class=\"form-control\" maxlength=\"{d}\" value=\"{f}\">", .{
        if (opts.password) "password" else "text", id, opts.max, app.esc(value),
    });
    if (opts.help.len > 0) b.add("<span class=\"help-block\">{f}</span>", .{app.esc(opts.help)});
    b.raw("</div>");
}

pub fn checkbox(b: *app.Buf, id: []const u8, name: []const u8, checked: bool) void {
    b.add("<div class=\"form-group\"><label><input type=\"checkbox\" id=\"{s}\"{s}> {f}</label></div>", .{ id, if (checked) " checked" else "", app.esc(name) });
}

/// A date and time (UTC) from unix seconds.
pub fn dateTime(t: i64) []const u8 {
    if (t <= 0) return "-";
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(t) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.allocPrint(app.arena(), "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(),
    }) catch "";
}
