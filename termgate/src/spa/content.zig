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
/// `key`; the button searches the list at `path` (#/node...). Pages
/// without a search leave it empty (layout.renderDefault clears it).
pub fn search(path: []const u8, key: []const u8) void {
    var b: app.Buf = .{};
    b.add("<form class=\"form-inline form-search\"><input type=\"text\" id=\"key\" placeholder=\"search word...\" value=\"{f}\">", .{app.esc(key)});
    b.add("<button type=\"button\" data-action=\"search\" data-path=\"{f}\" class=\"button button-primary button-sm\">Search</button></form>", .{app.esc(path)});
    dom.setHtml("search", b.str());
}

/// The page numbers under a list (our earlier project's ruler): First, <<, a few
/// numbers around the current one, >>, Last. Each goes to `path` with the
/// search word and its page number.
pub fn ruler(b: *app.Buf, path: []const u8, key: []const u8, page: i64, pages: i64) void {
    if (pages < 2) return;
    const around = 3;
    var start: i64 = @max(1, page - around);
    var end = start + around * 2;
    if (end > pages) {
        start = @max(1, start - (end - pages));
        end = pages;
    }
    b.raw("<div class=\"row row-command\"><div class=\"col\"><div class=\"pagination\"><ul class=\"clear\">");
    const item = struct {
        fn add(buf: *app.Buf, p: []const u8, k: []const u8, pn: i64, text: []const u8, active: bool) void {
            // `p` may have a query of its own (a list's filters)
            const sep: []const u8 = if (std.mem.indexOfScalar(u8, p, '?') != null) "&" else "?";
            buf.add("<li{s}><a href=\"#{s}{s}key={s}&pn={d}\">{s}</a></li>", .{ if (active) " class=\"active\"" else "", p, sep, app.urlEncode(k), pn, text });
        }
    }.add;
    if (start > 1) {
        item(b, path, key, 1, "First", false);
        item(b, path, key, @max(1, page - around), "&lt;&lt;", false);
    }
    var i = start;
    while (i <= end) : (i += 1) item(b, path, key, i, std.fmt.allocPrint(app.arena(), "{d}", .{i}) catch "", i == page);
    if (end < pages) {
        item(b, path, key, @min(pages, page + around), "&gt;&gt;", false);
        item(b, path, key, pages, "Last", false);
    }
    b.raw("</ul></div></div></div>");
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

/// The page title: its parts joined by an arrow, the earlier ones links
/// (our earlier project's page_title). Each part: (text, link or "").
pub fn header(b: *app.Buf, parts: []const [2][]const u8) void {
    b.raw("<div class=\"row row-header\"><div class=\"col\"><div class=\"page-title primary\"><h3>");
    for (parts, 0..) |p, i| {
        if (i > 0) b.raw(" <i class=\"fa fa-fw fa-angle-right\"></i> ");
        if (p[1].len > 0) b.add("<a href=\"{s}\">{f}</a>", .{ p[1], app.esc(p[0]) }) else b.add("{f}", .{app.esc(p[0])});
    }
    b.raw("</h3></div></div></div>");
}

/// The row of buttons above or below a page's content.
pub fn commandStart(b: *app.Buf) void {
    b.raw("<div class=\"row row-command\"><div class=\"col\"><div class=\"button-group-fixed\">");
}

pub fn commandEnd(b: *app.Buf) void {
    b.raw("</div></div></div>");
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
