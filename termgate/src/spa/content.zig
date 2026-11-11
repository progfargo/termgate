//! Pieces every page uses, as our earlier project's content packages: the page
//! title with its path, the command row, a label for a status.

const std = @import("std");
const app = @import("app.zig");

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
pub fn field(b: *app.Buf, id: []const u8, name: []const u8, value: []const u8, opts: struct { required: bool = false, max: usize = 100, help: []const u8 = "", password: bool = false, autofocus: bool = false }) void {
    b.add("<div class=\"form-group\"><label{s}>{f}</label>", .{ if (opts.required) " class=\"required\"" else "", app.esc(name) });
    b.add("<input type=\"{s}\" id=\"{s}\" class=\"form-control\" maxlength=\"{d}\" value=\"{f}\"{s}>", .{
        if (opts.password) "password" else "text", id, opts.max, app.esc(value), if (opts.autofocus) " autofocus" else "",
    });
    if (opts.help.len > 0) b.add("<small class=\"form-help\">{f}</small>", .{app.esc(opts.help)});
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
