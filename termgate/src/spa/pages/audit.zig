//! Audit (#/audit): what users did in this panel (every changing call and
//! every sign-in, refused ones too), and the last sessions with their
//! logs.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");

const Action = struct { id: i64, at: i64, user: []const u8 = "", call: []const u8 = "", detail: []const u8 = "", ok: bool = true };

pub fn browse(query: []const u8) void {
    if (!state.can("audit", "browse")) return router.renderBadRequest();
    dom.setBodyId("");
    layout.renderDefault("audit");
    const key = app.queryValue(query, "key");
    content.search("/audit", key);
    const answer = fetch.post("audit/browse", .{ key, @max(1, app.queryInt(query, "pn")) }) orelse return;
    const page = fetch.fieldAs(content.Page(Action), answer, "data") orelse content.Page(Action){};
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Audit", "" }});
    content.commandStart(&b);
    content.commandEndNote(&b, "{d} entries{s}", .{ page.total, if (key.len > 0) " found" else "" });
    content.contentStart(&b);
    b.raw("<table><thead><tr><th>When</th><th>Who</th><th>What</th><th>About</th><th>Result</th></tr></thead><tbody>");
    if (page.rows.len == 0) b.raw("<tr><td colspan=\"5\">Empty list.</td></tr>");
    for (page.rows) |x| {
        b.add("<tr><td>{s}</td><td>", .{content.dateTime(x.at)});
        content.find(&b, if (x.user.len > 0) x.user else "-", key);
        b.raw("</td><td>");
        content.find(&b, x.call, key);
        b.raw("</td><td>");
        content.find(&b, x.detail, key);
        b.raw("</td><td>");
        if (x.ok) content.label(&b, "success", "done") else content.label(&b, "error", "denied");
        b.raw("</td></tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.ruler(&b, "/audit", key, page.page, page.pages);
    content.show(&b);
}
