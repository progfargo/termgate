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
const session = @import("session.zig");
const node_page = @import("node.zig");

const Action = struct { id: i64, at: i64, user: []const u8 = "", call: []const u8 = "", detail: []const u8 = "", ok: bool = true };

pub fn browse(_: []const u8) void {
    if (!state.can("audit", "browse")) return router.renderBadRequest();
    dom.setBodyId("");
    layout.renderDefault("audit");
    const answer = fetch.postRaw("audit/browse", "[200]") orelse return;
    const actions = fetch.fieldAs([]const Action, answer, "data") orelse &.{};
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Audit", "" }});
    content.contentStart(&b);
    b.raw("<table><thead><tr><th>When</th><th>Who</th><th>What</th><th>About</th><th>Result</th></tr></thead><tbody>");
    if (actions.len == 0) b.raw("<tr><td colspan=\"5\">Empty list.</td></tr>");
    for (actions) |x| {
        b.add("<tr><td>{s}</td><td>{f}</td><td>{f}</td><td>{f}</td><td>", .{ content.dateTime(x.at), app.esc(if (x.user.len > 0) x.user else "-"), app.esc(x.call), app.esc(x.detail) });
        if (x.ok) content.label(&b, "success", "done") else content.label(&b, "error", "denied");
        b.raw("</td></tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    if (state.can("session", "browse")) {
        const s = fetch.postRaw("session/recent", "[50]");
        const sessions = if (s) |v| fetch.fieldAs([]const node_page.Session, v, "data") orelse &.{} else &.{};
        b.raw("<div class=\"row row-header\"><div class=\"col\"><div class=\"page-title\"><h3>Sessions</h3></div></div></div>");
        content.contentStart(&b);
        session.table(&b, sessions, false);
        content.contentEnd(&b);
    }
    content.show(&b);
}
