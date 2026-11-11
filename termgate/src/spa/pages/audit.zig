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
const Form = @import("../form.zig").Form;
const CargoList = @import("../lib/cargo.zig").CargoList;

const Action = struct { id: i64, at: i64, user: []const u8 = "", call: []const u8 = "", detail: []const u8 = "", ok: bool = true };


// The list's state in the address (lib/cargo.zig): search word, page
var cg: CargoList = .{};
var cg_ready = false;
const cg_names = [_][]const u8{ "key", "pn" };

fn cargo() *CargoList {
    if (!cg_ready) {
        cg.addStr("key", "");
        cg.addInt("pn", 1);
        cg_ready = true;
    }
    return &cg;
}

/// The header's Search: the list with the word, from its first page.
pub fn submitSearch(f: Form) void {
    const c = cargo();
    c.setStr("key", f.trimmed("key"));
    c.setInt("pn", 1);
    router.go(c.makeUrl("/audit", &cg_names));
}

/// A page number under the list.
pub fn goPage(f: Form) void {
    const c = cargo();
    c.readMap(f);
    router.go(c.makeUrl("/audit", &cg_names));
}

pub fn browse(query: []const u8) void {
    if (!state.can("audit", "browse")) return router.renderBadRequest();
    dom.setBodyId("");
    layout.renderDefault("audit");
    const c = cargo();
    c.read(query);
    const key = c.str("key");
    content.search("auditSearch", key);
    const answer = fetch.post("audit/browse", .{ key, @max(1, c.int("pn")) }) orelse return;
    const page = fetch.fieldAs(content.Page(Action), answer, "data") orelse content.Page(Action){};
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Audit", "" }});
    content.contentStart(&b);
    b.raw("<table>");
    content.caption(&b, "{d} entries{s}", .{ page.total, if (key.len > 0) " found" else "" });
    b.raw("<thead><tr><th>When</th><th>Who</th><th>What</th><th>About</th><th class=\"center\">Result</th></tr></thead><tbody>");
    if (page.rows.len == 0) b.raw("<tr><td colspan=\"5\">Empty list.</td></tr>");
    for (page.rows) |x| {
        b.add("<tr><td>{s}</td><td>", .{content.dateTime(x.at)});
        content.find(&b, if (x.user.len > 0) x.user else "-", key);
        b.raw("</td><td>");
        content.find(&b, x.call, key);
        b.raw("</td><td>");
        content.find(&b, x.detail, key);
        b.raw("</td><td class=\"center\">");
        if (x.ok) content.label(&b, "success", "done") else content.label(&b, "error", "denied");
        b.raw("</td></tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.ruler(&b, page.pages, page.page, "auditGoPage");
    content.show(&b);
}
