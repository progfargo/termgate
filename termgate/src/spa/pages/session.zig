//! Sessions (#/session): every session, open and ended, searched and
//! paged; an open one can be watched and ended. A session's log (#/session/log: the commands typed
//! and their output). Watching a session live is #/session/watch
//! (watch.zig).

const std = @import("std");
const vt = @import("vt");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const CargoList = @import("../lib/cargo.zig").CargoList;
const node_page = @import("node.zig");
const Form = @import("../form.zig").Form;

const Session = node_page.Session;

fn begin(menu: []const u8) void {
    dom.setBodyId("");
    layout.renderDefault(menu);
}

fn list(path: []const u8, args: []const u8) []const Session {
    const answer = fetch.postRaw(path, args) orelse return &.{};
    return fetch.fieldAs([]const Session, answer, "data") orelse &.{};
}

/// The sessions, open and ended, the search word `key` marked in the node
/// and user names; an open one has Watch and End.
fn table(b: *app.Buf, sessions: []const Session, key: []const u8, open_count: usize, total: i64) void {
    const can_watch = state.can("session", "watch");
    const can_end = state.can("session", "end");
    const can_log = state.can("session", "log");
    b.raw("<table>");
    content.caption(b, "{d} sessions · {d} open", .{ total, open_count });
    b.raw("<thead><tr><th>Node name</th><th>User</th><th class=\"center\">Node</th><th class=\"center\">Session</th><th>Started</th><th>Ended</th><th class=\"right\">Command</th></tr></thead><tbody>");
    if (sessions.len == 0) b.raw("<tr><td colspan=\"7\">Empty list.</td></tr>");
    for (sessions) |s| {
        // Open now: termgate knows it (not the record)
        const open = s.open;
        b.raw("<tr><td>");
        content.find(b, s.node, key);
        b.raw("</td><td>");
        content.find(b, s.user, key);
        b.raw("</td><td class=\"center\">");
        if (s.node_online) content.label(b, "success", "online") else content.label(b, "default", "offline");
        b.raw("</td><td class=\"center\">");
        if (open) content.label(b, "success", "open") else content.label(b, "default", "ended");
        b.add("</td><td>{s}</td><td>{s}", .{ content.dateTime(s.started), if (s.ended) |e| content.dateTime(e) else "-" });
        if (s.exit_status) |x| b.add(" <small>(exit {d})</small>", .{x});
        b.raw("</td><td class=\"right\"><div class=\"button-group-fixed\">");
        if (open and can_watch) b.add("<a href=\"{f}\" class=\"button button-primary button-xs\">Watch</a>", .{app.esc(sessionUrl("#/session/watch", s, true))});
        if (can_log) b.add("<a href=\"{f}\" class=\"button button-default button-xs\">Log</a>", .{app.esc(sessionUrl("#/session/log", s, false))});
        if (open and can_end) b.add("<button type=\"button\" data-action=\"sessionEnd\" data-sid=\"{s}\" data-node=\"{f}\" data-key=\"{f}\" class=\"button button-error button-xs\">End</button>", .{ s.sid, app.esc(s.node), app.esc(s.user_key) });
        b.raw("</div></td></tr>");
    }
    b.raw("</tbody></table>");
}

// The list's state in the address (lib/cargo.zig): search word, page
var cg: CargoList = .{};
var cg_ready = false;
const cg_names = [_][]const u8{ "key", "pn" };

fn cargo() *CargoList {
    if (!cg_ready) {
        cg.addStr("key", "");
        cg.addInt("pn", 1);
        cg.addStr("sid", "");
        cg.addStr("node", "");
        cg.addStr("userKey", "");
        cg_ready = true;
    }
    return &cg;
}

/// The address of a session's page: its log, or watching it (with its
/// node and its user's key).
fn sessionUrl(path: []const u8, s: Session, watch: bool) []const u8 {
    const c = cargo();
    c.setStr("sid", s.sid);
    if (!watch) return c.makeUrl(path, &.{"sid"});
    c.setStr("node", s.node);
    c.setStr("userKey", s.user_key);
    return c.makeUrl(path, &.{ "sid", "node", "userKey" });
}

/// The header's Search: the list with the word, from its first page.
pub fn submitSearch(f: Form) void {
    const c = cargo();
    c.setStr("key", f.trimmed("key"));
    c.setInt("pn", 1);
    browse("");
}

/// A page number under the list.
pub fn goPage(f: Form) void {
    const c = cargo();
    c.readMap(f);
    browse("");
}

pub fn browse(query: []const u8) void {
    if (!state.can("session", "browse")) return router.renderBadRequest();
    begin("session");
    const c = cargo();
    if (query.len > 0) c.read(query);
    state.setExternalUrl(c.makeUrl("/session", &cg_names));
    const key = c.str("key");
    content.search("sessionSearch", key);
    const t = tableNow(key, c.int("pn"));
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Sessions", "" }});
    content.contentStart(&b);
    b.add("<div id=\"session-table\">{s}</div>", .{t.html});
    content.contentEnd(&b);
    content.ruler(&b, t.pages, t.page, "sessionGoPage");
    content.show(&b);
    if (!app.waiting) remember(t.html);
}

/// The table as termgate has it now: open sessions and the page of all.
fn tableNow(key: []const u8, pn: i64) struct { html: []const u8, pages: i64 = 1, page: i64 = 1 } {
    const open = list("session/browse", "[]");
    const recent = if (fetch.post("session/recent", .{ key, @max(1, pn) })) |ans| fetch.fieldAs(content.Page(Session), ans, "data") orelse content.Page(Session){} else content.Page(Session){};
    var b: app.Buf = .{};
    table(&b, recent.rows, key, open.len, recent.total);
    return .{ .html = b.str(), .pages = recent.pages, .page = recent.page };
}

// The table last shown, and when the list was last asked
var shown: []u8 = &.{};
var asked: i64 = 0;

fn remember(html: []const u8) void {
    app.gpa.free(shown);
    shown = app.gpa.dupe(u8, html) catch &.{};
    asked = app.now();
}

/// Whether the list on the screen is due a fresh look (every 5 seconds).
pub fn tickDue() bool {
    return app.now() - asked >= 5 and dom.exists("session-table");
}

/// The open/online state changes without F5: the table is asked again
/// and redrawn when it changed.
pub fn tick() void {
    const c = cargo();
    const t = tableNow(c.str("key"), c.int("pn"));
    if (app.waiting) return;
    asked = app.now();
    if (std.mem.eql(u8, t.html, shown)) return;
    dom.setHtml("session-table", t.html);
    remember(t.html);
}

pub fn end(f: Form) void {
    _ = fetch.post("session/end", .{ f.str("node"), f.str("key"), f.str("sid") }) orelse return;
    // On the watch page: the page stays, with the session's last screen;
    // the watch shows the end when the node reports it
    if (std.mem.startsWith(u8, dom.hash(), "/session/watch")) {
        if (!fetch.refused()) state.say("success", "The session has been ended.");
        _ = state.renderMessages();
        return;
    }
    if (fetch.refused()) state.keepMessages() else state.say("success", "The session has been ended.");
    router.go(dom.hash());
}

// --- Log ----------------------------------------------------------------------------

const Command = struct { seq: i64, at: i64, line: []const u8, output: []const u8, output_chars: i64 = 0, intact: bool = true };

fn unbase64(text: []const u8) []const u8 {
    const dec = std.base64.standard.Decoder;
    const out = app.arena().alloc(u8, dec.calcSizeForSlice(text) catch return "") catch return "";
    dec.decode(out, text) catch return "";
    return out;
}

/// Terminal bytes as the screen shows them (libghostty-vt): escape
/// sequences applied, not printed. The screen is tall enough that nothing
/// scrolls off; trailing blanks are dropped.
fn screenText(bytes: []const u8) []const u8 {
    if (bytes.len == 0) return "";
    const rows = @min(std.mem.count(u8, bytes, "\n") + 2, 5000);
    const screen = vt.Screen.create(app.gpa, std.Io.failing, 160, @intCast(rows)) catch return "";
    defer screen.destroy();
    screen.feed(bytes);
    const text = screen.text(app.arena()) catch return "";
    var out: app.Buf = .{};
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        out.raw(std.mem.trimEnd(u8, line, " "));
        out.raw("\n");
    }
    return std.mem.trimEnd(u8, out.str(), "\n");
}

/// A typed line as it looked: a DEL (Backspace) deletes the character
/// before the cursor.
fn typedText(raw: []const u8) []const u8 {
    const line = std.mem.trimEnd(u8, raw, "\r\n");
    var b: app.Buf = .{};
    for (line) |c| if (c == 0x7f) b.raw("\x08\x1b[P") else b.list.append(app.arena(), c) catch {};
    return screenText(b.str());
}

pub fn log(query: []const u8) void {
    if (!state.can("session", "log")) return router.renderBadRequest();
    begin("session");
    const cg_ = cargo();
    cg_.read(query);
    const sid = cg_.str("sid");
    const answer = fetch.post("session/log", .{sid}) orelse return;
    const cmds = fetch.fieldAs([]const Command, answer, "data") orelse &.{};
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Sessions", "#/session" }, .{ std.fmt.allocPrint(app.arena(), "Log: {s}", .{sid}) catch "Log", "" } });
    content.contentStart(&b);
    if (cmds.len == 0) b.raw("<p>Nothing was typed in this session.</p>");
    for (cmds) |c| {
        b.add("<div><p><small>{s}</small></p><pre><strong>{f}</strong>\n{f}</pre>", .{ content.dateTime(c.at), app.esc(typedText(unbase64(c.line))), app.esc(screenText(unbase64(c.output))) });
        if (c.output_chars > 0 and unbase64(c.output).len < c.output_chars) b.add("<p><small>{d} characters of output in all; the first are kept.</small></p>", .{c.output_chars});
        if (!c.intact) b.raw("<p><small>This entry could not be read (changed, or another key).</small></p>");
        b.raw("</div>");
    }
    content.contentEnd(&b);
    content.show(&b);
}
