//! Nodes (#/node): the gateways that run tgnode. The list with each node's
//! state, connection and system; New (a node key and the command for the
//! device); Info (#/node/display: connection, system with Refresh, its
//! sessions); New Key, Approve/Reject a registration, Disable/Enable,
//! Delete (asks first). A disabled or deleted node is disconnected.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const CargoList = @import("../lib/cargo.zig").CargoList;
const Form = @import("../form.zig").Form;

pub const Node = struct {
    id: i64,
    name: []const u8,
    description: []const u8 = "",
    state: []const u8 = "",
    hardware_key: ?[]const u8 = null,
    request_key: ?[]const u8 = null,
    status: ?[]const u8 = null,
    created: i64 = 0,
    last_seen: ?i64 = null,
    token_expires: ?i64 = null,
    online: bool = false,
};

/// What tgnode reports; every field may be missing
const Status = struct {
    version: []const u8 = "",
    hostname: []const u8 = "",
    os: []const u8 = "",
    kernel: []const u8 = "",
    arch: []const u8 = "",
    cpus: u32 = 0,
    uptime_s: u64 = 0,
    load: [3]f64 = .{ 0, 0, 0 },
    mem_total_kb: u64 = 0,
    mem_available_kb: u64 = 0,
    disk_total_bytes: u64 = 0,
    disk_free_bytes: u64 = 0,
};

pub const Session = struct {
    sid: []const u8,
    node: []const u8 = "",
    user_key: []const u8 = "",
    /// The user's name
    user: []const u8 = "",
    started: i64 = 0,
    ended: ?i64 = null,
    exit_status: ?i64 = null,
};

/// A page of the nodes, by a search word
fn nodes(key: []const u8, page: i64) ?content.Page(Node) {
    const answer = fetch.post("node/browse", .{ key, page }) orelse return null;
    return fetch.fieldAs(content.Page(Node), answer, "data");
}

const Summary = struct { total: i64 = 0, online: i64 = 0, pending: i64 = 0 };

fn nodeById(id: i64) ?Node {
    const answer = fetch.post("node/get", .{id}) orelse return null;
    return fetch.fieldAs(Node, answer, "data") orelse {
        router.renderNotFound();
        return null;
    };
}

fn statusOf(n: Node) ?Status {
    return std.json.parseFromSliceLeaky(Status, app.arena(), n.status orelse return null, .{ .ignore_unknown_fields = true }) catch null;
}

fn begin() void {
    dom.setBodyId("");
    layout.renderDefault("node");
}

fn stateLabel(b: *app.Buf, n: Node) void {
    if (std.mem.eql(u8, n.state, "approved")) {
        if (n.online) content.label(b, "success", "online") else content.label(b, "default", "offline");
    } else if (std.mem.eql(u8, n.state, "pending")) {
        content.label(b, "warning", "waiting for approval");
    } else if (std.mem.eql(u8, n.state, "waiting")) {
        content.label(b, "primary", "waiting for the device");
    } else content.label(b, "error", n.state);
}

fn gb(kb: u64) f64 {
    return @as(f64, @floatFromInt(kb)) / (1024 * 1024);
}

/// "just now", "5 min ago", "3 h ago", "2 days ago"
pub fn ago(t: ?i64) []const u8 {
    const v = t orelse return "never";
    const d = @max(app.now() - v, 0);
    if (d < 60) return "just now";
    if (d < 3600) return std.fmt.allocPrint(app.arena(), "{d} min ago", .{@divTrunc(d, 60)}) catch "";
    if (d < 86400) return std.fmt.allocPrint(app.arena(), "{d} h ago", .{@divTrunc(d, 3600)}) catch "";
    return std.fmt.allocPrint(app.arena(), "{d} days ago", .{@divTrunc(d, 86400)}) catch "";
}

// --- Browse -------------------------------------------------------------------

// The list's state in the address (lib/cargo.zig): search word, page
var cg: CargoList = .{};
var cg_ready = false;
const cg_names = [_][]const u8{ "key", "pn" };

fn cargo() *CargoList {
    if (!cg_ready) {
        cg.addStr("key", "");
        cg.addInt("pn", 1);
        cg.addInt("nodeId", 0);
        cg_ready = true;
    }
    return &cg;
}

/// The address of a node's page (#/node/display?nodeId=3).
fn nodeUrl(path: []const u8, id: i64) []const u8 {
    const c = cargo();
    c.setInt("nodeId", id);
    return c.makeUrl(path, &.{"nodeId"});
}

/// The node of a page's address.
fn readNodeId(query: []const u8) i64 {
    const c = cargo();
    c.read(query);
    return c.int("nodeId");
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
    if (!state.can("node", "browse")) return router.renderBadRequest();
    begin();
    const c = cargo();
    if (query.len > 0) c.read(query);
    state.setExternalUrl(c.makeUrl("/node", &cg_names));
    const key = c.str("key");
    content.search("nodeSearch", key);
    // Fresh system info from the online nodes, for the next look
    _ = fetch.postRaw("node/status_all", "[]");
    const page = nodes(key, @max(1, c.int("pn"))) orelse return;
    const list = page.rows;
    const sum = if (fetch.postRaw("node/summary", "[]")) |s| fetch.fieldAs(Summary, s, "data") orelse Summary{} else Summary{};
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Nodes", "" }});
    if (state.can("node", "insert")) {
        content.commandStart(&b);
        b.raw("<a href=\"#/node/insert\" class=\"button button-default button-sm\">New</a>");
        content.commandEnd(&b);
    }
    content.contentStart(&b);
    b.raw("<table>");
    content.caption(&b, "{d} nodes · {d} online · {d} waiting for approval{s}", .{ sum.total, sum.online, sum.pending, if (key.len > 0) std.fmt.allocPrint(app.arena(), " · {d} found", .{page.total}) catch "" else "" });
    b.raw("<thead><tr><th>Name</th><th class=\"center\">State</th><th>Last seen</th><th>System</th><th class=\"right\">Command</th></tr></thead><tbody>");
    if (list.len == 0) b.raw("<tr><td colspan=\"5\">Empty list.</td></tr>");
    for (list) |n| {
        b.add("<tr><td><a href=\"{s}\">", .{nodeUrl("#/node/display", n.id)});
        content.find(&b, n.name, key);
        b.raw("</a>");
        if (n.description.len > 0) {
            b.raw("<br><small>");
            content.find(&b, n.description, key);
            b.raw("</small>");
        }
        b.raw("</td><td class=\"center\">");
        stateLabel(&b, n);
        b.add("</td><td>{s}</td><td>", .{if (std.mem.eql(u8, n.state, "approved")) ago(n.last_seen) else "-"});
        if (statusOf(n)) |st| {
            b.add("{f} · {f} {f} · {d} CPUs<br><small>Memory {d:.1} / {d:.1} GB · Disk {d:.0} GB free · tgnode {f}</small>", .{
                app.esc(st.hostname),                                         app.esc(st.os),                    app.esc(st.arch), st.cpus,
                gb(st.mem_total_kb -| st.mem_available_kb),                   gb(st.mem_total_kb),               @as(f64, @floatFromInt(st.disk_free_bytes)) / 1e9,
                app.esc(st.version),
            });
        } else b.raw("-");
        b.raw("</td><td class=\"right\"><div class=\"button-group-fixed\">");
        commands(&b, n, "xs");
        b.raw("</div></td></tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.ruler(&b, page.pages, page.page, "nodeGoPage");
    content.show(&b);
}

/// The buttons for a node, by its state and the user's rights.
/// The pages of a node; the button of the one shown is selected.
const Tab = enum { none, info, new_key, delete };

fn commands(b: *app.Buf, n: Node, size: []const u8) void {
    toolbar(b, n, size, .none);
}

fn toolbar(b: *app.Buf, n: Node, size: []const u8, tab: Tab) void {
    const sel = struct {
        fn f(t: Tab, want: Tab) []const u8 {
            return if (t == want) " selected" else "";
        }
    }.f;
    b.add("<a href=\"{s}\" class=\"button button-default button-{s}{s}\">Info</a>", .{ nodeUrl("#/node/display", n.id), size, sel(tab, .info) });
    const is = struct {
        fn f(x: Node, s: []const u8) bool {
            return std.mem.eql(u8, x.state, s);
        }
    }.f;
    if (state.can("node", "update") and is(n, "pending")) {
        b.add("<button type=\"button\" data-action=\"nodeApprove\" data-id=\"{d}\" class=\"button button-primary button-{s}\">Approve</button>", .{ n.id, size });
        b.add("<button type=\"button\" data-action=\"nodeReject\" data-id=\"{d}\" class=\"button button-default button-{s}\">Reject</button>", .{ n.id, size });
    }
    if (state.can("node", "insert") and (is(n, "waiting") or is(n, "pending")))
        b.add("<a href=\"{s}\" class=\"button button-default button-{s}{s}\">New Key</a>", .{ nodeUrl("#/node/new_key", n.id), size, sel(tab, .new_key) });
    if (state.can("node", "update") and (is(n, "approved") or is(n, "disabled"))) {
        const off = is(n, "disabled");
        b.add("<button type=\"button\" data-action=\"nodeSetDisabled\" data-id=\"{d}\" data-off=\"{s}\" data-name=\"{f}\" class=\"button button-{s} button-{s}\">{s}</button>", .{ n.id, if (off) "0" else "1", app.esc(n.name), if (off) "default" else "warning", size, if (off) "Enable" else "Disable" });
    }
    if (state.can("node", "delete")) b.add("<a href=\"{s}\" class=\"button button-error button-{s}{s}\">Delete</a>", .{ nodeUrl("#/node/delete", n.id), size, sel(tab, .delete) });
}

/// A node's page: the path back (Nodes, the node's Info) and its toolbar.
fn recordHeader(b: *app.Buf, n: Node, tab: Tab) void {
    const info = nodeUrl("#/node/display", n.id);
    switch (tab) {
        .info, .none => content.header(b, &.{ .{ "Nodes", "#/node" }, .{ n.name, "" } }),
        .new_key => content.header(b, &.{ .{ "Nodes", "#/node" }, .{ n.name, info }, .{ "New Key", "" } }),
        .delete => content.header(b, &.{ .{ "Nodes", "#/node" }, .{ n.name, info }, .{ "Delete", "" } }),
    }
    content.commandStart(b);
    toolbar(b, n, "sm", tab);
    if (tab == .info and n.online) b.add("<button type=\"button\" data-action=\"nodeRefresh\" data-name=\"{f}\" class=\"button button-default button-sm\"><i class=\"fas fa-rotate fa-fw\"></i> Refresh</button>", .{app.esc(n.name)});
    content.commandEnd(b);
}

// --- Insert and the node key ------------------------------------------------------

pub fn insert(_: []const u8) void {
    if (!state.can("node", "insert")) return router.renderBadRequest();
    begin();
    renderInsert("", "");
}

fn renderInsert(name: []const u8, description: []const u8) void {
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Nodes", "#/node" }, .{ "New Record", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "node-name-input", "Name:", name, .{ .required = true, .max = 63, .help = "Lowercase letters, digits and _, starting with a letter: ist_kadikoy_gw01" });
    content.field(&b, "node-desc-input", "Description:", description, .{ .max = 255, .help = "Where it is, what it does (optional)." });
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"nodeInsert\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/node\" class=\"button button-default button-sm\">Cancel</a></div>");
    b.raw("<span class=\"help-block\">termgate makes a node key; it is used once, on the device, within an hour.</span></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn submitInsert(f: Form) void {
    const name = f.trimmed("node-name-input");
    const description = f.trimmed("node-desc-input");
    const answer = fetch.post("node/insert", .{ .name = name, .description = description }) orelse return;
    if (fetch.refused()) return renderInsert(name, description);
    const key = fetch.fieldAs(Key, answer, "data") orelse return;
    const n = nodeById(key.id) orelse return;
    showKey(n, key);
}

/// A node's New Key page: a new node key replaces the one before.
pub fn newKeyPage(query: []const u8) void {
    if (!state.can("node", "insert")) return router.renderBadRequest();
    begin();
    const n = nodeById(readNodeId(query)) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, n, .new_key);
    content.contentStart(&b);
    b.raw("<p>Make a new node key? It replaces the one before; it is used once, on the device, within an hour.</p>");
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"nodeNewKey\" data-id=\"{d}\" class=\"button button-primary button-sm\">Make new key</button>", .{n.id});
    content.commandEnd(&b);
    content.show(&b);
}

pub fn newKey(f: Form) void {
    const id = f.int("id");
    const n = nodeById(id) orelse return;
    const answer = fetch.post("node/new_key", .{ .id = id }) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
        return router.go(dom.hash());
    }
    begin();
    showKey(n, fetch.fieldAs(Key, answer, "data") orelse return);
}

/// The node key, once, with the command for the device.
const Key = struct { id: i64, code: []const u8 };

fn showKey(n: Node, key: Key) void {
    const command = std.fmt.allocPrint(app.arena(), "tgnode --node-key {s}", .{key.code}) catch return;
    var b: app.Buf = .{};
    recordHeader(&b, n, .new_key);
    content.contentStart(&b);
    b.raw("<p>Run this once on the device, within an hour. The device then asks to be approved here.</p>");
    b.add("<pre class=\"wrap\">{f}</pre>", .{app.esc(command)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"copy\" data-text=\"{f}\" class=\"button button-default button-sm\"><i class=\"fa fa-copy\"></i> Copy</button>", .{app.esc(command)});
    b.add("<a href=\"{s}\" class=\"button button-default button-sm\">Done</a>", .{nodeUrl("#/node/display", n.id)});
    content.commandEnd(&b);
    content.show(&b);
}

// --- State changes ------------------------------------------------------------------

pub fn approve(f: Form) void {
    afterChange(fetch.post("node/approve", .{f.int("id")}), "The node has been approved.");
}

pub fn reject(f: Form) void {
    afterChange(fetch.post("node/reject", .{f.int("id")}), "The registration has been rejected.");
}

pub fn setDisabled(f: Form) void {
    const off = std.mem.eql(u8, f.str("off"), "1");
    const answer = fetch.post("node/set_disabled", .{ f.int("id"), off });
    // A disabled node is disconnected at once
    if (answer != null and off and !fetch.refused()) _ = fetch.post("node/kick", .{f.str("name")});
    afterChange(answer, if (off) "The node has been disabled and disconnected." else "The node has been enabled.");
}

fn afterChange(answer: ?std.json.Value, done: []const u8) void {
    if (answer == null) return;
    if (fetch.refused()) state.keepMessages() else state.say("success", done);
    // Back to where the button was
    router.go(dom.hash());
}

// --- Display ------------------------------------------------------------------------

pub fn display(query: []const u8) void {
    if (!state.can("node", "browse")) return router.renderBadRequest();
    begin();
    const id = readNodeId(query);
    const n = nodeById(id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, n, .info);
    content.contentStart(&b);
    b.raw("<table><tbody>");
    b.add("<tr><th class=\"fixed-middle\">Name:</th><td>{f}</td></tr><tr><th>Description:</th><td>{f}</td></tr><tr><th>State:</th><td>", .{ app.esc(n.name), app.esc(n.description) });
    stateLabel(&b, n);
    b.add("</td></tr><tr><th>Last seen:</th><td>{s}</td></tr><tr><th>Added:</th><td>{s}</td></tr>", .{ ago(n.last_seen), content.dateTime(n.created) });
    if (n.hardware_key) |k| b.add("<tr><th>Hardware key:</th><td><small>{f}</small></td></tr>", .{app.esc(k)});
    if (n.request_key) |k| b.add("<tr><th>Asks to register with:</th><td><small>{f}</small></td></tr>", .{app.esc(k)});
    if (std.mem.eql(u8, n.state, "waiting")) if (n.token_expires) |t| b.add("<tr><th>Node key valid until:</th><td>{s} UTC</td></tr>", .{content.dateTime(t)});
    if (statusOf(n)) |st| {
        b.add("<tr><th>Hostname:</th><td>{f}</td></tr><tr><th>System:</th><td>{f}, kernel {f}, {f}, {d} CPUs</td></tr>", .{ app.esc(st.hostname), app.esc(st.os), app.esc(st.kernel), app.esc(st.arch), st.cpus });
        const used = st.mem_total_kb -| st.mem_available_kb;
        b.add("<tr><th>Memory:</th><td>{d:.1} of {d:.1} GB used</td></tr>", .{ gb(used), gb(st.mem_total_kb) });
        b.add("<tr><th>Disk:</th><td>{d:.0} GB free of {d:.0} GB</td></tr>", .{ @as(f64, @floatFromInt(st.disk_free_bytes)) / 1e9, @as(f64, @floatFromInt(st.disk_total_bytes)) / 1e9 });
        b.add("<tr><th>Load:</th><td>{d:.2} {d:.2} {d:.2}, up {d} h</td></tr><tr><th>tgnode:</th><td>{f}</td></tr>", .{ st.load[0], st.load[1], st.load[2], st.uptime_s / 3600, app.esc(st.version) });
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);

    // Its sessions: the open ones first
    if (state.can("session", "browse")) {
        const answer = fetch.post("node/sessions", .{ n.name, 20 });
        const sessions = if (answer) |ans| fetch.fieldAs([]const Session, ans, "data") orelse &.{} else &.{};
        b.raw("<div class=\"row row-header\"><div class=\"col\"><div class=\"page-title\"><h3>Sessions</h3></div></div></div>");
        content.contentStart(&b);
        b.raw("<table><thead><tr><th>Who</th><th>Started</th><th>Ended</th></tr></thead><tbody>");
        if (sessions.len == 0) b.raw("<tr><td colspan=\"3\">No sessions yet.</td></tr>");
        for (sessions) |s| b.add("<tr><td>{f}</td><td>{s}</td><td>{s}</td></tr>", .{ app.esc(s.user), content.dateTime(s.started), if (s.ended) |e| content.dateTime(e) else "open" });
        b.raw("</tbody></table>");
        content.contentEnd(&b);
    }
    content.show(&b);
}

pub fn refresh(f: Form) void {
    _ = fetch.post("node/status", .{f.str("name")}) orelse return;
    state.say("info", "The node was asked for its system info; it shows here in a moment.");
    router.go(dom.hash());
}

// --- Delete -------------------------------------------------------------------------

var delete_id: i64 = 0;

pub fn delete(query: []const u8) void {
    if (!state.can("node", "delete")) return router.renderBadRequest();
    begin();
    delete_id = readNodeId(query);
    const n = nodeById(delete_id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, n, .delete);
    content.contentStart(&b);
    b.raw("<p>Delete this node? It is disconnected at once and has to register again to come back.</p><table><tbody>");
    b.add("<tr><th class=\"fixed-middle\">Name:</th><td>{f}</td></tr><tr><th>Description:</th><td>{f}</td></tr><tr><th>State:</th><td>", .{ app.esc(n.name), app.esc(n.description) });
    stateLabel(&b, n);
    b.raw("</td></tr></tbody></table>");
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"nodeDelete\" data-name=\"{f}\" class=\"button button-error button-sm\">Yes</button><a href=\"{s}\" class=\"button button-default button-sm\">Cancel</a>", .{ app.esc(n.name), nodeUrl("#/node/display", n.id) });
    content.commandEnd(&b);
    content.show(&b);
}

pub fn submitDelete(f: Form) void {
    _ = fetch.post("node/delete", .{delete_id}) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
    } else {
        _ = fetch.post("node/kick", .{f.str("name")});
        state.say("success", "Record has been deleted.");
    }
    router.go("/node");
}
