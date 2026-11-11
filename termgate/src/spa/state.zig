//! Who is signed in and what it may do, and the messages of the last
//! answer: as our earlier project's state package. Filled from /api/init and from
//! signing in.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");

pub const User = struct {
    name: []const u8 = "",
    superuser: bool = false,
    /// "page:function", from the user's roles
    rights: []const []const u8 = &.{},
    /// While acting as another user: the signed-in user's own name
    real: ?[]const u8 = null,
    /// May the signed-in user itself act as another, or stop
    can_select: bool = false,
    can_unselect: bool = false,
};

/// Null: nobody is signed in
var user_arena: std.heap.ArenaAllocator = .init(app.gpa);
pub var user: ?User = null;
/// Whether signing in asks for the authenticator code
pub var second_step = true;
/// The settings the panel uses (our earlier project's state.Config): page numbers
/// on each side of the current one under a list
pub var ruler_len: i64 = 4;

/// The address of the list shown, with its state (our earlier project's
/// ExternalUrl): the page title's link button copies it. Cleared at each
/// page (router.zig).
var external_buf: [512]u8 = undefined;
pub var external_url: []const u8 = "";

pub fn setExternalUrl(url: []const u8) void {
    if (app.waiting) return;
    const n = @min(url.len, external_buf.len);
    @memcpy(external_buf[0..n], url[0..n]);
    external_url = external_buf[0..n];
}

pub fn signedIn() bool {
    return user != null;
}

/// May the user do this? The server checks it again on every call; here
/// it decides what the page shows (our earlier project's IsRight).
pub fn can(page: []const u8, func: []const u8) bool {
    const u = user orelse return false;
    if (u.superuser) return true;
    for (u.rights) |r| {
        if (r.len == page.len + 1 + func.len and std.mem.startsWith(u8, r, page) and r[page.len] == ':' and std.mem.endsWith(u8, r, func)) return true;
    }
    return false;
}

/// Keeps the user from an answer (init, signing in); null signs out.
pub fn setUser(v: ?std.json.Value) void {
    if (app.waiting) return;
    _ = user_arena.reset(.retain_capacity);
    const val = v orelse {
        user = null;
        return;
    };
    if (val != .object) {
        user = null;
        return;
    }
    const copy = std.json.parseFromValue(User, user_arena.allocator(), val, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch {
        user = null;
        return;
    };
    user = copy.value;
}

// ---------------------------------------------------------------------------
// Messages (our earlier project's state.Msg): those of the last answer, shown in
// the message area above the page

pub const Message = struct {
    name: []const u8 = "",
    type: []const u8 = "info",
    lines: []const []const u8 = &.{},
    /// Goes away by itself after 5 seconds (our earlier project's; false: stays)
    @"auto-clear": bool = true,
    title: []const u8 = "",
};

/// The messages of the last answer (replaced by the next call)
pub var messages: []const Message = &.{};

/// Messages kept for the next page that is shown (after a call that goes
/// on to another page, which makes calls of its own); shown once
var pending_arena: std.heap.ArenaAllocator = .init(app.gpa);
var pending: std.ArrayList(Message) = .empty;

/// Takes the messages of an answer.
pub fn takeMessages(answer: std.json.Value) void {
    messages = &.{};
    if (answer != .object) return;
    const list = answer.object.get("messages") orelse return;
    messages = std.json.parseFromValueLeaky([]const Message, app.arena(), list, .{ .ignore_unknown_fields = true }) catch &.{};
}

/// A message of the page itself, shown with the next page drawn.
pub fn say(kind: []const u8, text: []const u8) void {
    if (app.waiting) return;
    const a = pending_arena.allocator();
    const lines = a.alloc([]const u8, 1) catch return;
    lines[0] = a.dupe(u8, text) catch return;
    pending.append(a, .{ .type = kind, .lines = lines }) catch {};
}

/// The last answer's messages are shown with the next page drawn too.
pub fn keepMessages() void {
    if (app.waiting) return;
    const a = pending_arena.allocator();
    for (messages) |m| {
        const lines = a.alloc([]const u8, m.lines.len) catch return;
        for (m.lines, lines) |l, *d| d.* = a.dupe(u8, l) catch "";
        pending.append(a, .{ .name = a.dupe(u8, m.name) catch "", .type = a.dupe(u8, m.type) catch "info", .lines = lines, .@"auto-clear" = m.@"auto-clear", .title = a.dupe(u8, m.title) catch "" }) catch {};
    }
    messages = &.{};
}

pub fn has(name: []const u8) bool {
    for (messages) |m| if (std.mem.eql(u8, m.name, name)) return true;
    return false;
}

// A job (fetch.zig) may run more than once before it is done: the
// messages of the page it says in a run that waits are said again in the
// next run, and those it showed are dropped only when it is done.
var job_mark: usize = 0;
var shown = false;

pub fn jobStarted() void {
    job_mark = pending.items.len;
}

pub fn runStarted() void {
    pending.shrinkRetainingCapacity(job_mark);
    shown = false;
}

pub fn jobDone() void {
    if (!shown) return;
    pending = .empty;
    _ = pending_arena.reset(.retain_capacity);
    job_mark = 0;
}

/// Shows the messages in the message area (our earlier project's Msg.Render);
/// false if there were none. Each can be closed; those that clear by
/// themselves go after 5 seconds.
pub fn renderMessages() bool {
    if (app.waiting) return false;
    shown = true;
    if (messages.len == 0 and pending.items.len == 0) {
        dom.setHtml("site-message", "");
        return false;
    }
    var b: app.Buf = .{};
    b.raw("<div class=\"row\"><div class=\"col\">");
    for ([_][]const Message{ pending.items, messages }) |list| for (list) |m| {
        const class = if (std.mem.eql(u8, m.type, "error")) "alert-error" else if (std.mem.eql(u8, m.type, "warning")) "alert-warning" else if (std.mem.eql(u8, m.type, "success")) "alert-success" else "alert-info";
        const title = if (m.title.len > 0) m.title else if (std.mem.eql(u8, m.type, "error")) "Error:" else if (std.mem.eql(u8, m.type, "warning")) "Warning:" else if (std.mem.eql(u8, m.type, "success")) "Success:" else "Info:";
        b.add("<div class=\"alert {s}{s}\"><i class=\"fa fa-times button-close\"></i><p><strong>{f}</strong></p>", .{ class, if (m.@"auto-clear") " auto-clear" else "", app.esc(title) });
        for (m.lines) |l| b.add("<p>{f}</p>", .{app.esc(l)});
        b.raw("</div>");
    };
    b.raw("</div></div>");
    dom.setHtml("site-message", b.str());
    dom.autoClearMessages();
    return true;
}
