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
    const a = pending_arena.allocator();
    const lines = a.alloc([]const u8, 1) catch return;
    lines[0] = a.dupe(u8, text) catch return;
    pending.append(a, .{ .type = kind, .lines = lines }) catch {};
}

/// The last answer's messages are shown with the next page drawn too.
pub fn keepMessages() void {
    const a = pending_arena.allocator();
    for (messages) |m| {
        const lines = a.alloc([]const u8, m.lines.len) catch return;
        for (m.lines, lines) |l, *d| d.* = a.dupe(u8, l) catch "";
        pending.append(a, .{ .name = a.dupe(u8, m.name) catch "", .type = a.dupe(u8, m.type) catch "info", .lines = lines, .title = a.dupe(u8, m.title) catch "" }) catch {};
    }
    messages = &.{};
}

pub fn has(name: []const u8) bool {
    for (messages) |m| if (std.mem.eql(u8, m.name, name)) return true;
    return false;
}

/// Shows the messages in the message area (our earlier project's Msg.Render);
/// false if there were none. Each can be closed.
pub fn renderMessages() bool {
    defer {
        pending = .empty;
        _ = pending_arena.reset(.retain_capacity);
    }
    if (messages.len == 0 and pending.items.len == 0) {
        dom.setHtml("site-message", "");
        return false;
    }
    var b: app.Buf = .{};
    b.raw("<div class=\"row\"><div class=\"col\">");
    for ([_][]const Message{ pending.items, messages }) |list| for (list) |m| {
        const class = if (std.mem.eql(u8, m.type, "error")) "alert-error" else if (std.mem.eql(u8, m.type, "warning")) "alert-warning" else if (std.mem.eql(u8, m.type, "success")) "alert-success" else "alert-info";
        const title = if (m.title.len > 0) m.title else if (std.mem.eql(u8, m.type, "error")) "Error" else if (std.mem.eql(u8, m.type, "warning")) "Warning" else if (std.mem.eql(u8, m.type, "success")) "Done" else "Note";
        b.add("<div class=\"alert {s}\"><i class=\"fa fa-times button-close\"></i><p><strong>{f}</strong></p>", .{ class, app.esc(title) });
        for (m.lines) |l| b.add("<p>{f}</p>", .{app.esc(l)});
        b.raw("</div>");
    };
    b.raw("</div></div>");
    dom.setHtml("site-message", b.str());
    return true;
}
