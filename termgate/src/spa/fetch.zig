//! The calls to termgate's API: POST /api/<page>/<function> with JSON, as
//! our earlier project's fetch package. The answer's messages go to state; a
//! missing right, a missing record and an ended session are handled
//! here, as our earlier project's ErrorHandler.
//!
//! The requests are asynchronous (web/spa/boot.js), yet a page's code
//! reads from top to bottom, as our earlier project's code inside a goroutine:
//! every event of the page (a hash change, a click, a tick) runs as a job.
//! When a job asks for an answer that has not come yet, the request is
//! sent, `post` gives null and the rest of that run changes nothing on the
//! page (app.waiting: dom, state and router leave it). When the answer
//! comes, the job runs again from the start: the answers it has are given
//! at once, in the order they were asked, and it goes on to the next
//! call, until it runs to its end.

const std = @import("std");
const app = @import("app.zig");
const state = @import("state.zig");

// web/spa/boot.js: starts the request; its answer comes to answer()
extern "env" fn tg_post(id: u32, path: [*]const u8, path_len: usize, body: [*]const u8, body_len: usize) void;

/// What router.zig does on a missing right (400), a missing record (404)
/// and an ended session (401); set by main.zig (no import loop).
pub var on_bad_request: *const fn () void = noop;
pub var on_not_found: *const fn () void = noop;
pub var on_signed_out: *const fn () void = noop;

fn noop() void {}

/// What a job runs: an event of the page with its two strings (the hash;
/// an action's name and its form).
pub const Run = *const fn (a: []const u8, b: []const u8) void;

const Call = struct {
    /// The request, to tell whether a run asks the same (path and body)
    request: []u8,
    /// Its answer once it came: status (0: the server cannot be reached)
    /// and text
    status: ?i32 = null,
    text: []u8 = &.{},
};

const Job = struct {
    run: Run,
    a: []u8,
    b: []u8,
    calls: std.ArrayList(Call) = .empty,
    /// The id of the request it waits for
    waiting_for: u32 = 0,

    fn deinit(j: *Job) void {
        for (j.calls.items) |c| {
            app.gpa.free(c.request);
            app.gpa.free(c.text);
        }
        j.calls.deinit(app.gpa);
        app.gpa.free(j.a);
        app.gpa.free(j.b);
        app.gpa.destroy(j);
    }
};

/// The page's job (a page shown, a button), and the ticks' (a watched
/// session). A new page job replaces the one before: its answer, if it
/// still comes, is dropped.
pub const Kind = enum { page, tick };
var jobs: [2]?*Job = .{ null, null };
/// The job running now, and how many of its calls this run has made
var current: ?*Job = null;
var next_call: usize = 0;
var next_id: u32 = 1;

/// Whether a job of this kind waits for an answer.
pub fn busy(kind: Kind) bool {
    return jobs[@intFromEnum(kind)] != null;
}

/// Runs an event of the page as a job.
pub fn start(kind: Kind, run: Run, a: []const u8, b: []const u8) void {
    const slot = &jobs[@intFromEnum(kind)];
    if (slot.*) |old| old.deinit();
    slot.* = null;
    const j = app.gpa.create(Job) catch return;
    j.* = .{ .run = run, .a = app.gpa.dupe(u8, a) catch "", .b = app.gpa.dupe(u8, b) catch "" };
    slot.* = j;
    state.jobStarted();
    go(kind, j);
}

/// One run of a job; done when it asked for nothing it does not have.
fn go(kind: Kind, j: *Job) void {
    current = j;
    next_call = 0;
    app.waiting = false;
    state.runStarted();
    j.run(j.a, j.b);
    const done = !app.waiting;
    current = null;
    app.waiting = false;
    if (done) {
        state.jobDone();
        jobs[@intFromEnum(kind)] = null;
        j.deinit();
    }
}

/// An answer came (web/spa/boot.js): its job runs again.
pub fn answer(id: u32, status: i32, text: []const u8) void {
    for (&jobs, 0..) |*slot, k| {
        const j = slot.* orelse continue;
        if (j.waiting_for != id) continue;
        const c = &j.calls.items[j.calls.items.len - 1];
        c.status = status;
        c.text = app.gpa.dupe(u8, text) catch &.{};
        return go(@enumFromInt(k), j);
    }
    // A job replaced since: dropped
}

/// Calls `path` with `args` as JSON. The answer's object, or null when
/// the call failed (the page has been told) or its answer has not come
/// yet. Its messages are in state.messages either way.
pub fn post(path: []const u8, args: anytype) ?std.json.Value {
    const body = std.json.Stringify.valueAlloc(app.arena(), args, .{}) catch return null;
    return postRaw(path, body);
}

pub fn postRaw(path: []const u8, body: []const u8) ?std.json.Value {
    // After a call that waits, a run asks for nothing more
    if (app.waiting) return null;
    const j = current orelse return null;
    const request = std.mem.concat(app.arena(), u8, &.{ path, "\x00", body }) catch return null;
    const i = next_call;
    next_call += 1;
    if (i < j.calls.items.len and !std.mem.eql(u8, j.calls.items[i].request, request)) {
        // The run asks something else than before: what came after is void
        for (j.calls.items[i..]) |c| {
            app.gpa.free(c.request);
            app.gpa.free(c.text);
        }
        j.calls.shrinkRetainingCapacity(i);
    }
    if (i == j.calls.items.len) {
        j.calls.append(app.gpa, .{ .request = app.gpa.dupe(u8, request) catch return null }) catch return null;
        j.waiting_for = next_id;
        next_id +%= 1;
        tg_post(j.waiting_for, path.ptr, path.len, body.ptr, body.len);
    }
    const c = j.calls.items[i];
    const status = c.status orelse {
        app.waiting = true;
        return null;
    };
    return handle(status, c.text);
}

fn handle(status: i32, text: []const u8) ?std.json.Value {
    const a = app.arena();
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch std.json.Value{ .null = {} };
    state.takeMessages(parsed);
    switch (status) {
        200 => return parsed,
        401 => {
            state.setUser(null);
            on_signed_out();
        },
        400 => on_bad_request(),
        404 => on_not_found(),
        0 => state.say("error", "The server cannot be reached."),
        else => if (state.messages.len == 0) state.say("error", "The server could not do it."),
    }
    return null;
}

/// A field of an answer's object, or null.
pub fn field(ans: std.json.Value, name: []const u8) ?std.json.Value {
    if (ans != .object) return null;
    return ans.object.get(name);
}

/// A field turned into `T` (missing or of another shape: null).
pub fn fieldAs(comptime T: type, ans: std.json.Value, name: []const u8) ?T {
    const v = field(ans, name) orelse return null;
    return std.json.parseFromValueLeaky(T, app.arena(), v, .{ .ignore_unknown_fields = true }) catch null;
}

/// Whether the answer has a warning or error message: the call was
/// refused (a rule; our earlier project answers it with status 200).
pub fn refused() bool {
    for (state.messages) |m| if (std.mem.eql(u8, m.type, "warning") or std.mem.eql(u8, m.type, "error")) return true;
    return false;
}
