//! The calls to termgate's API: POST /api/<page>/<function> with JSON, as
//! our earlier project's fetch package. The call waits for the answer (a
//! synchronous request, made by web/spa/boot.js). The answer's messages
//! go to state; a missing right, a missing record and an ended session
//! are handled here, as our earlier project's ErrorHandler.

const std = @import("std");
const app = @import("app.zig");
const state = @import("state.zig");

// web/spa/boot.js
extern "env" fn tg_post(path: [*]const u8, path_len: usize, body: [*]const u8, body_len: usize) i32;
extern "env" fn tg_answer_len() usize;
extern "env" fn tg_answer_read(out: [*]u8) void;

/// What router.zig does on a missing right (400), a missing record (404)
/// and an ended session (401); set by main.zig (no import loop).
pub var on_bad_request: *const fn () void = noop;
pub var on_not_found: *const fn () void = noop;
pub var on_signed_out: *const fn () void = noop;

fn noop() void {}

/// Calls `path` with `args` as JSON. The answer's object, or null when
/// the call failed (the page has been told). Its messages are in
/// state.messages either way.
pub fn post(path: []const u8, args: anytype) ?std.json.Value {
    const a = app.arena();
    const body = std.json.Stringify.valueAlloc(a, args, .{}) catch return null;
    return postRaw(path, body);
}

pub fn postRaw(path: []const u8, body: []const u8) ?std.json.Value {
    const a = app.arena();
    const status = tg_post(path.ptr, path.len, body.ptr, body.len);
    const text = a.alloc(u8, tg_answer_len()) catch return null;
    tg_answer_read(text.ptr);
    const answer = std.json.parseFromSliceLeaky(std.json.Value, a, text, .{}) catch std.json.Value{ .null = {} };
    state.takeMessages(answer);
    switch (status) {
        200 => return answer,
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
pub fn field(answer: std.json.Value, name: []const u8) ?std.json.Value {
    if (answer != .object) return null;
    return answer.object.get(name);
}

/// A field turned into `T` (missing or of another shape: null).
pub fn fieldAs(comptime T: type, answer: std.json.Value, name: []const u8) ?T {
    const v = field(answer, name) orelse return null;
    return std.json.parseFromValueLeaky(T, app.arena(), v, .{ .ignore_unknown_fields = true }) catch null;
}

/// Whether the answer has a warning or error message: the call was
/// refused (a rule; our earlier project answers it with status 200).
pub fn refused() bool {
    for (state.messages) |m| if (std.mem.eql(u8, m.type, "warning") or std.mem.eql(u8, m.type, "error")) return true;
    return false;
}
