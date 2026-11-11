//! Signing in to the panel from the browser: the calls behind the sign-in
//! screens (ui.zig) and who is signed in. See server/auth.zig.

const std = @import("std");
const rpc = @import("rpc");


var signed_in = false;
var name_buf: [64]u8 = undefined;
var name_len: usize = 0;
var superuser = false;
/// While the user acts as another (users.select): its own name
var real_buf: [64]u8 = undefined;
var real_len: usize = 0;
var can_select = false;
var can_unselect = false;
/// The user's rights, each "module:action" (see rights.zig), in one buffer
var rights_buf: [2048]u8 = undefined;
var rights_list: [96][]const u8 = undefined;
var rights_count: usize = 0;

pub fn signedIn() bool {
    return signed_in;
}

pub fn name() []const u8 {
    return name_buf[0..name_len];
}

pub fn isSuperuser() bool {
    return signed_in and superuser;
}

/// The signed-in user's own name while it acts as `name()`; null when it
/// is itself.
pub fn actingFor() ?[]const u8 {
    return if (signed_in and real_len > 0) real_buf[0..real_len] else null;
}

/// May the signed-in user itself act as another user, or stop doing so.
pub fn canSelect() bool {
    return signed_in and can_select;
}

pub fn canUnselect() bool {
    return signed_in and can_unselect;
}

/// May the signed-in user do this? The server checks it again on every
/// call; here it decides what the screens show.
pub fn can(module: []const u8, action: []const u8) bool {
    if (!signed_in) return false;
    if (superuser) return true;
    for (rights_list[0..rights_count]) |r| {
        if (r.len == module.len + 1 + action.len and std.mem.startsWith(u8, r, module) and r[module.len] == ':' and std.mem.endsWith(u8, r, action)) return true;
    }
    return false;
}

const Me = struct {
    name: []const u8,
    superuser: bool = false,
    rights: []const []const u8 = &.{},
    real: ?[]const u8 = null,
    can_select: bool = false,
    can_unselect: bool = false,
};

fn remember(me: Me) void {
    name_len = @min(me.name.len, name_buf.len);
    @memcpy(name_buf[0..name_len], me.name[0..name_len]);
    superuser = me.superuser;
    const real = me.real orelse "";
    real_len = @min(real.len, real_buf.len);
    @memcpy(real_buf[0..real_len], real[0..real_len]);
    can_select = me.can_select or me.superuser;
    can_unselect = me.can_unselect;
    rights_count = 0;
    var used: usize = 0;
    for (me.rights) |r| {
        if (rights_count == rights_list.len or used + r.len > rights_buf.len) break;
        @memcpy(rights_buf[used..][0..r.len], r);
        rights_list[rights_count] = rights_buf[used..][0..r.len];
        rights_count += 1;
        used += r.len;
    }
    signed_in = true;
}

/// At start: is the browser's session still good? Also after roles were
/// changed: the user's own rights may be different now.
pub fn resume_(a: std.mem.Allocator) void {
    const r = rpc.call(a, "me", "{}") catch return;
    if (r.status != 200) {
        if (r.status == 401) signed_in = false;
        return;
    }
    const me = std.json.parseFromSliceLeaky(Me, a, r.body, .{ .ignore_unknown_fields = true }) catch return;
    remember(me);
}

pub const LoginResult = union(enum) {
    /// Signed in with the password alone (termgate built with
    /// -Dsecond-step=false)
    signed_in,
    /// Password accepted: now the code from the authenticator app
    code,
    /// First sign-in: this secret goes into the authenticator app first,
    /// typed as text or scanned as a QR code (`uri`)
    setup: struct { secret: []const u8, uri: []const u8 },
    /// Shown to the user
    failed: []const u8,
};

pub fn login(a: std.mem.Allocator, who: []const u8, password: []const u8) LoginResult {
    const body = std.json.Stringify.valueAlloc(a, .{ .name = who, .password = password }, .{}) catch return .{ .failed = "Out of memory." };
    const r = rpc.call(a, "login", body) catch return .{ .failed = "The server cannot be reached." };
    const Answer = struct { step: []const u8 = "", secret: []const u8 = "", uri: []const u8 = "", retry_after: i64 = 0 };
    const ans = std.json.parseFromSliceLeaky(Answer, a, r.body, .{ .ignore_unknown_fields = true }) catch Answer{};
    return switch (r.status) {
        200 => if (std.mem.eql(u8, ans.step, "setup"))
            .{ .setup = .{ .secret = ans.secret, .uri = ans.uri } }
        else if (std.mem.eql(u8, ans.step, "done")) blk: {
            const me = std.json.parseFromSliceLeaky(Me, a, r.body, .{ .ignore_unknown_fields = true }) catch break :blk .{ .failed = "Sign-in failed." };
            remember(me);
            break :blk .signed_in;
        } else .code,
        401 => .{ .failed = "Wrong name or password." },
        429 => .{ .failed = std.fmt.allocPrint(a, "Too many wrong attempts. Try again in {d} s.", .{ans.retry_after}) catch "Too many wrong attempts." },
        0 => .{ .failed = "The server cannot be reached." },
        else => .{ .failed = "Sign-in failed." },
    };
}

/// The second step. Null: signed in; otherwise what to show.
pub fn code(a: std.mem.Allocator, text: []const u8) ?[]const u8 {
    const body = std.json.Stringify.valueAlloc(a, .{ .code = text }, .{}) catch return "Out of memory.";
    const r = rpc.call(a, "login2", body) catch return "The server cannot be reached.";
    switch (r.status) {
        200 => {},
        401 => return "Wrong code.",
        429 => return "Too many wrong attempts. Try again later.",
        0 => return "The server cannot be reached.",
        else => return "Sign-in failed.",
    }
    const me = std.json.parseFromSliceLeaky(Me, a, r.body, .{ .ignore_unknown_fields = true }) catch return "Sign-in failed.";
    remember(me);
    return null;
}

// --- users and roles (see server/auth.zig) -----------------------------------

pub const RoleRef = struct { id: i64, name: []const u8 };
pub const UserRow = struct { id: i64, name: []const u8, superuser: bool, disabled: bool, second_step: bool, created: i64, roles: []const RoleRef };
pub const RoleRow = struct { id: i64, name: []const u8, description: []const u8, user_count: i64 };
pub const RoleDetail = struct { role: RoleRow, rights: []const []const u8 };

const failed_text = "The server cannot be reached.";

/// What the server said went wrong, or the general text.
fn errorOf(a: std.mem.Allocator, body: []const u8) []const u8 {
    const Answer = struct { @"error": []const u8 = "" };
    const ans = std.json.parseFromSliceLeaky(Answer, a, body, .{ .ignore_unknown_fields = true }) catch Answer{};
    return if (ans.@"error".len > 0) ans.@"error" else failed_text;
}

/// A call that only succeeds or not. Null: done; otherwise what to show.
fn plain(a: std.mem.Allocator, call_name: []const u8, value: anytype) ?[]const u8 {
    const body = std.json.Stringify.valueAlloc(a, value, .{}) catch return "Out of memory.";
    const r = rpc.call(a, call_name, body) catch return failed_text;
    return if (r.status == 200) null else errorOf(a, r.body);
}

/// Null: the list could not be read (no right, or no server).
pub fn usersList(a: std.mem.Allocator) ?[]const UserRow {
    const r = rpc.call(a, "users.list", "{}") catch return null;
    if (r.status != 200) return null;
    const List = struct { users: []const UserRow };
    const l = std.json.parseFromSliceLeaky(List, a, r.body, .{ .ignore_unknown_fields = true }) catch return null;
    return l.users;
}

pub fn userGet(a: std.mem.Allocator, id: i64) ?UserRow {
    for (usersList(a) orelse return null) |u| if (u.id == id) return u;
    return null;
}

/// A generated password to hand over, or why not.
pub const PasswordResult = union(enum) { password: struct { id: i64, name: []const u8, text: []const u8 }, failed: []const u8 };

fn passwordCall(a: std.mem.Allocator, call_name: []const u8, value: anytype) PasswordResult {
    const body = std.json.Stringify.valueAlloc(a, value, .{}) catch return .{ .failed = "Out of memory." };
    const r = rpc.call(a, call_name, body) catch return .{ .failed = failed_text };
    const Answer = struct { id: i64 = 0, name: []const u8 = "", password: []const u8 = "" };
    const ans = std.json.parseFromSliceLeaky(Answer, a, r.body, .{ .ignore_unknown_fields = true }) catch Answer{};
    if (r.status == 200 and ans.password.len > 0) return .{ .password = .{ .id = ans.id, .name = ans.name, .text = ans.password } };
    return .{ .failed = errorOf(a, r.body) };
}

pub fn userCreate(a: std.mem.Allocator, who: []const u8) PasswordResult {
    return passwordCall(a, "users.create", .{ .name = who });
}

pub fn userReset(a: std.mem.Allocator, id: i64) PasswordResult {
    return passwordCall(a, "users.reset", .{ .id = id });
}

pub fn userUpdate(a: std.mem.Allocator, id: i64, who: []const u8, disabled: bool) ?[]const u8 {
    return plain(a, "users.update", .{ .id = id, .name = who, .disabled = disabled });
}

pub fn userDelete(a: std.mem.Allocator, id: i64) ?[]const u8 {
    return plain(a, "users.delete", .{ .id = id });
}

pub fn userGrant(a: std.mem.Allocator, id: i64, role: i64) ?[]const u8 {
    return plain(a, "users.grant", .{ .id = id, .role = role });
}

pub fn userRevoke(a: std.mem.Allocator, id: i64, role: i64) ?[]const u8 {
    return plain(a, "users.revoke", .{ .id = id, .role = role });
}

pub fn rolesList(a: std.mem.Allocator) ?[]const RoleRow {
    const r = rpc.call(a, "roles.list", "{}") catch return null;
    if (r.status != 200) return null;
    const List = struct { roles: []const RoleRow };
    const l = std.json.parseFromSliceLeaky(List, a, r.body, .{ .ignore_unknown_fields = true }) catch return null;
    return l.roles;
}

pub fn roleGet(a: std.mem.Allocator, id: i64) ?RoleDetail {
    const body = std.json.Stringify.valueAlloc(a, .{ .id = id }, .{}) catch return null;
    const r = rpc.call(a, "roles.get", body) catch return null;
    if (r.status != 200) return null;
    return std.json.parseFromSliceLeaky(RoleDetail, a, r.body, .{ .ignore_unknown_fields = true }) catch null;
}

/// Acts as user `id` from now on: its rights apply (users.select).
pub fn userSelect(a: std.mem.Allocator, id: i64) ?[]const u8 {
    return plain(a, "users.select", .{ .id = id });
}

/// Back to being oneself.
pub fn userUnselect(a: std.mem.Allocator) ?[]const u8 {
    // No arguments: an empty object (`.{}` would be written as [])
    const r = rpc.call(a, "users.unselect", "{}") catch return failed_text;
    return if (r.status == 200) null else errorOf(a, r.body);
}

/// Changes one's own password; null: done, otherwise why not.
pub fn changePassword(a: std.mem.Allocator, current: []const u8, new: []const u8, new2: []const u8) ?[]const u8 {
    return plain(a, "profile.password", .{ .current = current, .new = new, .new2 = new2 });
}

/// `id` 0: a new role. `list` null: the role's rights are not changed.
pub fn roleSave(a: std.mem.Allocator, id: i64, role_name: []const u8, description: []const u8, list: ?[]const []const u8) ?[]const u8 {
    const v = .{ .id = id, .name = role_name, .description = description, .rights = list };
    return plain(a, if (id == 0) "roles.insert" else "roles.update", v);
}

pub fn roleDelete(a: std.mem.Allocator, id: i64) ?[]const u8 {
    return plain(a, "roles.delete", .{ .id = id });
}

pub fn logout(a: std.mem.Allocator) void {
    _ = rpc.call(a, "logout", "{}") catch {};
    signed_in = false;
    superuser = false;
    rights_count = 0;
    name_len = 0;
    real_len = 0;
    can_select = false;
    can_unselect = false;
}
