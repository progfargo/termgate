//! termgate's panel: a single-page app in Zig, compiled to WASM, built
//! like our earlier project's spa/. The page (web/spa/index.html, boot.js) calls
//! the functions exported here: at the start, when the hash changes and
//! when an element with data-action is clicked. Pages are in pages/; the
//! routes and actions are wired below.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");
const state = @import("state.zig");
const fetch = @import("fetch.zig");
const router = @import("router.zig");
const layout = @import("layout.zig");
const Form = @import("form.zig").Form;

const login = @import("pages/login.zig");
const welcome = @import("pages/welcome.zig");
const user = @import("pages/user.zig");
const role = @import("pages/role.zig");
const profile = @import("pages/profile.zig");
const node = @import("pages/node.zig");

const routes = [_]router.Route{
    .{ .path = "/login", .handler = login.render, .public = true },
    .{ .path = "/welcome", .handler = welcome.render },
    .{ .path = "/user", .handler = user.browse },
    .{ .path = "/user/insert", .handler = user.insert },
    .{ .path = "/user/update", .handler = user.update },
    .{ .path = "/user/role", .handler = user.role },
    .{ .path = "/user/update_pass", .handler = user.updatePass },
    .{ .path = "/user/delete", .handler = user.delete },
    .{ .path = "/role", .handler = role.browse },
    .{ .path = "/role/insert", .handler = role.insert },
    .{ .path = "/role/update", .handler = role.update },
    .{ .path = "/role/right", .handler = role.right },
    .{ .path = "/role/delete", .handler = role.delete },
    .{ .path = "/node", .handler = node.browse },
    .{ .path = "/node/insert", .handler = node.insert },
    .{ .path = "/node/display", .handler = node.display },
    .{ .path = "/node/delete", .handler = node.delete },
    .{ .path = "/profile", .handler = profile.render },
    .{ .path = "/profile/update_pass", .handler = profile.updatePass },
};

const Action = struct { name: []const u8, run: *const fn (Form) void };

/// data-action names and what they do
const actions = [_]Action{
    .{ .name = "login", .run = login.submit },
    .{ .name = "loginCode", .run = login.submitCode },
    .{ .name = "loginBack", .run = login.back },
    .{ .name = "logout", .run = login.logout },
    .{ .name = "copy", .run = user.copy },
    .{ .name = "userFilter", .run = user.filter },
    .{ .name = "userInsert", .run = user.submitInsert },
    .{ .name = "userUpdate", .run = user.submitUpdate },
    .{ .name = "userRoleGrant", .run = user.submitRoleGrant },
    .{ .name = "userRoleRevoke", .run = user.submitRoleRevoke },
    .{ .name = "userUpdatePass", .run = user.submitUpdatePass },
    .{ .name = "userDelete", .run = user.submitDelete },
    .{ .name = "userSelect", .run = user.select },
    .{ .name = "userUnselect", .run = user.unselect },
    .{ .name = "roleInsert", .run = role.submitInsert },
    .{ .name = "roleUpdate", .run = role.submitUpdate },
    .{ .name = "roleRightUpdate", .run = role.submitRight },
    .{ .name = "roleDelete", .run = role.submitDelete },
    .{ .name = "profileUpdatePass", .run = profile.submitUpdatePass },
    .{ .name = "nodeInsert", .run = node.submitInsert },
    .{ .name = "nodeNewKey", .run = node.newKey },
    .{ .name = "nodeApprove", .run = node.approve },
    .{ .name = "nodeReject", .run = node.reject },
    .{ .name = "nodeSetDisabled", .run = node.setDisabled },
    .{ .name = "nodeRefresh", .run = node.refresh },
    .{ .name = "nodeDelete", .run = node.submitDelete },
};

/// The first page the user may open.
fn home() []const u8 {
    return "/welcome";
}

fn onSignedOut() void {
    layout.reset();
    router.go("/login");
}

// --- called by the page (web/spa/boot.js) -------------------------------------

/// Room for a string the page passes in.
export fn tg_alloc(len: usize) ?[*]u8 {
    const s = app.gpa.alloc(u8, len) catch return null;
    return s.ptr;
}

export fn tg_free(ptr: [*]u8, len: usize) void {
    app.gpa.free(ptr[0..len]);
}

/// The page has loaded: who is signed in, then the page of the hash.
export fn tg_start() void {
    app.beginEvent();
    router.routes = &routes;
    router.home = home;
    fetch.on_bad_request = router.renderBadRequest;
    fetch.on_not_found = router.renderNotFound;
    fetch.on_signed_out = onSignedOut;
    login.reload();
    router.navigate(dom.hash());
}

/// The hash changed (a link, the browser's back button).
export fn tg_route(ptr: [*]const u8, len: usize) void {
    app.beginEvent();
    router.navigate(ptr[0..len]);
}

/// An element with data-action was clicked; `form` is the JSON of its
/// form's fields and its data-* attributes.
export fn tg_action(name_ptr: [*]const u8, name_len: usize, form_ptr: [*]const u8, form_len: usize) void {
    app.beginEvent();
    const name = name_ptr[0..name_len];
    const f = Form.parse(form_ptr[0..form_len]);
    for (actions) |a| if (std.mem.eql(u8, a.name, name)) return a.run(f);
    std.log.warn("unknown action {s}", .{name});
}

/// WASM has no console of its own: log lines go to the page's.
pub const std_options: std.Options = .{ .logFn = log };

extern "env" fn tg_log(ptr: [*]const u8, len: usize) void;

fn log(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime fmt: []const u8, args: anytype) void {
    _ = scope;
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, "termgate " ++ @tagName(level) ++ ": " ++ fmt, args) catch return;
    tg_log(s.ptr, s.len);
}

test {
    _ = app;
}
