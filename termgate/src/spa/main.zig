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
const user = @import("pages/user.zig");
const role = @import("pages/role.zig");
const profile = @import("pages/profile.zig");
const node = @import("pages/node.zig");
const session = @import("pages/session.zig");
const live = @import("live.zig");
const audit = @import("pages/audit.zig");
const config = @import("pages/config.zig");
const help = @import("pages/help.zig");
const watch = @import("pages/watch.zig");

const routes = [_]router.Route{
    .{ .path = "/login", .handler = login.render, .public = true },
    .{ .path = "/logout", .handler = logoutRoute },
    .{ .path = "/user/unselect", .handler = unselectRoute },
    .{ .path = "/user", .handler = user.browse },
    .{ .path = "/user/insert", .handler = user.insert },
    .{ .path = "/user/update", .handler = user.update },
    .{ .path = "/user/role", .handler = user.role },
    .{ .path = "/user/update_pass", .handler = user.updatePass },
    .{ .path = "/user/delete", .handler = user.delete },
    .{ .path = "/user/display", .handler = user.display },
    .{ .path = "/user/terminal", .handler = user.terminal },
    .{ .path = "/role", .handler = role.browse },
    .{ .path = "/role/insert", .handler = role.insert },
    .{ .path = "/role/update", .handler = role.update },
    .{ .path = "/role/right", .handler = role.right },
    .{ .path = "/role/delete", .handler = role.delete },
    .{ .path = "/role/display", .handler = role.display },
    .{ .path = "/node", .handler = node.browse },
    .{ .path = "/node/insert", .handler = node.insert },
    .{ .path = "/node/display", .handler = node.display },
    .{ .path = "/node/delete", .handler = node.delete },
    .{ .path = "/node/new_key", .handler = node.newKeyPage },
    .{ .path = "/session", .handler = session.browse },
    .{ .path = "/session/log", .handler = session.log },
    .{ .path = "/session/watch", .handler = watch.render },
    .{ .path = "/audit", .handler = audit.browse },
    .{ .path = "/config", .handler = config.browse },
    .{ .path = "/help", .handler = help.render },
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
    .{ .name = "copyUrl", .run = copyUrl },
    .{ .name = "nodeSearch", .run = node.submitSearch },
    .{ .name = "nodeGoPage", .run = node.goPage },
    .{ .name = "sessionSearch", .run = session.submitSearch },
    .{ .name = "sessionGoPage", .run = session.goPage },
    .{ .name = "auditSearch", .run = audit.submitSearch },
    .{ .name = "auditGoPage", .run = audit.goPage },
    .{ .name = "userSearch", .run = user.submitSearch },
    .{ .name = "userGoPage", .run = user.goPage },
    .{ .name = "userFilter", .run = user.filter },
    .{ .name = "userClear", .run = user.clearFilter },
    .{ .name = "userInsert", .run = user.submitInsert },
    .{ .name = "userUpdate", .run = user.submitUpdate },
    .{ .name = "userRoleGrant", .run = user.submitRoleGrant },
    .{ .name = "userRoleRevoke", .run = user.submitRoleRevoke },
    .{ .name = "userUpdatePass", .run = user.submitUpdatePass },
    .{ .name = "userDelete", .run = user.submitDelete },
    .{ .name = "userSelect", .run = user.select },
    .{ .name = "userUnselect", .run = user.unselect },
    .{ .name = "userAccessKey", .run = user.submitAccessKey },
    .{ .name = "userTerminalRevoke", .run = user.submitTerminalRevoke },
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
    .{ .name = "sessionEnd", .run = session.end },
    .{ .name = "configUpdate", .run = config.submit },
};

/// The page title's link button
fn copyUrl(_: Form) void {
    dom.copyUrl(state.external_url);
}

/// The top menu's Sign out and the user info's unselect are links (as
/// our earlier project's #/logout and #/user/unselect)
fn logoutRoute(_: []const u8) void {
    login.logout(.{});
}

fn unselectRoute(_: []const u8) void {
    user.unselect(.{});
}

/// The first page the user may open, in the menu's order.
fn home() []const u8 {
    const pages = [_]struct { []const u8, []const u8, []const u8 }{
        .{ "/node", "node", "browse" },
        .{ "/session", "session", "browse" },
        .{ "/audit", "audit", "browse" },
        .{ "/user", "user", "browse" },
        .{ "/role", "role", "browse" },
        .{ "/config", "config", "browse" },
        .{ "/profile", "profile", "browse" },
        .{ "/help", "help", "browse" },
    };
    for (pages) |p| if (state.can(p[1], p[2])) return p[0];
    return "/profile";
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

// Each event of the page runs as a job (fetch.zig): it may run again
// when an answer it waits for comes.

/// The page has loaded: who is signed in, then the page of the hash.
export fn tg_start() void {
    app.beginEvent();
    router.routes = &routes;
    router.home = home;
    fetch.on_bad_request = router.renderBadRequest;
    fetch.on_not_found = router.renderNotFound;
    fetch.on_signed_out = onSignedOut;
    fetch.start(.page, startRun, "", "");
}

fn startRun(_: []const u8, _: []const u8) void {
    login.reload();
    router.navigate(dom.hash());
}

/// The hash changed (a link, the browser's back button).
export fn tg_route(ptr: [*]const u8, len: usize) void {
    app.beginEvent();
    fetch.start(.page, routeRun, ptr[0..len], "");
}

fn routeRun(path: []const u8, _: []const u8) void {
    // Leaving a watched session stops watching it
    if (watch.watching() and !std.mem.startsWith(u8, path, "/session/watch")) watch.stop();
    router.navigate(path);
}

/// Four times a second: a watched session's new output; every 5 seconds
/// the live part of the page (live.zig). One request at a time.
export fn tg_tick() void {
    if (fetch.busy(.tick)) return;
    if (watch.watching()) {
        app.beginEvent();
        fetch.start(.tick, tickRun, "", "");
    } else if (live.due()) {
        app.beginEvent();
        var buf: [16]u8 = undefined;
        fetch.start(.tick, liveTickRun, std.fmt.bufPrint(&buf, "{d}", .{live.current()}) catch "", "");
    }
}

fn tickRun(_: []const u8, _: []const u8) void {
    watch.tick();
}

fn liveTickRun(for_page: []const u8, _: []const u8) void {
    live.tick(std.fmt.parseInt(u32, for_page, 10) catch return);
}

/// An element with data-action was clicked; `form` is the JSON of its
/// form's fields and its data-* attributes.
export fn tg_action(name_ptr: [*]const u8, name_len: usize, form_ptr: [*]const u8, form_len: usize) void {
    app.beginEvent();
    fetch.start(.page, actionRun, name_ptr[0..name_len], form_ptr[0..form_len]);
}

fn actionRun(name: []const u8, form: []const u8) void {
    const f = Form.parse(form);
    for (actions) |a| if (std.mem.eql(u8, a.name, name)) return a.run(f);
    std.log.warn("unknown action {s}", .{name});
}

/// The answer to request `id` (web/spa/boot.js): its job runs again.
export fn tg_answer(id: u32, status: i32, ptr: [*]const u8, len: usize) void {
    app.beginEvent();
    fetch.answer(id, status, ptr[0..len]);
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
