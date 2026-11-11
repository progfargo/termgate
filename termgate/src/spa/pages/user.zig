//! Users (#/user), as our earlier project's user pages: the list with its role and
//! status filters; New; Edit; Roles; New password; Delete (asks first);
//! Select (act as the user) and back. Each button is there only for who
//! has its right; the server checks it again and keeps the rules (the
//! superuser, the last admin).
//!
//! termgate makes the passwords (shown once, handed over by whoever made
//! the user); there is no e-mail.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const login = @import("login.zig");
const Form = @import("../form.zig").Form;

const RoleRef = struct { id: i64, name: []const u8 };
const User = struct { id: i64, name: []const u8, superuser: bool = false, disabled: bool = false, second_step: bool = false, created: i64 = 0, roles: []const RoleRef = &.{} };
const Role = struct { id: i64, name: []const u8, description: []const u8 = "", user_count: i64 = 0 };

fn users() ?[]const User {
    const answer = fetch.postRaw("user/browse", "{}") orelse return null;
    return fetch.fieldAs([]const User, answer, "users");
}

fn userById(id: i64) ?User {
    for (users() orelse return null) |u| if (u.id == id) return u;
    router.renderNotFound();
    return null;
}

fn roles() []const Role {
    const answer = fetch.postRaw("role/browse", "{}") orelse return &.{};
    return fetch.fieldAs([]const Role, answer, "roles") orelse &.{};
}

fn begin() void {
    dom.setBodyId("");
    layout.renderDefault("user");
}

fn show(b: *const app.Buf) void {
    dom.setHtml("main-content", b.str());
    _ = state.renderMessages();
    dom.focusFirstField();
}

fn status(b: *app.Buf, u: User) void {
    // Without the second step (a build for trying the panel) nobody sets it up
    if (u.disabled) content.label(b, "error", "Blocked") else if (!u.second_step and state.second_step) content.label(b, "warning", "Not signed in yet") else content.label(b, "success", "Active");
}

// --- Browse -------------------------------------------------------------------

/// Filters of the list, kept while the page is open (rid: role, stat:
/// active, blocked, new)
var filter_role: i64 = 0;
var filter_status: []const u8 = "default";
var filter_status_buf: [16]u8 = undefined;

pub fn browse(query: []const u8) void {
    if (!state.can("user", "browse")) return router.renderBadRequest();
    begin();
    if (query.len > 0) {
        filter_role = app.queryInt(query, "rid");
        setStatus(app.queryValue(query, "stat"));
    }
    const list = users() orelse return;
    const all_roles = if (state.can("user", "role_browse")) roles() else &.{};
    const me = state.user.?;
    const can_select = me.can_select and me.real == null;
    const has_command = can_select or state.can("user", "update") or state.can("user", "role_browse") or state.can("user", "update_pass") or state.can("user", "delete");

    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Users", "" }});
    content.commandStart(&b);
    if (state.can("user", "insert")) b.raw("<a href=\"#/user/insert\" class=\"button button-default button-sm\">New</a>");
    // Each filter in a form of its own, as in our earlier project
    if (all_roles.len > 0) {
        b.add("<form class=\"form-inline\"><div class=\"form-group\"><select id=\"user-rid-select\" class=\"form-control\" data-change=\"userFilter\"><option value=\"0\"{s}>All roles</option>", .{if (filter_role == 0) " selected" else ""});
        for (all_roles) |r| b.add("<option value=\"{d}\"{s}>{f}</option>", .{ r.id, if (r.id == filter_role) " selected" else "", app.esc(r.name) });
        b.raw("</select></div></form>");
    }
    b.raw("<form class=\"form-inline\"><div class=\"form-group\"><select id=\"user-stat-select\" class=\"form-control\" data-change=\"userFilter\">");
    for ([_][2][]const u8{ .{ "default", "All statuses" }, .{ "active", "Active" }, .{ "new", "Not signed in yet" }, .{ "blocked", "Blocked" } }) |o|
        b.add("<option value=\"{s}\"{s}>{s}</option>", .{ o[0], if (std.mem.eql(u8, o[0], filter_status)) " selected" else "", o[1] });
    b.raw("</select></div></form>");
    b.raw("<a href=\"#/user?rid=0&stat=default\" class=\"button button-default button-sm\" title=\"Reset all filters.\">Clear</a>");
    content.commandEnd(&b);

    content.contentStart(&b);
    b.raw("<table><thead><tr><th>Name</th><th>Status</th><th>Roles</th><th>Created</th>");
    if (has_command) b.raw("<th class=\"right\">Command</th>");
    b.raw("</tr></thead><tbody>");
    var shown: usize = 0;
    for (list) |u| {
        if (!matches(u)) continue;
        shown += 1;
        b.add("<tr><td>{f}</td><td>", .{app.esc(u.name)});
        status(&b, u);
        b.raw("</td><td>");
        if (u.superuser) content.label(&b, "primary", "superuser");
        for (u.roles, 0..) |r, i| b.add("{s}{f}", .{ if (i > 0 or u.superuser) ", " else " ", app.esc(r.name) });
        b.add("</td><td>{s}</td>", .{content.dateTime(u.created)});
        if (has_command) {
            const own = std.mem.eql(u8, u.name, me.name);
            b.raw("<td class=\"right\"><div class=\"button-group-fixed\">");
            // Act as the user: not oneself, not a blocked user, the
            // superuser only by the superuser
            if (can_select and !own and !u.disabled and (!u.superuser or me.superuser))
                b.add("<button type=\"button\" data-action=\"userSelect\" data-id=\"{d}\" class=\"button button-default button-xs\" title=\"See and use the panel as this user does.\">Select</button>", .{u.id});
            // Nobody changes the superuser
            if (!u.superuser) {
                if (state.can("user", "update")) b.add("<a href=\"#/user/update?userId={d}\" class=\"button button-default button-xs\" title=\"Edit record.\">Edit</a>", .{u.id});
                if (state.can("user", "role_browse")) b.add("<a href=\"#/user/role?userId={d}\" class=\"button button-default button-xs\" title=\"Edit user roles.\">Roles</a>", .{u.id});
                if (state.can("user", "update_pass")) b.add("<a href=\"#/user/update_pass?userId={d}\" class=\"button button-default button-xs\" title=\"Give the user a new password.\">New Pass</a>", .{u.id});
                if (state.can("user", "delete") and !own) b.add("<a href=\"#/user/delete?userId={d}\" class=\"button button-error button-xs\" title=\"Delete record.\">Delete</a>", .{u.id});
            }
            b.raw("</div></td>");
        }
        b.raw("</tr>");
    }
    if (shown == 0) b.add("<tr><td colspan=\"{d}\">Empty list.</td></tr>", .{@as(u8, if (has_command) 5 else 4)});
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    show(&b);
}

fn setStatus(s: []const u8) void {
    const n = @min(s.len, filter_status_buf.len);
    @memcpy(filter_status_buf[0..n], s[0..n]);
    filter_status = if (n == 0) "default" else filter_status_buf[0..n];
}

fn matches(u: User) bool {
    if (filter_role != 0) {
        var has = false;
        for (u.roles) |r| has = has or r.id == filter_role;
        if (!has) return false;
    }
    if (std.mem.eql(u8, filter_status, "active")) return !u.disabled and u.second_step;
    if (std.mem.eql(u8, filter_status, "new")) return !u.disabled and !u.second_step;
    if (std.mem.eql(u8, filter_status, "blocked")) return u.disabled;
    return true;
}

/// A filter was changed
pub fn filter(f: Form) void {
    // The filter that changed; the other one stays as it is
    const rid = if (f.str("user-rid-select").len > 0) f.int("user-rid-select") else filter_role;
    const stat = if (f.str("user-stat-select").len > 0) f.str("user-stat-select") else filter_status;
    router.go(std.fmt.allocPrint(app.arena(), "/user?rid={d}&stat={s}", .{ rid, stat }) catch return);
}

// --- Insert -------------------------------------------------------------------

pub fn insert(_: []const u8) void {
    if (!state.can("user", "insert")) return router.renderBadRequest();
    begin();
    renderInsert("");
}

fn renderInsert(name: []const u8) void {
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ "New Record", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "user-name-input", "Name:", name, .{ .required = true, .max = 32, .autofocus = true, .help = "Lowercase letters, digits, _ . -; starts with a letter." });
    b.raw("<p>termgate makes a password, shown once; you hand it over. The user sets up the second step at the first sign-in.</p>");
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"userInsert\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/user\" class=\"button button-default button-sm\">Cancel</a></div></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    show(&b);
}

pub fn submitInsert(f: Form) void {
    const name = f.trimmed("user-name-input");
    const answer = fetch.post("user/insert", .{ .name = name }) orelse return renderInsert(name);
    if (fetch.refused()) return renderInsert(name);
    const id = fetch.fieldAs(i64, answer, "id") orelse 0;
    showPassword(name, fetch.fieldAs([]const u8, answer, "password") orelse "", id);
}

/// The new password, once; then the user's roles.
fn showPassword(name: []const u8, password: []const u8, id: i64) void {
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ name, "" }, .{ "Password", "" } });
    content.contentStart(&b);
    b.raw("<p>Shown once. Hand it over yourself: termgate sends no e-mail. At the next sign-in the user sets up its second step (authenticator app).</p>");
    b.add("<p><strong id=\"user-password\">{f}</strong></p>", .{app.esc(password)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"copy\" data-text=\"{f}\" class=\"button button-default button-sm\"><i class=\"fa fa-copy\"></i> Copy</button>", .{app.esc(password)});
    if (state.can("user", "role_browse")) b.add("<a href=\"#/user/role?userId={d}\" class=\"button button-primary button-sm\">Roles</a>", .{id});
    b.raw("<a href=\"#/user\" class=\"button button-default button-sm\">Done</a>");
    content.commandEnd(&b);
    show(&b);
}

// --- Update -------------------------------------------------------------------

var edit_id: i64 = 0;

pub fn update(query: []const u8) void {
    if (!state.can("user", "update")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "userId");
    const u = userById(edit_id) orelse return;
    renderUpdate(u.name, u.disabled, std.mem.eql(u8, u.name, state.user.?.name));
}

fn renderUpdate(name: []const u8, disabled: bool, own: bool) void {
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ "Edit Record", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "user-name-input", "Name:", name, .{ .required = true, .max = 32, .autofocus = true, .help = "Lowercase letters, digits, _ . -; starts with a letter." });
    // Nobody blocks themselves
    if (!own) content.checkbox(&b, "user-blocked-input", "Blocked: cannot sign in", disabled);
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"userUpdate\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/user\" class=\"button button-default button-sm\">Cancel</a></div></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    show(&b);
}

pub fn submitUpdate(f: Form) void {
    const name = f.trimmed("user-name-input");
    const blocked = f.checked("user-blocked-input");
    _ = fetch.post("user/update", .{ .id = edit_id, .name = name, .disabled = blocked }) orelse return;
    if (fetch.refused()) return renderUpdate(name, blocked, !dom.exists("user-blocked-input"));
    // The name in the menu may be this user's
    login.reload();
    state.say("success", "Record has been changed.");
    router.go("/user");
}

// --- Roles --------------------------------------------------------------------

pub fn role(query: []const u8) void {
    if (!state.can("user", "role_browse")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "userId");
    renderRoles();
}

fn renderRoles() void {
    const u = userById(edit_id) orelse return;
    const all = roles();
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ u.name, "" }, .{ "Roles", "" } });
    content.contentStart(&b);
    b.raw("<table><thead><tr><th>Role</th><th>Description</th>");
    const can_revoke = state.can("user", "role_revoke");
    if (can_revoke) b.raw("<th class=\"right\">Command</th>");
    b.raw("</tr></thead><tbody>");
    if (u.roles.len == 0) b.raw("<tr><td colspan=\"3\">No roles: this user may sign in but do nothing.</td></tr>");
    for (u.roles) |r| {
        var description: []const u8 = "";
        for (all) |x| if (x.id == r.id) {
            description = x.description;
        };
        b.add("<tr><td>{f}</td><td>{f}</td>", .{ app.esc(r.name), app.esc(description) });
        if (can_revoke) b.add("<td class=\"right\"><button type=\"button\" data-action=\"userRoleRevoke\" data-role=\"{d}\" class=\"button button-error button-xs\">Revoke</button></td>", .{r.id});
        b.raw("</tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    // Giving one of the roles the user does not have yet
    if (state.can("user", "role_grant")) {
        b.raw("<div class=\"row row-command\"><div class=\"col\"><form class=\"form-inline\"><div class=\"form-group\"><select id=\"user-role-select\" class=\"form-control\"><option value=\"0\">Select a role</option>");
        for (all) |r| {
            var has = false;
            for (u.roles) |x| has = has or x.id == r.id;
            if (!has) b.add("<option value=\"{d}\">{f}</option>", .{ r.id, app.esc(r.name) });
        }
        b.raw("</select></div> <button type=\"button\" data-action=\"userRoleGrant\" class=\"button button-primary button-sm\">Grant</button></form></div></div>");
    }
    content.commandStart(&b);
    b.raw("<a href=\"#/user\" class=\"button button-default button-sm\">Back</a>");
    content.commandEnd(&b);
    show(&b);
}

pub fn submitRoleGrant(f: Form) void {
    const role_id = f.int("user-role-select");
    if (role_id == 0) {
        state.say("warning", "You did not select a role.");
        return renderRoles();
    }
    _ = fetch.post("user/role_grant", .{ .id = edit_id, .role = role_id }) orelse return;
    afterRoles("Role has been granted.");
}

pub fn submitRoleRevoke(f: Form) void {
    _ = fetch.post("user/role_revoke", .{ .id = edit_id, .role = f.int("role") }) orelse return;
    afterRoles("Role has been revoked.");
}

fn afterRoles(done: []const u8) void {
    if (fetch.refused()) state.keepMessages() else state.say("success", done);
    // One's own rights may have changed
    login.reload();
    layout.renderDefault("user");
    renderRoles();
}

// --- New password -------------------------------------------------------------

pub fn updatePass(query: []const u8) void {
    if (!state.can("user", "update_pass")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "userId");
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ u.name, "" }, .{ "New Password", "" } });
    content.contentStart(&b);
    b.add("<p>Give <strong>{f}</strong> a new password? Its sessions end, and it sets up the second step again at the next sign-in.</p>", .{app.esc(u.name)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.raw("<button type=\"button\" data-action=\"userUpdatePass\" class=\"button button-warning button-sm\">Yes</button><a href=\"#/user\" class=\"button button-default button-sm\">Cancel</a>");
    content.commandEnd(&b);
    show(&b);
}

pub fn submitUpdatePass(_: Form) void {
    const answer = fetch.post("user/update_pass", .{ .id = edit_id }) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
        return router.go("/user");
    }
    showPassword(fetch.fieldAs([]const u8, answer, "name") orelse "", fetch.fieldAs([]const u8, answer, "password") orelse "", edit_id);
}

// --- Delete -------------------------------------------------------------------

pub fn delete(query: []const u8) void {
    if (!state.can("user", "delete")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "userId");
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Users", "#/user" }, .{ "Delete Record", "" } });
    content.contentStart(&b);
    b.raw("<p>Delete this user?</p><table><tbody>");
    b.add("<tr><th class=\"fixed-middle\">Name:</th><td>{f}</td></tr><tr><th>Status:</th><td>", .{app.esc(u.name)});
    status(&b, u);
    b.raw("</td></tr><tr><th>Roles:</th><td>");
    for (u.roles, 0..) |r, i| b.add("{s}{f}", .{ if (i > 0) ", " else "", app.esc(r.name) });
    b.raw("</td></tr></tbody></table>");
    content.contentEnd(&b);
    content.commandStart(&b);
    b.raw("<button type=\"button\" data-action=\"userDelete\" class=\"button button-error button-sm\">Yes</button><a href=\"#/user\" class=\"button button-default button-sm\">Cancel</a>");
    content.commandEnd(&b);
    show(&b);
}

pub fn submitDelete(_: Form) void {
    _ = fetch.post("user/delete", .{ .id = edit_id }) orelse return;
    if (fetch.refused()) state.keepMessages() else state.say("success", "Record has been deleted.");
    router.go("/user");
}

// --- Acting as another user ---------------------------------------------------

pub fn select(f: Form) void {
    _ = fetch.post("user/select", .{ .id = f.int("id") }) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
        return browse("");
    }
    actingChanged("You now see the panel as this user does.");
}

pub fn unselect(_: Form) void {
    _ = fetch.postRaw("user/unselect", "{}") orelse return;
    if (fetch.refused()) return;
    actingChanged("You are yourself again.");
}

/// Another user's rights apply now: its menu, its first page.
fn actingChanged(text: []const u8) void {
    login.reload();
    state.say("success", text);
    layout.reset();
    router.go("/");
}

/// The Copy button of a shown password
pub fn copy(f: Form) void {
    dom.copy(f.str("text"));
}
