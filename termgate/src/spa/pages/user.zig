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
const combo = @import("../content/combo.zig");
const CargoList = @import("../lib/cargo.zig").CargoList;
const Form = @import("../form.zig").Form;

const RoleRef = struct { id: i64, name: []const u8 };
/// A user's terminal access (tgterm)
const Terminal = struct {
    user_key: ?[]const u8 = null,
    max_uses: ?i64 = null,
    expires: ?i64 = null,
    revoked: bool = false,
    created: i64 = 0,
    uses: i64 = 0,
};
const User = struct { id: i64, name: []const u8, superuser: bool = false, disabled: bool = false, second_step: bool = false, created: i64 = 0, nodes: []const u8 = "", roles: []const RoleRef = &.{}, terminal: ?Terminal = null };
const Role = struct { id: i64, name: []const u8, description: []const u8 = "", user_count: i64 = 0 };

const UserPage = struct { users: []const User = &.{}, total: i64 = 0, page: i64 = 1, pages: i64 = 1 };

/// A page of the users, by a search word, a role and a status
fn users(key: []const u8, rid: i64, stat: []const u8, page: i64) ?UserPage {
    const answer = fetch.post("user/browse", .{ .key = key, .rid = rid, .stat = stat, .pn = page }) orelse return null;
    return std.json.parseFromValueLeaky(UserPage, app.arena(), answer, .{ .ignore_unknown_fields = true }) catch null;
}

fn userById(id: i64) ?User {
    const answer = fetch.post("user/browse", .{ .id = id }) orelse return null;
    const list = fetch.fieldAs([]const User, answer, "users") orelse &.{};
    if (list.len == 1) return list[0];
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

/// The pages of a user; the button of the one shown is selected.
const Tab = enum { none, info, edit, roles, new_pass, terminal, delete };

/// A user's page: the path back (Users, the user's Info), then `title`,
/// and its toolbar.
fn recordHeader(b: *app.Buf, u: User, tab: Tab, title: []const u8) void {
    if (tab == .info) {
        content.header(b, &.{ .{ "Users", "#/user" }, .{ u.name, "" } });
    } else content.header(b, &.{ .{ "Users", "#/user" }, .{ u.name, userUrl("#/user/display", u.id) }, .{ title, "" } });
    content.commandStart(b);
    toolbar(b, u, "sm", tab);
    content.commandEnd(b);
}

/// A user's buttons, by the user's rights and the rules (nobody changes
/// the superuser, nobody deletes or acts as themselves).
fn toolbar(b: *app.Buf, u: User, size: []const u8, tab: Tab) void {
    const me = state.user.?;
    const own = std.mem.eql(u8, u.name, me.name);
    const sel = struct {
        fn f(t: Tab, want: Tab) []const u8 {
            return if (t == want) " selected" else "";
        }
    }.f;
    const Btn = struct { tab: Tab, path: []const u8, label: []const u8, title: []const u8, show: bool, class: []const u8 = "default" };
    const buttons = [_]Btn{
        .{ .tab = .info, .path = "#/user/display", .label = "Info", .title = "The user's record.", .show = true },
        .{ .tab = .edit, .path = "#/user/update", .label = "Edit", .title = "Edit record.", .show = !u.superuser and state.can("user", "update") },
        .{ .tab = .roles, .path = "#/user/role", .label = "Roles", .title = "Edit user roles.", .show = !u.superuser and state.can("user", "role_browse") },
        .{ .tab = .new_pass, .path = "#/user/update_pass", .label = "New Pass", .title = "Give the user a new password.", .show = tab != .none and !u.superuser and state.can("user", "update_pass") },
        // Only on the user's own pages, not in the list
        .{ .tab = .terminal, .path = "#/user/terminal", .label = "Access Key", .title = "A terminal access key: the user signs in to tgterm with it once.", .show = tab != .none and state.can("user", "access") },
        .{ .tab = .delete, .path = "#/user/delete", .label = "Delete", .title = "Delete record.", .show = !u.superuser and !own and state.can("user", "delete"), .class = "error" },
    };
    // Act as the user: not oneself, not a blocked user, the superuser
    // only by the superuser
    if (me.can_select and me.real == null and !own and !u.disabled and (!u.superuser or me.superuser))
        b.add("<button type=\"button\" data-action=\"userSelect\" data-id=\"{d}\" class=\"button button-default button-{s}\" title=\"See and use the panel as this user does.\">Select</button>", .{ u.id, size });
    for (buttons) |x| if (x.show)
        b.add("<a href=\"{s}\" class=\"button button-{s} button-{s}{s}\" title=\"{s}\">{s}</a>", .{ userUrl(x.path, u.id), x.class, size, sel(tab, x.tab), x.title, x.label });
}

fn status(b: *app.Buf, u: User) void {
    // Without the second step (a build for trying the panel) nobody sets it up
    if (u.disabled) content.label(b, "error", "Blocked") else if (!u.second_step and state.second_step) content.label(b, "warning", "Not signed in yet") else content.label(b, "success", "Active");
}

// --- Browse -------------------------------------------------------------------

// The list's state in the address (lib/cargo.zig): key, a search word;
// pn, the page; rid, a role; stat: active, new, blocked
var cg: CargoList = .{};
var cg_ready = false;
const cg_names = [_][]const u8{ "key", "pn", "rid", "stat" };

fn cargo() *CargoList {
    if (!cg_ready) {
        cg.addStr("key", "");
        cg.addInt("pn", 1);
        cg.addInt("rid", 0);
        cg.addStr("stat", "default");
        cg.addInt("userId", 0);
        cg_ready = true;
    }
    return &cg;
}

/// The address of a user's page (#/user/update?userId=3).
fn userUrl(path: []const u8, id: i64) []const u8 {
    const c = cargo();
    c.setInt("userId", id);
    return c.makeUrl(path, &.{"userId"});
}

/// The user of a page's address.
fn readUserId(query: []const u8) i64 {
    const c = cargo();
    c.read(query);
    return c.int("userId");
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

/// A filter was changed: the list from its first page.
pub fn filter(f: Form) void {
    const c = cargo();
    if (f.str("user-rid-select").len > 0) c.setInt("rid", f.int("user-rid-select"));
    if (f.str("user-stat-select").len > 0) c.setStr("stat", f.str("user-stat-select"));
    c.setInt("pn", 1);
    browse("");
}

/// Clear: the list without its search word and filters.
pub fn clearFilter(_: Form) void {
    cargo().clear();
    browse("");
}

pub fn browse(query: []const u8) void {
    if (!state.can("user", "browse")) return router.renderBadRequest();
    begin();
    const c = cargo();
    if (query.len > 0) c.read(query);
    state.setExternalUrl(c.makeUrl("/user", &cg_names));
    const key = c.str("key");
    const filter_role = c.int("rid");
    const filter_status = c.str("stat");
    content.search("userSearch", key);
    const page = users(key, filter_role, if (std.mem.eql(u8, filter_status, "default")) "" else filter_status, @max(1, c.int("pn"))) orelse return;
    const list = page.users;
    const all_roles = if (state.can("user", "role_browse")) roles() else &.{};
    const me = state.user.?;
    const can_select = me.can_select and me.real == null;
    const has_command = can_select or state.can("user", "update") or state.can("user", "role_browse") or state.can("user", "update_pass") or state.can("user", "access") or state.can("user", "delete");

    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Users", "" }});
    content.commandStart(&b);
    if (state.can("user", "insert")) b.raw("<a href=\"#/user/insert\" class=\"button button-default button-sm\">New</a>");
    // Each filter in a form of its own, as in our earlier project
    if (all_roles.len > 0) {
        var role_combo = combo.Combo.init("All roles");
        for (all_roles) |r| role_combo.add(r.id, r.name);
        b.add("<form class=\"form-inline\"><div class=\"form-group\"><select id=\"user-rid-select\" class=\"form-control\" data-change=\"userFilter\">{s}</select></div></form>", .{role_combo.format(filter_role)});
    }
    var stat_combo: combo.EnumCombo = .{};
    stat_combo.add("default", "All statuses");
    stat_combo.add("active", "Active");
    stat_combo.add("new", "Not signed in yet");
    stat_combo.add("blocked", "Blocked");
    b.add("<form class=\"form-inline\"><div class=\"form-group\"><select id=\"user-stat-select\" class=\"form-control\" data-change=\"userFilter\">{s}</select></div></form>", .{stat_combo.format(filter_status)});
    b.raw("<button type=\"button\" data-action=\"userClear\" class=\"button button-default button-sm\" title=\"Reset all filters.\">Clear</button>");
    content.commandEnd(&b);

    content.contentStart(&b);
    b.raw("<table><thead><tr><th>Name</th><th class=\"center\">Status</th><th>Roles</th><th class=\"center\">Access Key</th>");
    if (has_command) b.raw("<th class=\"right\">Command</th>");
    b.raw("</tr></thead><tbody>");
    var shown: usize = 0;
    for (list) |u| {
        shown += 1;
        b.add("<tr><td><a href=\"{s}\">", .{userUrl("#/user/display", u.id)});
        content.find(&b, u.name, key);
        b.raw("</a></td><td class=\"center\">");
        status(&b, u);
        b.raw("</td><td>");
        if (u.superuser) content.label(&b, "primary", "superuser");
        for (u.roles, 0..) |r, i| b.add("{s}{f}", .{ if (i > 0 or u.superuser) ", " else " ", app.esc(r.name) });
        b.raw("</td><td class=\"center\">");
        terminalLabel(&b, u.terminal);
        b.raw("</td>");
        if (has_command) {
            b.raw("<td class=\"right\"><div class=\"button-group-fixed\">");
            toolbar(&b, u, "xs", .none);
            b.raw("</div></td>");
        }
        b.raw("</tr>");
    }
    if (shown == 0) b.add("<tr><td colspan=\"{d}\">Empty list.</td></tr>", .{@as(u8, if (has_command) 5 else 4)});
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.ruler(&b, page.pages, page.page, "userGoPage");
    show(&b);
}

// --- Insert -------------------------------------------------------------------

/// The user of the page shown
var edit_id: i64 = 0;

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
    content.field(&b, "user-name-input", "Name:", name, .{ .required = true, .max = 32, .help = "Lowercase letters, digits, _ . -; starts with a letter." });
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
    const password = fetch.fieldAs([]const u8, answer, "password") orelse "";
    const u = userById(fetch.fieldAs(i64, answer, "id") orelse 0) orelse return;
    showPassword(u, password, .none);
}

/// The new password, once; then the user's roles.
fn showPassword(u: User, password: []const u8, tab: Tab) void {
    const id = u.id;
    var b: app.Buf = .{};
    recordHeader(&b, u, tab, "Password");
    content.contentStart(&b);
    b.raw("<p>Shown once. Hand it over yourself: termgate sends no e-mail. At the next sign-in the user sets up its second step (authenticator app).</p>");
    b.add("<p><strong id=\"user-password\">{f}</strong></p>", .{app.esc(password)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"copy\" data-text=\"{f}\" class=\"button button-default button-sm\"><i class=\"fa fa-copy\"></i> Copy</button>", .{app.esc(password)});
    if (state.can("user", "role_browse")) b.add("<a href=\"{s}\" class=\"button button-primary button-sm\">Roles</a>", .{userUrl("#/user/role", id)});
    b.add("<a href=\"{s}\" class=\"button button-default button-sm\">Done</a>", .{userUrl("#/user/display", id)});
    content.commandEnd(&b);
    show(&b);
}

// --- Info ---------------------------------------------------------------------

pub fn display(query: []const u8) void {
    if (!state.can("user", "browse")) return router.renderBadRequest();
    begin();
    edit_id = readUserId(query);
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, u, .info, "");
    content.contentStart(&b);
    b.add("<table><tbody><tr><th class=\"fixed-middle\">Name:</th><td>{f}</td></tr><tr><th>Status:</th><td>", .{app.esc(u.name)});
    status(&b, u);
    b.raw("</td></tr><tr><th>Roles:</th><td>");
    if (u.superuser) content.label(&b, "primary", "superuser");
    for (u.roles, 0..) |r, i| b.add("{s}{f}", .{ if (i > 0 or u.superuser) ", " else " ", app.esc(r.name) });
    b.add("</td></tr><tr><th>Nodes:</th><td>{f}</td></tr><tr><th>Access Key:</th><td>", .{app.esc(if (u.nodes.len > 0) u.nodes else "-")});
    terminalLabel(&b, u.terminal);
    b.add("</td></tr><tr><th>Added:</th><td>{s}</td></tr></tbody></table>", .{content.dateTime(u.created)});
    content.contentEnd(&b);
    show(&b);
}

// --- Update -------------------------------------------------------------------

pub fn update(query: []const u8) void {
    if (!state.can("user", "update")) return router.renderBadRequest();
    begin();
    edit_id = readUserId(query);
    const u = userById(edit_id) orelse return;
    renderUpdate(u, u.name, u.disabled, u.nodes);
}

fn renderUpdate(u: User, name: []const u8, disabled: bool, nodes: []const u8) void {
    const own = std.mem.eql(u8, u.name, state.user.?.name);
    var b: app.Buf = .{};
    recordHeader(&b, u, .edit, "Edit");
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "user-name-input", "Name:", name, .{ .required = true, .max = 32, .help = "Lowercase letters, digits, _ . -; starts with a letter." });
    // Nobody blocks themselves
    if (!own) content.checkbox(&b, "user-blocked-input", "Blocked: cannot sign in", disabled);
    content.field(&b, "user-nodes-input", "Nodes:", nodes, .{ .max = 255, .help = "The nodes this user may reach with tgterm: names or patterns, comma separated: ist_*, pump?? (* any, ? one character). Empty: none." });
    b.add("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"userUpdate\" class=\"button button-primary button-sm\">Submit</button> <a href=\"{s}\" class=\"button button-default button-sm\">Cancel</a></div></div>", .{userUrl("#/user/display", u.id)});
    b.raw("</form>");
    content.contentEnd(&b);
    show(&b);
}

pub fn submitUpdate(f: Form) void {
    const name = f.trimmed("user-name-input");
    const blocked = f.checked("user-blocked-input");
    // "ist_*, pump??": the patterns without spaces
    var nodes: std.ArrayList(u8) = .empty;
    for (f.trimmed("user-nodes-input")) |ch| if (ch != ' ') nodes.append(app.arena(), ch) catch {};
    _ = fetch.post("user/update", .{ .id = edit_id, .name = name, .disabled = blocked, .nodes = nodes.items }) orelse return;
    if (fetch.refused()) return renderUpdate(userById(edit_id) orelse return, name, blocked, nodes.items);
    // The name in the menu may be this user's
    login.reload();
    state.say("success", "Record has been changed.");
    router.go("/user");
}

// --- Roles --------------------------------------------------------------------

pub fn role(query: []const u8) void {
    if (!state.can("user", "role_browse")) return router.renderBadRequest();
    begin();
    edit_id = readUserId(query);
    renderRoles();
}

fn renderRoles() void {
    const u = userById(edit_id) orelse return;
    const all = roles();
    var b: app.Buf = .{};
    recordHeader(&b, u, .roles, "Roles");
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
        // A form as the others: the field, then the button under it
        b.raw("<div class=\"row row-content\"><div class=\"col\"><form><div class=\"form-group\"><label class=\"required\">Role:</label><select id=\"user-role-select\" class=\"form-control\"><option value=\"0\">Select a role</option>");
        for (all) |r| {
            var has = false;
            for (u.roles) |x| has = has or x.id == r.id;
            if (!has) b.add("<option value=\"{d}\">{f}</option>", .{ r.id, app.esc(r.name) });
        }
        b.raw("</select></div><div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"userRoleGrant\" class=\"button button-primary button-sm\">Grant</button></div></div></form></div></div>");
    }
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
    edit_id = readUserId(query);
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, u, .new_pass, "New Password");
    content.contentStart(&b);
    b.add("<p>Give <strong>{f}</strong> a new password? Its sessions end, and it sets up the second step again at the next sign-in.</p>", .{app.esc(u.name)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"userUpdatePass\" class=\"button button-warning button-sm\">Yes</button><a href=\"{s}\" class=\"button button-default button-sm\">Cancel</a>", .{userUrl("#/user/display", u.id)});
    content.commandEnd(&b);
    show(&b);
}

pub fn submitUpdatePass(_: Form) void {
    const answer = fetch.post("user/update_pass", .{ .id = edit_id }) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
        return router.go("/user");
    }
    const password = fetch.fieldAs([]const u8, answer, "password") orelse "";
    showPassword(userById(edit_id) orelse return, password, .new_pass);
}

// --- Delete -------------------------------------------------------------------

pub fn delete(query: []const u8) void {
    if (!state.can("user", "delete")) return router.renderBadRequest();
    begin();
    edit_id = readUserId(query);
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, u, .delete, "Delete");
    content.contentStart(&b);
    b.raw("<p>Delete this user?</p><table><tbody>");
    b.add("<tr><th class=\"fixed-middle\">Name:</th><td>{f}</td></tr><tr><th>Status:</th><td>", .{app.esc(u.name)});
    status(&b, u);
    b.raw("</td></tr><tr><th>Roles:</th><td>");
    for (u.roles, 0..) |r, i| b.add("{s}{f}", .{ if (i > 0) ", " else "", app.esc(r.name) });
    b.raw("</td></tr></tbody></table>");
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"userDelete\" class=\"button button-error button-sm\">Yes</button><a href=\"{s}\" class=\"button button-default button-sm\">Cancel</a>", .{userUrl("#/user/display", u.id)});
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

// --- Terminal access ----------------------------------------------------------------

/// The state of a user's terminal access, as a label.
fn terminalLabel(b: *app.Buf, t: ?Terminal) void {
    const x = t orelse return b.raw("-");
    if (x.revoked) return content.label(b, "error", "revoked");
    if (x.user_key != null) return content.label(b, "success", "active");
    if (x.expires) |e| if (e <= app.now()) return content.label(b, "warning", "key expired");
    content.label(b, "primary", "key not used yet");
}

pub fn terminal(query: []const u8) void {
    if (!state.can("user", "access")) return router.renderBadRequest();
    begin();
    edit_id = readUserId(query);
    renderTerminal(.{});
}

const KeyForm = struct { uses: []const u8 = "", days: []const u8 = "" };

fn renderTerminal(form: KeyForm) void {
    const u = userById(edit_id) orelse return;
    var b: app.Buf = .{};
    recordHeader(&b, u, .terminal, "Access Key");
    content.contentStart(&b);
    b.raw("<p>Terminal access: this user connects with tgterm, like ssh, to its nodes (Edit). It also needs a role with the right terminal:connect (such as terminal_user).</p>");
    if (u.terminal) |t| {
        b.raw("<table><tbody><tr><th class=\"fixed-middle\">State:</th><td>");
        terminalLabel(&b, t);
        b.add("</td></tr><tr><th>Nodes:</th><td>{f}</td></tr>", .{app.esc(if (u.nodes.len > 0) u.nodes else "- (set them with Edit)")});
        b.add("<tr><th>Sessions:</th><td>{d} used", .{t.uses});
        if (t.max_uses) |m| b.add(" of {d}", .{m});
        b.raw("</td></tr>");
        if (t.expires) |e| b.add("<tr><th>Until:</th><td>{s} UTC</td></tr>", .{content.dateTime(e)});
        if (t.user_key) |k| b.add("<tr><th>Key:</th><td><small>{f}</small></td></tr>", .{app.esc(k)});
        b.raw("</tbody></table>");
    } else b.raw("<p>No terminal access given yet.</p>");
    content.contentEnd(&b);
    if (u.terminal) |t| if (!t.revoked) {
        content.commandStart(&b);
        b.raw("<button type=\"button\" data-action=\"userTerminalRevoke\" class=\"button button-error button-sm\">Revoke</button>");
        content.commandEnd(&b);
    };
    // A new access key (replaces what the user had)
    b.raw("<div class=\"row row-header\"><div class=\"col\"><div class=\"page-title\"><h3>Give terminal access</h3></div></div></div>");
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "term-uses-input", "Sessions:", form.uses, .{ .max = 6, .help = "Total number of sessions the key can open; empty: no limit." });
    content.field(&b, "term-days-input", "Days:", form.days, .{ .max = 4, .help = "Valid lifetime (days) of the key; empty: no limit." });
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"userAccessKey\" class=\"button button-primary button-sm\">Make access key</button></div>");
    b.raw("<span class=\"help-block\">Give sessions, days or both.</span></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn submitAccessKey(f: Form) void {
    const form: KeyForm = .{ .uses = f.trimmed("term-uses-input"), .days = f.trimmed("term-days-input") };
    const number = struct {
        fn get(text: []const u8) error{Invalid}!?u32 {
            if (text.len == 0) return null;
            const n = std.fmt.parseInt(u32, text, 10) catch return error.Invalid;
            return if (n == 0) error.Invalid else n;
        }
    }.get;
    const uses = number(form.uses) catch {
        state.say("warning", "Sessions is a whole number above 0, or empty.");
        return renderTerminal(form);
    };
    const days = number(form.days) catch {
        state.say("warning", "Days is a whole number above 0, or empty.");
        return renderTerminal(form);
    };
    const answer = fetch.post("user/access_key", .{ .id = edit_id, .uses = uses, .days = days }) orelse return;
    if (fetch.refused()) {
        state.keepMessages();
        return renderTerminal(form);
    }
    const access_key = (fetch.fieldAs(struct { key: []const u8 }, answer, "data") orelse return).key;
    const u = userById(edit_id) orelse return;
    const command = std.fmt.allocPrint(app.arena(), "tgterm --access-key {s}", .{access_key}) catch return;
    var b: app.Buf = .{};
    recordHeader(&b, u, .terminal, "Access Key");
    content.contentStart(&b);
    b.add("<p>Shown once. Hand it to <strong>{f}</strong>: it runs this once on its own machine; tgterm makes its key there. After that \"tgterm &lt;node&gt;\" is enough.</p>", .{app.esc(u.name)});
    b.add("<pre class=\"wrap\">{f}</pre>", .{app.esc(command)});
    content.contentEnd(&b);
    content.commandStart(&b);
    b.add("<button type=\"button\" data-action=\"copy\" data-text=\"{f}\" class=\"button button-default button-sm\"><i class=\"fa fa-copy\"></i> Copy</button>", .{app.esc(command)});
    b.add("<a href=\"{s}\" class=\"button button-default button-sm\">Done</a>", .{userUrl("#/user/terminal", edit_id)});
    content.commandEnd(&b);
    content.show(&b);
}

pub fn submitTerminalRevoke(_: Form) void {
    _ = fetch.post("user/terminal_revoke", .{ .id = edit_id }) orelse return;
    if (fetch.refused()) state.keepMessages() else state.say("success", "Terminal access has been revoked; its connections are closed.");
    renderTerminal(.{});
}

/// The Copy button of a shown password
pub fn copy(f: Form) void {
    dom.copy(f.str("text"));
}
