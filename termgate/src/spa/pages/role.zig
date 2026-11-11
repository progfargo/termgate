//! Roles (#/role), as our earlier project's role pages: the list; New; Edit (name
//! and description); Role Rights (a table per page with All, None,
//! Reverse); Delete (asks first). The role admin is changed by the
//! superuser only and never deleted; the server keeps that too.

const std = @import("std");
const rights = @import("rights");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const login = @import("login.zig");
const Form = @import("../form.zig").Form;

const Role = struct { id: i64, name: []const u8, description: []const u8 = "", user_count: i64 = 0 };

fn roles() ?[]const Role {
    const answer = fetch.postRaw("role/browse", "{}") orelse return null;
    return fetch.fieldAs([]const Role, answer, "roles");
}

/// A role and its rights.
fn get(id: i64) ?struct { role: Role, rights: []const []const u8 } {
    const answer = fetch.post("role/get", .{ .id = id }) orelse return null;
    const role = fetch.fieldAs(Role, answer, "role") orelse {
        router.renderNotFound();
        return null;
    };
    return .{ .role = role, .rights = fetch.fieldAs([]const []const u8, answer, "rights") orelse &.{} };
}

/// Only the superuser changes the role admin
fn changeable(r: Role) bool {
    return !std.mem.eql(u8, r.name, "admin") or (state.user != null and state.user.?.superuser);
}

fn begin() void {
    dom.setBodyId("");
    layout.renderDefault("role");
}

// --- Browse -------------------------------------------------------------------

pub fn browse(_: []const u8) void {
    if (!state.can("role", "browse")) return router.renderBadRequest();
    begin();
    const list = roles() orelse return;
    const can_update = state.can("role", "update");
    const can_right = state.can("role", "role_right");
    const can_delete = state.can("role", "delete");
    const has_command = can_update or can_right or can_delete;

    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Roles", "" }});
    if (state.can("role", "insert")) {
        content.commandStart(&b);
        b.raw("<a href=\"#/role/insert\" class=\"button button-default button-sm\">New</a>");
        content.commandEnd(&b);
    }
    content.contentStart(&b);
    b.raw("<table><thead><tr><th>Role Name</th><th>Explanation</th><th>Users</th>");
    if (has_command) b.raw("<th class=\"right\">Command</th>");
    b.raw("</tr></thead><tbody>");
    if (list.len == 0) b.raw("<tr><td colspan=\"4\">Empty list.</td></tr>");
    for (list) |r| {
        b.add("<tr><td>{f}</td><td>{f}</td><td>{d}</td>", .{ app.esc(r.name), app.esc(r.description), r.user_count });
        if (has_command) {
            b.raw("<td class=\"right\"><div class=\"button-group-fixed\">");
            if (changeable(r)) {
                if (can_update) b.add("<a href=\"#/role/update?roleId={d}\" class=\"button button-default button-xs\">Edit</a>", .{r.id});
                if (can_right) b.add("<a href=\"#/role/right?roleId={d}\" class=\"button button-default button-xs\">Role Rights</a>", .{r.id});
            }
            if (can_delete and !std.mem.eql(u8, r.name, "admin")) b.add("<a href=\"#/role/delete?roleId={d}\" class=\"button button-error button-xs\">Delete</a>", .{r.id});
            b.raw("</div></td>");
        }
        b.raw("</tr>");
    }
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.show(&b);
}

// --- Insert and update ----------------------------------------------------------

var edit_id: i64 = 0;

pub fn insert(_: []const u8) void {
    if (!state.can("role", "insert")) return router.renderBadRequest();
    begin();
    edit_id = 0;
    renderForm("", "");
}

pub fn update(query: []const u8) void {
    if (!state.can("role", "update")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "roleId");
    const r = get(edit_id) orelse return;
    renderForm(r.role.name, r.role.description);
}

fn renderForm(name: []const u8, description: []const u8) void {
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Roles", "#/role" }, .{ if (edit_id == 0) "New Record" else "Edit Record", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "role-name-input", "Role Name:", name, .{ .required = true, .max = 32, .help = "Letters, digits, _ and -; starts with a letter." });
    content.field(&b, "role-exp-input", "Explanation:", description, .{ .max = 255 });
    b.add("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"{s}\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/role\" class=\"button button-default button-sm\">Cancel</a></div></div>", .{if (edit_id == 0) "roleInsert" else "roleUpdate"});
    b.raw("</form>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn submitInsert(f: Form) void {
    const name = f.trimmed("role-name-input");
    const description = f.trimmed("role-exp-input");
    const answer = fetch.post("role/insert", .{ .name = name, .description = description }) orelse return;
    if (fetch.refused()) return renderForm(name, description);
    state.say("success", "Record has been saved.");
    // Its rights next, for who may set them
    const id = fetch.fieldAs(i64, answer, "id") orelse 0;
    if (state.can("role", "role_right") and id != 0) return router.go(std.fmt.allocPrint(app.arena(), "/role/right?roleId={d}", .{id}) catch "/role");
    router.go("/role");
}

pub fn submitUpdate(f: Form) void {
    const name = f.trimmed("role-name-input");
    const description = f.trimmed("role-exp-input");
    // Without rights: they stay as they are
    _ = fetch.post("role/update", .{ .id = edit_id, .name = name, .description = description }) orelse return;
    if (fetch.refused()) return renderForm(name, description);
    state.say("success", "Record has been changed.");
    router.go("/role");
}

// --- Rights -------------------------------------------------------------------

pub fn right(query: []const u8) void {
    if (!state.can("role", "role_right")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "roleId");
    const r = get(edit_id) orelse return;
    if (!changeable(r.role)) return router.renderBadRequest();
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Roles", "#/role" }, .{ r.role.name, "" }, .{ "Role Rights", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    for (rights.modules) |m| {
        b.add("<table><thead><tr class=\"role-header\"><th>{s}</th><th><div class=\"button-group-fixed\">", .{m.title});
        b.raw("<button type=\"button\" class=\"select-all button button-default button-xs\">All</button><button type=\"button\" class=\"select-none button button-default button-xs\">None</button><button type=\"button\" class=\"select-reverse button button-default button-xs\">Reverse</button>");
        b.raw("</div></th></tr></thead><tbody><tr><th>Right Name</th><th>Right</th></tr>");
        for (m.actions) |ac| {
            const on = rights.has(r.rights, m.name, ac.name);
            b.add("<tr><td><label><input type=\"checkbox\" name=\"right\" value=\"{s}:{s}\"{s}><span class=\"radio-label\">{s}</span></label></td><td>{s}:{s}</td></tr>", .{ m.name, ac.name, if (on) " checked" else "", ac.title, m.name, ac.name });
        }
        b.raw("</tbody></table>");
    }
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"roleRightUpdate\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/role\" class=\"button button-default button-sm\">Cancel</a></div></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn submitRight(f: Form) void {
    _ = fetch.post("role/right_update", .{ .id = edit_id, .rights = f.list("right") }) orelse return;
    if (fetch.refused()) state.keepMessages() else state.say("success", "Role rights have been changed.");
    // One's own rights may have changed
    login.reload();
    layout.reset();
    router.go("/role");
}

// --- Delete -------------------------------------------------------------------

pub fn delete(query: []const u8) void {
    if (!state.can("role", "delete")) return router.renderBadRequest();
    begin();
    edit_id = app.queryInt(query, "roleId");
    const r = get(edit_id) orelse return;
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Roles", "#/role" }, .{ "Delete Record", "" } });
    content.contentStart(&b);
    b.raw("<p>Delete this role?</p><table><tbody>");
    b.add("<tr><th class=\"fixed-middle\">Role Name:</th><td>{f}</td></tr><tr><th>Explanation:</th><td>{f}</td></tr><tr><th>Users:</th><td>{d}</td></tr>", .{ app.esc(r.role.name), app.esc(r.role.description), r.role.user_count });
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.commandStart(&b);
    b.raw("<button type=\"button\" data-action=\"roleDelete\" class=\"button button-error button-sm\">Yes</button><a href=\"#/role\" class=\"button button-default button-sm\">Cancel</a>");
    content.commandEnd(&b);
    content.show(&b);
}

pub fn submitDelete(_: Form) void {
    _ = fetch.post("role/delete", .{ .id = edit_id }) orelse return;
    if (fetch.refused()) state.keepMessages() else state.say("success", "Record has been deleted.");
    router.go("/role");
}
