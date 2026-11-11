//! Users screen (Admin): the list; the form of a user with its roles; the
//! password shown once after a user is made or gets a new one; acting as
//! another user.
//!
//! termgate makes the passwords and whoever made the user hands it over:
//! there is no sign-up and termgate sends no e-mail. Each operation has its
//! own right, as in our earlier project; the superuser cannot be changed here.

const std = @import("std");
const lv = @import("lvgl");
const session = @import("session");
const ui = @import("../ui.zig");

const Mode = enum { list, form, password };
var mode: Mode = .list;
/// 0: new user
var edit_id: i64 = 0;
var pending_delete: i64 = 0;
var blocked_cb: ?*lv.lv_obj_t = null;
/// The roles in the form's dropdown, in its order
var offered: [64]i64 = undefined;
var offered_count: usize = 0;

/// The user and password shown once
var shown_name: [40]u8 = undefined;
var shown_name_len: usize = 0;
var shown_password: [40]u8 = undefined;
var shown_password_len: usize = 0;

pub fn reset() void {
    mode = .list;
    edit_id = 0;
    shown_password_len = 0;
}

pub fn render() void {
    switch (mode) {
        .list => renderList(),
        .form => renderForm(),
        .password => renderPassword(),
    }
}

// ---------------------------------------------------------------------------
// List

fn renderList() void {
    const a = ui.beginPage();
    const h = ui.header(ui.content, "Users", "Who may sign in to this panel. What each may do comes from its roles.");
    if (session.can("user", "insert")) ui.refs.new_user_btn = ui.button(h.actions, lv.LV_SYMBOL_PLUS ++ " New", onNew, null);
    ui.flushPendingMsg();

    const list = session.usersList(a) orelse return ui.showMsg(.warning, "The users could not be read.");
    ui.refs.user_rows = list.len;
    const can_open = session.can("user", "update") or session.can("user", "update_pass") or
        session.can("user", "role_browse") or session.can("user", "role_grant") or session.can("user", "role_revoke");
    const can_delete = session.can("user", "delete");
    // Acting as another user starts from one's own user
    const can_act = session.canSelect() and session.actingFor() == null;
    const table = ui.Table.init(ui.content, &.{ "Name", "Roles", "Status" }, &.{ 30, 40, 30 });
    for (list) |u| {
        var roles: std.ArrayList(u8) = .empty;
        if (u.superuser) roles.appendSlice(a, "superuser") catch {};
        for (u.roles) |r| {
            if (roles.items.len > 0) roles.appendSlice(a, ", ") catch {};
            roles.appendSlice(a, r.name) catch {};
        }
        const status: [*:0]const u8 = if (u.disabled) "blocked" else if (!u.second_step) "has not signed in yet" else "active";
        const actions = table.row(&.{ ui.z(a, u.name), ui.z(a, if (roles.items.len > 0) roles.items else "-"), status });
        if (can_open) {
            const b = ui.iconButton(actions, lv.LV_SYMBOL_EDIT, onEdit, ui.idPtr(u.id), false);
            if (ui.refs.first_user_edit_btn == null) ui.refs.first_user_edit_btn = b;
            ui.refs.last_user_edit_btn = b;
        }
        const own = std.mem.eql(u8, u.name, session.name());
        // Act as this user: not oneself, not a blocked user, and the
        // superuser only by the superuser
        if (can_act and !own and !u.disabled and (!u.superuser or session.isSuperuser()))
            ui.refs.last_user_select_btn = ui.iconButton(actions, lv.LV_SYMBOL_EYE_OPEN, onSelect, ui.idPtr(u.id), false);
        // Not the superuser, and nobody deletes themselves
        if (can_delete and !u.superuser and !own)
            ui.refs.last_user_delete_btn = ui.iconButton(actions, lv.LV_SYMBOL_TRASH, onDelete, ui.idPtr(u.id), true);
    }
}

fn onNew(_: ?*lv.lv_event_t) callconv(.c) void {
    edit_id = 0;
    mode = .form;
    ui.rerender();
}

fn onEdit(e: ?*lv.lv_event_t) callconv(.c) void {
    edit_id = @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
    mode = .form;
    ui.rerender();
}

fn onSelect(e: ?*lv.lv_event_t) callconv(.c) void {
    const id: i64 = @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    if (session.userSelect(arena.allocator(), id)) |why| return ui.showMsg(.warning, why);
    // From now on the panel is that user's: its menu, its rights
    ui.actingChanged();
}

fn onDelete(e: ?*lv.lv_event_t) callconv(.c) void {
    const id: i64 = @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const u = session.userGet(a, id) orelse {
        ui.setPendingMsg(.warning, "The user is not there any more.");
        return ui.rerender();
    };
    pending_delete = id;
    ui.confirm("Delete this user?", ui.z(a, u.name), onDeleteYes);
}

fn onDeleteYes(e: ?*lv.lv_event_t) callconv(.c) void {
    ui.closeConfirm(e);
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    if (session.userDelete(arena.allocator(), pending_delete)) |why| ui.setPendingMsg(.warning, why) else ui.setPendingMsg(.success, "Deleted.");
    ui.rerender();
}

// ---------------------------------------------------------------------------
// Form

fn renderForm() void {
    const a = ui.beginPage();
    blocked_cb = null;
    var user: session.UserRow = .{ .id = 0, .name = "", .superuser = false, .disabled = false, .second_step = false, .created = 0, .roles = &.{} };
    if (edit_id != 0) {
        user = session.userGet(a, edit_id) orelse {
            mode = .list;
            ui.setPendingMsg(.warning, "The user is not there any more.");
            return renderList();
        };
    }
    const own = edit_id != 0 and std.mem.eql(u8, user.name, session.name());
    const h = ui.formHeader(ui.content, if (edit_id == 0) "New user" else "Edit user", onBack);
    const c = h.card;
    if (user.superuser) {
        // Nobody changes the superuser: not its name, password or roles
        _ = ui.bold(c, ui.z(a, user.name));
        _ = ui.muted(c, "The superuser has every right. Nobody can change, block or delete it, give it a new password or change its roles; it changes its own password in its profile.");
        ui.flushPendingMsg();
        return;
    }
    ui.refs.user_name_ta = ui.field(c, a, "Name", 32, user.name, "Lowercase letters, digits, _ . -; starts with a letter");
    if (edit_id == 0) {
        _ = ui.muted(c, "termgate makes a password; you hand it over. The user sets up the second step at the first sign-in.");
    } else if (!own) {
        // Nobody blocks themselves
        blocked_cb = ui.checkbox(c, "Blocked: cannot sign in", user.disabled);
    }
    if (edit_id == 0 or session.can("user", "update")) ui.refs.user_create_btn = ui.formButtons(c, onSubmit, onBack);
    ui.flushPendingMsg();
    if (edit_id == 0) return;

    if (session.can("user", "update_pass")) {
        const pc = ui.card(ui.content);
        _ = ui.bold(pc, "Password");
        _ = ui.muted(pc, "A new password ends the user's sessions; the second step is set up again at the next sign-in.");
        const row = ui.box(pc, lv.LV_FLEX_FLOW_ROW);
        _ = ui.outlineButton(row, "New password", onNewPassword, null, false);
    }
    renderRoles(a, user);
}

/// The roles of the user, and giving one more.
fn renderRoles(a: std.mem.Allocator, user: session.UserRow) void {
    // The user's roles are shown to who may see them, given and taken by
    // who may do that
    const can_see = session.can("user", "role_browse");
    const can_grant = session.can("user", "role_grant");
    const can_revoke = session.can("user", "role_revoke");
    if (!can_see and !can_grant) return;
    const c = ui.card(ui.content);
    _ = ui.bold(c, "Roles");
    ui.refs.user_roles = user.roles.len;
    if (can_see) {
        if (user.roles.len == 0) _ = ui.muted(c, "No roles: this user may sign in but do nothing.");
        for (user.roles) |r| {
            const row = ui.box(c, lv.LV_FLEX_FLOW_ROW);
            const l = ui.label(row, ui.z(a, r.name));
            lv.lv_obj_set_width(l, 1);
            lv.lv_obj_set_flex_grow(l, 1);
            if (can_revoke) _ = ui.iconButton(row, lv.LV_SYMBOL_CLOSE, onRevoke, ui.idPtr(r.id), true);
        }
    }
    if (!can_grant) return;
    // The roles the user does not have yet
    const all = session.rolesList(a) orelse return;
    var names: std.ArrayList([]const u8) = .empty;
    offered_count = 0;
    for (all) |r| {
        var has = false;
        for (user.roles) |x| has = has or x.id == r.id;
        if (has or offered_count == offered.len) continue;
        offered[offered_count] = r.id;
        offered_count += 1;
        names.append(a, r.name) catch {};
    }
    if (offered_count == 0) return;
    const row = ui.box(c, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_top(row, ui.dp(6), 0);
    ui.refs.user_role_dd = ui.dropdown(row, names.items, 0);
    lv.lv_obj_set_width(ui.refs.user_role_dd, ui.dp(200));
    ui.refs.user_grant_btn = ui.outlineButton(row, "Give role", onGrant, null, false);
}

fn onBack(_: ?*lv.lv_event_t) callconv(.c) void {
    reset();
    ui.rerender();
}

fn onSubmit(_: ?*lv.lv_event_t) callconv(.c) void {
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const name = std.mem.trim(u8, ui.taText(ui.refs.user_name_ta), " ");
    if (edit_id == 0) {
        switch (session.userCreate(a, name)) {
            .password => |p| {
                // Shown once; then the new user's form, to give it roles
                edit_id = p.id;
                showPassword(name, p.text);
            },
            .failed => |why| return ui.showMsg(.warning, why),
        }
        return ui.rerender();
    }
    if (session.userUpdate(a, edit_id, name, if (blocked_cb) |cb| ui.isChecked(cb) else false)) |why| return ui.showMsg(.warning, why);
    ui.setPendingMsg(.success, "Saved.");
    mode = .list;
    // The name shown at the top right may be this user's
    ui.reloadRights();
    ui.rerender();
}

fn onNewPassword(_: ?*lv.lv_event_t) callconv(.c) void {
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    switch (session.userReset(arena.allocator(), edit_id)) {
        .password => |p| showPassword(p.name, p.text),
        .failed => |why| return ui.showMsg(.warning, why),
    }
    ui.rerender();
}

fn onGrant(_: ?*lv.lv_event_t) callconv(.c) void {
    const i = ui.selected(ui.refs.user_role_dd);
    if (i >= offered_count) return;
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    afterRoleChange(session.userGrant(arena.allocator(), edit_id, offered[i]), "Role given.");
}

fn onRevoke(e: ?*lv.lv_event_t) callconv(.c) void {
    const role: i64 = @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    afterRoleChange(session.userRevoke(arena.allocator(), edit_id, role), "Role taken.");
}

fn afterRoleChange(failed: ?[]const u8, done: []const u8) void {
    if (failed) |why| ui.setPendingMsg(.warning, why) else ui.setPendingMsg(.success, done);
    // The user's own rights may have changed
    ui.reloadRights();
    ui.rerender();
}

// ---------------------------------------------------------------------------
// The password, shown once

fn showPassword(name: []const u8, password: []const u8) void {
    shown_name_len = @min(name.len, shown_name.len);
    @memcpy(shown_name[0..shown_name_len], name[0..shown_name_len]);
    shown_password_len = @min(password.len, shown_password.len);
    @memcpy(shown_password[0..shown_password_len], password[0..shown_password_len]);
    mode = .password;
}

fn renderPassword() void {
    const a = ui.beginPage();
    _ = ui.header(ui.content, ui.zfmt(a, "Password for {s}", .{shown_name[0..shown_name_len]}), "Shown once. Hand it over yourself: termgate sends no e-mail.");
    const c = ui.card(ui.content);
    const pw = ui.label(c, ui.z(a, shown_password[0..shown_password_len]));
    lv.lv_obj_set_style_text_font(pw, ui.font_title, 0);
    lv.lv_obj_set_style_text_color(pw, lv.lv_color_hex(ui.color_primary), 0);
    ui.refs.code_label = pw;
    _ = ui.muted(c, "At the next sign-in the user sets up its second step (authenticator app).");
    const row = ui.box(c, lv.LV_FLEX_FLOW_ROW);
    _ = ui.button(row, lv.LV_SYMBOL_COPY ++ " Copy", onCopyPassword, null);
    ui.refs.done_btn = ui.outlineButton(row, "Done", onPasswordDone, null, false);
}

fn onCopyPassword(_: ?*lv.lv_event_t) callconv(.c) void {
    var buf: [48]u8 = undefined;
    const t = std.fmt.bufPrintSentinel(&buf, "{s}", .{shown_password[0..shown_password_len]}, 0) catch return;
    if (ui.copy_text) |f| f(t.ptr);
}

/// Back to the user's form: a new user gets its roles there.
fn onPasswordDone(_: ?*lv.lv_event_t) callconv(.c) void {
    shown_password_len = 0;
    mode = .form;
    ui.rerender();
}
