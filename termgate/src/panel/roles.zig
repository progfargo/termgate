//! Roles screen (Admin): the list; the form with the rights of the role.

const std = @import("std");
const lv = @import("lvgl");
const dbm = @import("db");
const session = @import("session");
const ui = @import("../ui.zig");

const rights = dbm.rights;

const Mode = enum { list, form };
var mode: Mode = .list;
/// 0: new role
var edit_id: i64 = 0;
var pending_delete: i64 = 0;

/// Checkbox of every right in the form, in the order of rights.modules
const right_count = blk: {
    var n = 0;
    for (rights.modules) |m| n += m.actions.len;
    break :blk n;
};
var right_boxes: [right_count]?*lv.lv_obj_t = @splat(null);

pub fn reset() void {
    mode = .list;
    edit_id = 0;
}

pub fn render() void {
    switch (mode) {
        .list => renderList(),
        .form => renderForm(),
    }
}

/// For the self-test: the checkbox of module:action in the form.
pub fn rightBox(module: []const u8, action: []const u8) ?*lv.lv_obj_t {
    if (mode != .form) return null;
    var i: usize = 0;
    for (rights.modules) |m| {
        for (m.actions) |ac| {
            if (std.mem.eql(u8, m.name, module) and std.mem.eql(u8, ac.name, action)) return right_boxes[i];
            i += 1;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// List

fn renderList() void {
    const a = ui.beginPage();
    const h = ui.header(ui.content, "Roles", "A role is a set of rights. Users get their rights from the roles they are given.");
    if (session.can("role", "insert")) ui.refs.new_role_btn = ui.button(h.actions, lv.LV_SYMBOL_PLUS ++ " New", onNew, null);
    ui.flushPendingMsg();

    const list = session.rolesList(a) orelse return ui.showMsg(.warning, "The roles could not be read.");
    ui.refs.role_rows = list.len;
    if (list.len == 0) return ui.showMsg(.info, "There are no roles yet.");
    const can_update = session.can("role", "update");
    const can_delete = session.can("role", "delete");
    // The role admin: changed by the superuser only, never deleted
    const table = ui.Table.init(ui.content, &.{ "Name", "Description", "Users" }, &.{ 25, 60, 15 });
    for (list) |r| {
        const actions = table.row(&.{ ui.z(a, r.name), ui.z(a, r.description), ui.zfmt(a, "{d}", .{r.user_count}) });
        const admin = std.mem.eql(u8, r.name, "admin");
        if (can_update and (!admin or session.isSuperuser())) ui.refs.last_role_edit_btn = ui.iconButton(actions, lv.LV_SYMBOL_EDIT, onEdit, ui.idPtr(r.id), false);
        if (can_delete and !admin) ui.refs.last_role_delete_btn = ui.iconButton(actions, lv.LV_SYMBOL_TRASH, onDelete, ui.idPtr(r.id), true);
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

fn onDelete(e: ?*lv.lv_event_t) callconv(.c) void {
    const id: i64 = @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const r = session.roleGet(a, id) orelse {
        ui.setPendingMsg(.warning, "The role is not there any more.");
        return ui.rerender();
    };
    pending_delete = id;
    ui.confirm("Delete this role?", ui.z(a, r.role.name), onDeleteYes);
}

fn onDeleteYes(e: ?*lv.lv_event_t) callconv(.c) void {
    ui.closeConfirm(e);
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    if (session.roleDelete(arena.allocator(), pending_delete)) |why| ui.setPendingMsg(.warning, why) else ui.setPendingMsg(.success, "Deleted.");
    ui.rerender();
}

// ---------------------------------------------------------------------------
// Form

fn renderForm() void {
    const a = ui.beginPage();
    var role: session.RoleRow = .{ .id = 0, .name = "", .description = "", .user_count = 0 };
    var have: []const []const u8 = &.{};
    if (edit_id != 0) {
        const d = session.roleGet(a, edit_id) orelse {
            mode = .list;
            ui.setPendingMsg(.warning, "The role is not there any more.");
            return renderList();
        };
        role = d.role;
        have = d.rights;
    }
    const h = ui.formHeader(ui.content, if (edit_id == 0) "New role" else "Edit role", onBack);
    const c = h.card;
    ui.refs.role_name_ta = ui.field(c, a, "Name", 32, role.name, "Letters, digits, _ and -; starts with a letter");
    ui.refs.role_description_ta = ui.field(c, a, "Description", 255, role.description, null);

    // Changing a role's rights is a right of its own
    const can_rights = session.can("role", "role_right");
    right_boxes = @splat(null);
    if (can_rights) _ = ui.bold(c, "Rights");
    var i: usize = 0;
    for (rights.modules) |m| {
        if (!can_rights) break;
        const row = ui.box(c, lv.LV_FLEX_FLOW_ROW_WRAP);
        lv.lv_obj_set_style_pad_column(row, ui.dp(18), 0);
        const ml = ui.label(row, ui.z(a, m.title));
        // On a phone the module's name has a line of its own
        const narrow = lv.lv_display_get_horizontal_resolution(null) < ui.dp(600);
        lv.lv_obj_set_width(ml, if (narrow) lv.lv_pct(100) else ui.dp(130));
        if (narrow) lv.lv_obj_set_style_text_color(ml, lv.lv_color_hex(ui.color_dim), 0);
        for (m.actions) |ac| {
            right_boxes[i] = ui.checkbox(row, ui.z(a, ac.title), rights.has(have, m.name, ac.name));
            i += 1;
        }
    }
    ui.refs.role_save_btn = ui.formButtons(c, onSubmit, onBack);
    ui.flushPendingMsg();
}

fn onBack(_: ?*lv.lv_event_t) callconv(.c) void {
    mode = .list;
    ui.rerender();
}

fn onSubmit(_: ?*lv.lv_event_t) callconv(.c) void {
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var list: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    for (rights.modules) |m| {
        for (m.actions) |ac| {
            if (right_boxes[i] != null and ui.isChecked(right_boxes[i])) list.append(a, std.fmt.allocPrint(a, "{s}:{s}", .{ m.name, ac.name }) catch continue) catch {};
            i += 1;
        }
    }
    // Without the right to change rights, they are not sent (and stay)
    const send_rights: ?[]const []const u8 = if (session.can("role", "role_right")) list.items else null;
    const name = std.mem.trim(u8, ui.taText(ui.refs.role_name_ta), " ");
    if (name.len == 0) return ui.showMsg(.warning, "Give the role a name.");
    if (session.roleSave(a, edit_id, name, ui.taText(ui.refs.role_description_ta), send_rights)) |why| return ui.showMsg(.warning, why);
    ui.setPendingMsg(.success, "Saved.");
    mode = .list;
    // The user's own rights may have changed
    ui.reloadRights();
    ui.rerender();
}
