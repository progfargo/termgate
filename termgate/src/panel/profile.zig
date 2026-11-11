//! Profile screen: the signed-in user's own name and roles, and changing
//! its own password (giving the current one), as in another earlier project and
//! our earlier project. While acting as another user it is that user's profile.

const std = @import("std");
const lv = @import("lvgl");
const session = @import("session");
const ui = @import("../ui.zig");

pub fn render() void {
    const a = ui.beginPage();
    const h = ui.header(ui.content, "Profile", "Your own user.");
    _ = h;
    const c = ui.card(ui.content);
    _ = ui.bold(c, ui.z(a, session.name()));
    if (session.isSuperuser()) _ = ui.muted(c, "Superuser: has every right.");
    if (session.actingFor()) |real| _ = ui.muted(c, ui.zfmt(a, "You are signed in as {s} and act as this user.", .{real}));

    if (session.can("profile", "update_password")) {
        const pc = ui.card(ui.content);
        _ = ui.bold(pc, "Change password");
        ui.refs.profile_current_ta = passwordField(pc, a, "Current password", null);
        ui.refs.profile_new_ta = passwordField(pc, a, "New password", "At least 8 characters.");
        ui.refs.profile_new2_ta = passwordField(pc, a, "New password again", null);
        ui.refs.profile_password_btn = ui.formButtons(pc, onPassword, null);
    }
    ui.flushPendingMsg();
}

fn passwordField(parent: ?*lv.lv_obj_t, a: std.mem.Allocator, name: [*:0]const u8, help: ?[*:0]const u8) ?*lv.lv_obj_t {
    const ta = ui.field(parent, a, name, 128, "", help);
    lv.lv_textarea_set_password_mode(ta, true);
    return ta;
}

fn onPassword(_: ?*lv.lv_event_t) callconv(.c) void {
    var arena: std.heap.ArenaAllocator = .init(ui.gpa);
    defer arena.deinit();
    const failed = session.changePassword(
        arena.allocator(),
        ui.taText(ui.refs.profile_current_ta),
        ui.taText(ui.refs.profile_new_ta),
        ui.taText(ui.refs.profile_new2_ta),
    );
    if (failed) |why| return ui.showMsg(.warning, why);
    ui.setPendingMsg(.success, "Your password has been changed.");
    ui.rerender();
}
