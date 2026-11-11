//! Configuration screen (Admin): where the relay is, and the settings of
//! sessions and their logs.

const std = @import("std");
const lv = @import("lvgl");
const dbm = @import("db");
const session = @import("session");
const ui = @import("../ui.zig");

pub fn render() void {
    const a = ui.beginPage();
    _ = ui.header(ui.content, "Configuration", "The relay nodes and users connect to, and how long sessions and their logs are kept.");

    const rc = ui.card(ui.content);
    _ = ui.title(rc, "Relay");
    if (ui.relayInfo()) |r| {
        const row = ui.box(rc, lv.LV_FLEX_FLOW_ROW);
        const addr = ui.label(row, ui.zfmt(a, "{s}:{d}", .{ r.host, r.port }));
        lv.lv_obj_set_width(addr, lv.LV_SIZE_CONTENT);
        if (ui.relayConnected()) {
            _ = ui.chip(row, "connected", ui.color_success);
        } else {
            _ = ui.chip(row, "not connected", ui.color_danger);
        }
        _ = ui.bold(rc, "CA fingerprint (SHA-256)");
        _ = ui.muted(rc, ui.zfmt(a, "{x}", .{&r.ca_fingerprint}));
    } else {
        _ = ui.muted(rc, "Not configured yet: node keys and invitations cannot be created.");
    }

    ui.db_lock.lockUncancelable(ui.io);
    const st = ui.db.settingsGet() catch dbm.Settings{};
    ui.db_lock.unlock(ui.io);
    const c = ui.card(ui.content);
    _ = ui.title(c, "Sessions");
    ui.refs.set_output_ta = ui.field(c, a, "Max command output (characters)", 9, std.mem.span(ui.zfmt(a, "{d}", .{st.max_command_output})), "Output kept per command in the session log.");
    ui.refs.set_minutes_ta = ui.field(c, a, "Max session length (minutes)", 6, std.mem.span(ui.zfmt(a, "{d}", .{st.max_session_minutes})), "Sessions are ended after this. 0: no limit.");
    ui.refs.set_days_ta = ui.field(c, a, "Keep session logs (days)", 5, std.mem.span(ui.zfmt(a, "{d}", .{st.log_days})), "Older logs are deleted. 0: kept.");
    if (session.can("config", "update")) ui.refs.set_save_btn = ui.formButtons(c, onSave, null);
    ui.refs.set_msg = ui.muted(c, "");
}

fn onSave(_: ?*lv.lv_event_t) callconv(.c) void {
    const num = struct {
        fn f(ta: ?*lv.lv_obj_t) ?i64 {
            const v = std.fmt.parseInt(i64, std.mem.trim(u8, ui.taText(ta), " "), 10) catch return null;
            return if (v < 0) null else v;
        }
    }.f;
    const out = num(ui.refs.set_output_ta);
    const minutes = num(ui.refs.set_minutes_ta);
    const days = num(ui.refs.set_days_ta);
    if (out == null or minutes == null or days == null) {
        lv.lv_label_set_text(ui.refs.set_msg, "Enter whole numbers, 0 or more.");
        return;
    }
    ui.db_lock.lockUncancelable(ui.io);
    const r = ui.db.settingsSet(.{ .max_command_output = out.?, .max_session_minutes = minutes.?, .log_days = days.? });
    ui.db_lock.unlock(ui.io);
    lv.lv_label_set_text(ui.refs.set_msg, if (r) |_| "Saved." else |_| "Could not save.");
}
