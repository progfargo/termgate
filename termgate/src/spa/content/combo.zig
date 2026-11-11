//! Options of a select box: our earlier project's content/combo. EnumCombo: fixed
//! keys and labels; Combo: records (id and label) with a first option
//! for none (0).

const std = @import("std");
const app = @import("../app.zig");

pub const EnumCombo = struct {
    list: std.ArrayList([2][]const u8) = .empty,

    pub fn add(ec: *EnumCombo, key: []const u8, label: []const u8) void {
        ec.list.append(app.arena(), .{ key, label }) catch {};
    }

    pub fn format(ec: *const EnumCombo, cur_key: []const u8) []const u8 {
        var b: app.Buf = .{};
        for (ec.list.items) |it|
            b.add("<option value=\"{f}\"{s}>{f}</option>", .{ app.esc(it[0]), if (std.mem.eql(u8, it[0], cur_key)) " selected" else "", app.esc(it[1]) });
        return b.str();
    }
};

pub const Combo = struct {
    list: std.ArrayList(Item) = .empty,

    const Item = struct { key: i64, label: []const u8 };

    /// `default_option` stands for none (0)
    pub fn init(default_option: []const u8) Combo {
        var c: Combo = .{};
        c.add(0, default_option);
        return c;
    }

    pub fn add(c: *Combo, key: i64, label: []const u8) void {
        c.list.append(app.arena(), .{ .key = key, .label = label }) catch {};
    }

    /// Only the option for none
    pub fn isEmpty(c: *const Combo) bool {
        return c.list.items.len < 2;
    }

    pub fn format(c: *const Combo, cur_key: i64) []const u8 {
        var b: app.Buf = .{};
        for (c.list.items) |it|
            b.add("<option value=\"{d}\"{s}>{f}</option>", .{ it.key, if (it.key == cur_key) " selected" else "", app.esc(it.label) });
        return b.str();
    }
};
