//! What a click on a [data-action] element brings, as our earlier project's
//! formData: the fields of its form by id, and its data-* attributes
//! (data-id="3" as "id"). Collected by web/spa/boot.js.

const std = @import("std");
const app = @import("app.zig");

pub const Form = struct {
    map: ?std.json.ObjectMap = null,

    pub fn parse(json: []const u8) Form {
        const v = std.json.parseFromSliceLeaky(std.json.Value, app.arena(), json, .{}) catch return .{};
        return if (v == .object) .{ .map = v.object } else .{};
    }

    /// A value as text, "" if not there.
    pub fn str(f: Form, name: []const u8) []const u8 {
        const m = f.map orelse return "";
        const v = m.get(name) orelse return "";
        return switch (v) {
            .string => |s| s,
            else => "",
        };
    }

    /// A value trimmed of spaces.
    pub fn trimmed(f: Form, name: []const u8) []const u8 {
        return std.mem.trim(u8, f.str(name), " \t");
    }

    pub fn int(f: Form, name: []const u8) i64 {
        return std.fmt.parseInt(i64, f.trimmed(name), 10) catch 0;
    }

    /// The checked values of the checkboxes named `name`.
    pub fn list(f: Form, name: []const u8) []const []const u8 {
        const m = f.map orelse return &.{};
        const v = m.get(name) orelse return &.{};
        if (v != .array) return &.{};
        var out: std.ArrayList([]const u8) = .empty;
        for (v.array.items) |item| if (item == .string) out.append(app.arena(), item.string) catch {};
        return out.items;
    }

    /// A checkbox: boot.js gives "1" for checked.
    pub fn checked(f: Form, name: []const u8) bool {
        return std.mem.eql(u8, f.str(name), "1");
    }
};
