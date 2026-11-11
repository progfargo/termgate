//! A list page's state (search word, page number, filters): our earlier project's
//! lib/cargo. Each variable has a default; read from the address or a
//! form; makeUrl writes the address with the variables that are not at
//! their default. termgate keeps the state in the address (the hash), so
//! the browser's back button and F5 keep the page.

const std = @import("std");
const app = @import("../app.zig");
const Form = @import("../form.zig").Form;

const Kind = enum { int, str };

const Var = struct {
    name: []const u8,
    kind: Kind,
    default_int: i64 = 0,
    default_str: []const u8 = "",
    int_value: ?i64 = null,
    /// Owned (the page's allocator): it outlives the event
    str_value: ?[]u8 = null,
};

pub const CargoList = struct {
    vars: [8]Var = undefined,
    len: usize = 0,

    pub fn addInt(c: *CargoList, name: []const u8, default: i64) void {
        if (c.find(name) != null) std.debug.panic("Cargo variable already exists: {s}", .{name});
        c.vars[c.len] = .{ .name = name, .kind = .int, .default_int = default };
        c.len += 1;
    }

    pub fn addStr(c: *CargoList, name: []const u8, default: []const u8) void {
        if (c.find(name) != null) std.debug.panic("Cargo variable already exists: {s}", .{name});
        c.vars[c.len] = .{ .name = name, .kind = .str, .default_str = default };
        c.len += 1;
    }

    fn find(c: *CargoList, name: []const u8) ?*Var {
        for (c.vars[0..c.len]) |*v| if (std.mem.eql(u8, v.name, name)) return v;
        return null;
    }

    fn get(c: *CargoList, name: []const u8, kind: Kind) *Var {
        const v = c.find(name) orelse std.debug.panic("Cargo variable does not exist: {s}", .{name});
        if (v.kind != kind) std.debug.panic("Cargo variable type mismatch: {s}", .{name});
        return v;
    }

    pub fn setInt(c: *CargoList, name: []const u8, value: i64) void {
        c.get(name, .int).int_value = value;
    }

    pub fn setStr(c: *CargoList, name: []const u8, value: []const u8) void {
        const v = c.get(name, .str);
        if (v.str_value) |old| app.gpa.free(old);
        v.str_value = app.gpa.dupe(u8, value) catch null;
    }

    pub fn int(c: *CargoList, name: []const u8) i64 {
        const v = c.get(name, .int);
        return v.int_value orelse v.default_int;
    }

    pub fn str(c: *CargoList, name: []const u8) []const u8 {
        const v = c.get(name, .str);
        return v.str_value orelse v.default_str;
    }

    /// Every variable back to its default.
    pub fn clear(c: *CargoList) void {
        for (c.vars[0..c.len]) |*v| {
            v.int_value = null;
            if (v.str_value) |old| app.gpa.free(old);
            v.str_value = null;
        }
    }

    pub fn isDefault(c: *CargoList, name: []const u8) bool {
        const v = c.find(name) orelse std.debug.panic("Unknown cargo variable: {s}", .{name});
        return switch (v.kind) {
            .int => v.int_value == null or v.int_value.? == v.default_int,
            .str => v.str_value == null or std.mem.eql(u8, v.str_value.?, v.default_str),
        };
    }

    /// The variables a form has (data-pn of a ruler's button, a select);
    /// the others stay.
    pub fn readMap(c: *CargoList, f: Form) void {
        for (c.vars[0..c.len]) |v| {
            const text = f.str(v.name);
            if (text.len > 0) c.setText(v.name, text);
        }
    }

    /// The variables of an address's query; those it does not have stay
    /// as they are (our earlier project's Read).
    pub fn read(c: *CargoList, query: []const u8) void {
        for (c.vars[0..c.len]) |v| {
            const text = app.queryValue(query, v.name);
            if (text.len > 0) c.setText(v.name, text);
        }
    }

    fn setText(c: *CargoList, name: []const u8, raw: []const u8) void {
        // The search word without % and ? (our earlier project's clearKey)
        var text = raw;
        if (std.mem.eql(u8, name, "key")) {
            var out: std.ArrayList(u8) = .empty;
            for (raw) |ch| if (ch != '%' and ch != '?') out.append(app.arena(), ch) catch {};
            text = out.items;
        }
        switch (c.find(name).?.kind) {
            .int => c.setInt(name, std.fmt.parseInt(i64, text, 10) catch return),
            .str => c.setStr(name, text),
        }
    }

    /// `path` ("/user") with the named variables that are not at their
    /// default as its query.
    pub fn makeUrl(c: *CargoList, path: []const u8, names: []const []const u8) []const u8 {
        var b: app.Buf = .{};
        b.raw(path);
        var first = true;
        for (names) |name| {
            if (c.isDefault(name)) continue;
            b.raw(if (first) "?" else "&");
            first = false;
            const v = c.find(name).?;
            switch (v.kind) {
                .int => b.add("{s}={d}", .{ name, c.int(name) }),
                .str => b.add("{s}={s}", .{ name, app.urlEncode(c.str(name)) }),
            }
        }
        return b.str();
    }
};

test "the address of a list: read, changed, written" {
    var c: CargoList = .{};
    defer c.clear();
    c.addStr("key", "");
    c.addInt("pn", 1);
    c.addInt("rid", 0);
    c.addStr("stat", "default");
    c.read("key=ist%20gw%3F&pn=3&stat=blocked");
    try std.testing.expectEqualStrings("ist gw", c.str("key")); // without ? (clearKey)
    try std.testing.expectEqual(3, c.int("pn"));
    try std.testing.expectEqual(0, c.int("rid"));
    // Defaults are left out
    try std.testing.expectEqualStrings("#/user?key=ist%20gw&pn=3&stat=blocked", c.makeUrl("#/user", &.{ "key", "pn", "rid", "stat" }));
    c.setInt("pn", 1);
    c.setInt("rid", 4);
    try std.testing.expectEqualStrings("/user?key=ist%20gw&rid=4&stat=blocked", c.makeUrl("/user", &.{ "key", "pn", "rid", "stat" }));
    // Reading another address: what it does not have stays
    c.read("pn=2");
    try std.testing.expectEqualStrings("/user?key=ist%20gw&pn=2&rid=4&stat=blocked", c.makeUrl("/user", &.{ "key", "pn", "rid", "stat" }));
}
