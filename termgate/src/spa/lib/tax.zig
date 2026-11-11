//! A tree of named items, each with a parent, an order number (enum) and
//! a visible flag: our earlier project's lib/tax, as it is. The menus are built on
//! it (an item per page, visible by the user's right; reduce drops what
//! the user may not see), and so are tree-shaped select boxes.
//!
//! The tree's top item is "root", whose parent is "end". Asking for an
//! item that does not exist is a mistake in the page's code: it panics,
//! as our earlier project's does.

const std = @import("std");

pub fn Tax(comptime Data: type) type {
    return struct {
        const Self = @This();

        const Child = struct { name: []const u8, enum_: i64 };

        pub const Item = struct {
            name: []const u8,
            parent: []const u8,
            children: std.ArrayList(Child) = .empty,
            enum_: i64,
            visible: bool,
            data: Data,
        };

        a: std.mem.Allocator,
        list: std.StringHashMapUnmanaged(*Item) = .empty,

        /// Everything is allocated from `a` (the event's arena)
        pub fn init(a: std.mem.Allocator) Self {
            return .{ .a = a };
        }

        pub fn add(t: *Self, name: []const u8, parent: []const u8, enum_: i64, visible: bool, data: Data) void {
            if (t.list.contains(name)) std.debug.panic("Tax item already exists: {s}", .{name});
            const end = std.mem.eql(u8, parent, "end");
            if (!end and !t.list.contains(parent)) std.debug.panic("Parent item does not exist: {s}", .{parent});
            const item = t.a.create(Item) catch @panic("OOM");
            item.* = .{ .name = name, .parent = parent, .enum_ = enum_, .visible = visible, .data = data };
            if (!end) t.list.get(parent).?.children.append(t.a, .{ .name = name, .enum_ = enum_ }) catch @panic("OOM");
            t.list.put(t.a, name, item) catch @panic("OOM");
        }

        pub fn isExists(t: *const Self, name: []const u8) bool {
            return t.list.contains(name);
        }

        pub fn isEmpty(t: *const Self) bool {
            return t.list.count() == 0;
        }

        /// Only a leaf can be deleted.
        pub fn delete(t: *Self, name: []const u8) void {
            const item = t.getItem(name);
            if (t.isParent(name)) @panic("Parent taxonomy item can not be deleted.");
            const siblings = &t.getItem(item.parent).children;
            for (siblings.items, 0..) |c, i| if (std.mem.eql(u8, c.name, name)) {
                _ = siblings.orderedRemove(i);
                break;
            };
            _ = t.list.remove(name);
        }

        pub fn getItem(t: *const Self, name: []const u8) *Item {
            return t.list.get(name) orelse std.debug.panic("Tax item does not exists: {s}", .{name});
        }

        /// The parent, its parent and so on up to root.
        pub fn getAllParents(t: *const Self, name: []const u8) []const []const u8 {
            var out: std.ArrayList([]const u8) = .empty;
            var parent = t.getItem(name).parent;
            while (!std.mem.eql(u8, parent, "end")) : (parent = t.getItem(parent).parent)
                out.append(t.a, parent) catch @panic("OOM");
            return out.items;
        }

        pub fn isParent(t: *const Self, name: []const u8) bool {
            return t.getItem(name).children.items.len > 0;
        }

        pub fn getChildren(t: *const Self, name: []const u8) []const []const u8 {
            const item = t.getItem(name);
            const out = t.a.alloc([]const u8, item.children.items.len) catch @panic("OOM");
            for (item.children.items, out) |c, *o| o.* = c.name;
            return out;
        }

        /// `name` and everything under it, depth first.
        pub fn getAllChildren(t: *const Self, name: []const u8) []const []const u8 {
            var out: std.ArrayList([]const u8) = .empty;
            if (t.list.contains(name)) t.allChildren(name, &out);
            return out.items;
        }

        fn allChildren(t: *const Self, name: []const u8, out: *std.ArrayList([]const u8)) void {
            out.append(t.a, name) catch @panic("OOM");
            for (t.getItem(name).children.items) |c| t.allChildren(c.name, out);
        }

        /// Children in the order of their enum; the same enum: by name,
        /// backwards (as our earlier project's).
        pub fn sortChildren(t: *Self) void {
            var it = t.list.valueIterator();
            while (it.next()) |item| std.mem.sort(Child, item.*.children.items, {}, less);
        }

        fn less(_: void, x: Child, y: Child) bool {
            if (x.enum_ != y.enum_) return x.enum_ < y.enum_;
            return std.mem.order(u8, x.name, y.name) == .gt;
        }
    };
}

/// Ids of records in a tree (a tax combo): 0 is "end", 1 is "root".
pub fn intToName(a: std.mem.Allocator, id: i64) []const u8 {
    if (id == 0) return "end";
    if (id == 1) return "root";
    return std.fmt.allocPrint(a, "{d}", .{id}) catch @panic("OOM");
}

pub fn nameToInt(name: []const u8) i64 {
    if (std.mem.eql(u8, name, "end")) return 0;
    if (std.mem.eql(u8, name, "root")) return 1;
    return std.fmt.parseInt(i64, name, 10) catch 0;
}

test "a tree: order, parents, deleting a leaf" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var t = Tax(u8).init(arena.allocator());
    t.add("root", "end", 0, true, 0);
    t.add("admin", "root", 10, true, 1);
    t.add("node", "root", 5, true, 2);
    t.add("user", "admin", 20, true, 3);
    t.add("role", "admin", 10, true, 4);
    t.add("b", "admin", 30, true, 5);
    t.add("a", "admin", 30, true, 6);
    t.sortChildren();
    const kids = t.getChildren("admin");
    try std.testing.expectEqual(4, kids.len);
    try std.testing.expectEqualStrings("role", kids[0]);
    try std.testing.expectEqualStrings("user", kids[1]);
    try std.testing.expectEqualStrings("b", kids[2]); // same enum: by name backwards
    try std.testing.expectEqualStrings("node", t.getChildren("root")[0]);
    const up = t.getAllParents("role");
    try std.testing.expectEqual(2, up.len);
    try std.testing.expectEqualStrings("admin", up[0]);
    try std.testing.expectEqualStrings("root", up[1]);
    try std.testing.expectEqual(7, t.getAllChildren("root").len);
    t.delete("role");
    try std.testing.expect(!t.isExists("role"));
    try std.testing.expectEqual(3, t.getChildren("admin").len);
    try std.testing.expectEqual(1, nameToInt("root"));
    try std.testing.expectEqual(42, nameToInt(intToName(arena.allocator(), 42)));
}
