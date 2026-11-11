//! The left menu: our earlier project's content/left_menu, as it is. A tax of the
//! pages, each visible by the user's right; reduce drops what the user
//! may not see (a sub-menu with nothing left in it goes too, and one the
//! user may not open itself links to its first child).

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const tax_lib = @import("../lib/tax.zig");

pub const LeftMenuData = struct {
    url: []const u8 = "",
    label: []const u8 = "",
    icon: []const u8 = "",
    is_active: bool = false,
    is_submenu_open: bool = false,
};

const Tax = tax_lib.Tax(LeftMenuData);

/// The menu with `active_name` marked (a page not in the menu: none).
pub fn render(active_name: []const u8) void {
    if (!state.signedIn()) return;
    const can = state.can;
    var tax = Tax.init(app.arena());

    tax.add("root", "end", 0, true, .{});

    tax.add("node", "root", 10, can("node", "browse"), .{ .url = "#/node", .label = "Nodes", .icon = "fas fa-server" });
    tax.add("session", "root", 20, can("session", "browse"), .{ .url = "#/session", .label = "Sessions", .icon = "fas fa-terminal" });
    tax.add("audit", "root", 30, can("audit", "browse"), .{ .url = "#/audit", .label = "Audit", .icon = "fas fa-clipboard-list" });

    // admin
    tax.add("admin", "root", 40, can("user", "browse"), .{ .url = "#/user", .label = "Admin", .icon = "fas fa-gear" });
    tax.add("user_", "admin", 10, can("user", "browse"), .{ .url = "#/user", .label = "User Management", .icon = "fas fa-user" });
    tax.add("user", "user_", 10, can("user", "browse"), .{ .url = "#/user", .label = "Users", .icon = "fas fa-user-cog" });
    tax.add("role", "user_", 20, can("role", "browse"), .{ .url = "#/role", .label = "Roles", .icon = "fas fa-users-gear" });
    tax.add("config", "admin", 30, can("config", "browse"), .{ .url = "#/config", .label = "Configuration", .icon = "fas fa-gauge" });

    if (active_name.len > 0 and tax.isExists(active_name)) setActive(&tax, active_name);

    tax.sortChildren();
    reduce(&tax, "root");
    format(&tax);
}

fn setActive(tax: *Tax, name: []const u8) void {
    for (tax.getAllParents(name)) |parent| tax.getItem(parent).data.is_submenu_open = true;
    const item = tax.getItem(name);
    item.data.is_active = true;
    item.data.is_submenu_open = true;
}

fn reduce(tax: *Tax, name: []const u8) void {
    if (tax.isParent(name)) {
        for (tax.getChildren(name)) |child| reduce(tax, child);
        const item = tax.getItem(name);
        if (item.visible) return;
        if (!tax.isParent(name)) return tax.delete(name);
        // Not visible but still a parent: its first child's address
        const remaining = tax.getChildren(name);
        if (remaining.len > 0) item.data.url = tax.getItem(remaining[0]).data.url;
        return;
    }
    if (!tax.getItem(name).visible) tax.delete(name);
}

fn format(tax: *Tax) void {
    const children = tax.getChildren("root");
    if (children.len == 0) return dom.setHtml("left-menu-nav", "");
    var b: app.Buf = .{};
    b.raw("<nav><ul>");
    for (children) |child| formatItem(tax, child, &b);
    b.raw("</ul></nav>");
    dom.setHtml("left-menu-nav", b.str());
}

fn formatItem(tax: *Tax, name: []const u8, b: *app.Buf) void {
    const d = tax.getItem(name).data;
    if (tax.isParent(name)) {
        b.raw(if (d.is_active) "<li class=\"active sub-menu\">" else "<li class=\"sub-menu\">");
        b.add("<a href=\"{s}\"><i class=\"{s} fa-fw menu-icon left\"></i>{s}<i class=\"sub-menu-button fas fa-{s} fa-fw\"></i></a>", .{ d.url, d.icon, d.label, if (d.is_submenu_open) "minus" else "plus" });
        b.raw(if (d.is_submenu_open) "<ul class=\"sub-menu-show\">" else "<ul>");
        for (tax.getChildren(name)) |child| formatItem(tax, child, b);
        b.raw("</ul></li>");
    } else {
        b.raw(if (d.is_active) "<li class=\"active\">" else "<li>");
        b.add("<a href=\"{s}\"><i class=\"{s} fa-fw menu-icon left\"></i>{s}</a></li>", .{ d.url, d.icon, d.label });
    }
}
