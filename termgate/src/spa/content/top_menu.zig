//! The menu at the top right: our earlier project's content/top_menu, as it is.
//! Profile, Help, Sign out and the theme switch.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const tax_lib = @import("../lib/tax.zig");

pub const TopMenuData = struct {
    url: []const u8 = "",
    label: []const u8 = "",
    icon: []const u8 = "",
    is_active: bool = false,
};

const Tax = tax_lib.Tax(TopMenuData);

/// The menu with `active_name` marked (a page not in this menu: none).
pub fn render(active_name: []const u8) void {
    if (!state.signedIn()) return;
    var tax = Tax.init(app.arena());

    tax.add("root", "end", 0, true, .{});
    tax.add("profile", "root", 10, state.can("profile", "browse"), .{ .url = "#/profile", .label = "Profile", .icon = "fas fa-user" });
    // Help is for everyone (termgate has no help right)
    tax.add("help", "root", 20, true, .{ .url = "#/help", .label = "Help", .icon = "fas fa-life-ring" });
    tax.add("logout", "root", 30, state.signedIn(), .{ .url = "#/logout", .label = "Sign out", .icon = "fas fa-sign-out-alt" });

    if (active_name.len > 0 and tax.isExists(active_name)) tax.getItem(active_name).data.is_active = true;

    tax.sortChildren();
    reduce(&tax, "root");

    const children = tax.getChildren("root");
    if (children.len == 0) return dom.setHtml("top-menu", "");

    var b: app.Buf = .{};
    b.raw("<div class=\"top-menu\">");
    for (children, 0..) |child, i| {
        const d = tax.getItem(child).data;
        if (i > 0) b.raw(" |");
        b.add("<a href=\"{s}\"{s}>", .{ d.url, if (d.is_active) " class=\"active\"" else "" });
        if (d.icon.len > 0) b.add("<i class=\"{s} fa-fw left\"></i>", .{d.icon});
        b.add("{s}</a>", .{d.label});
    }
    b.raw("<button type=\"button\" data-action=\"toggleTheme\" class=\"theme-toggle\" title=\"Toggle theme\"><i class=\"fa-solid fa-moon icon-light\"></i><i class=\"fa-solid fa-sun icon-dark\"></i></button>");
    b.raw("</div>");
    dom.setHtml("top-menu", b.str());
}

fn reduce(tax: *Tax, name: []const u8) void {
    if (tax.isParent(name)) {
        for (tax.getChildren(name)) |child| reduce(tax, child);
        const item = tax.getItem(name);
        if (item.visible) return;
        if (!tax.isParent(name)) return tax.delete(name);
        const remaining = tax.getChildren(name);
        if (remaining.len > 0) item.data.url = tax.getItem(remaining[0]).data.url;
        return;
    }
    if (!tax.getItem(name).visible) tax.delete(name);
}
