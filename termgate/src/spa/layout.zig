//! The frame of the page, as our earlier project's layout and its left menu: the
//! menu on the left with the user at its bottom, the header, the message
//! area and #main-content.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");
const state = @import("state.zig");

const default_layout =
    \\<div class="left-menu" id="left-menu-div"><div id="left-menu-nav"></div><div class="user-info" id="user-info"></div></div>
    \\<header>
    \\<div class="left-menu-button" id="left-menu-btn" data-action="toggleSidebar"><i class="fa fa-bars"></i></div>
    \\<div class="site-title"><h1><a href="#/">term<span>gate</span></a></h1></div>
    \\<div class="top-menu" id="top-menu"></div>
    \\</header>
    \\<main><div class="site-message" id="site-message"></div><div id="main-content"></div></main>
;

const login_layout =
    \\<main><div class="site-message" id="site-message"></div><div id="main-content"></div></main>
;

const end_layout =
    \\<main><div class="row"><div class="col col-span md2 lg3 xl4"></div><div class="col md8 lg6 xl4" id="main-content"></div><div class="col col-span md2 lg3 xl4"></div></div></main>
;

/// Which frame is on the page now
var current: enum { none, default, login, end } = .none;

/// The frame of a signed-in page, with the menu showing `active`.
pub fn renderDefault(active: []const u8) void {
    if (current != .default) {
        dom.setHtml("app", default_layout);
        current = .default;
    }
    dom.setHtml("site-message", "");
    leftMenu(active);
    userInfo();
}

pub fn renderLogin() void {
    dom.setHtml("app", login_layout);
    current = .login;
}

pub fn renderEnd() void {
    dom.setHtml("app", end_layout);
    current = .end;
}

/// The frame is drawn again at the next page (after signing in or out,
/// or acting as another user: another menu).
pub fn reset() void {
    current = .none;
}

const Item = struct { name: []const u8, url: []const u8, label: []const u8, icon: []const u8, visible: bool };

fn leftMenu(active: []const u8) void {
    const main_items = [_]Item{
        .{ .name = "node", .url = "#/node", .label = "Nodes", .icon = "fas fa-server", .visible = state.can("node", "browse") },
        .{ .name = "session", .url = "#/session", .label = "Sessions", .icon = "fas fa-terminal", .visible = state.can("session", "browse") },
        .{ .name = "audit", .url = "#/audit", .label = "Audit", .icon = "fas fa-clipboard-list", .visible = state.can("audit", "browse") },
    };
    const admin_items = [_]Item{
        .{ .name = "user", .url = "#/user", .label = "Users", .icon = "fas fa-user-cog", .visible = state.can("user", "browse") },
        .{ .name = "role", .url = "#/role", .label = "Roles", .icon = "fas fa-users-gear", .visible = state.can("role", "browse") },
        .{ .name = "config", .url = "#/config", .label = "Configuration", .icon = "fas fa-gauge", .visible = state.can("config", "browse") },
        .{ .name = "help", .url = "#/help", .label = "Help", .icon = "fas fa-circle-question", .visible = true },
    };
    const profile_item: Item = .{ .name = "profile", .url = "#/profile", .label = "Profile", .icon = "fas fa-id-card", .visible = state.can("profile", "browse") };

    var b: app.Buf = .{};
    b.raw("<nav><ul>");
    for (main_items) |it| item(&b, it, active);
    // Admin: a sub-menu, open when one of its pages is shown
    var any = false;
    var open = false;
    for (admin_items) |it| {
        any = any or it.visible;
        open = open or std.mem.eql(u8, it.name, active);
    }
    if (any) {
        b.add("<li class=\"sub-menu{s}\"><a href=\"#/user\"><i class=\"fas fa-gear fa-fw menu-icon left\"></i>Admin<i class=\"sub-menu-button fas fa-{s} fa-fw\"></i></a><ul{s}>", .{
            if (open) " active" else "",
            if (open) "minus" else "plus",
            if (open) " class=\"sub-menu-show\"" else "",
        });
        for (admin_items) |it| item(&b, it, active);
        b.raw("</ul></li>");
    }
    item(&b, profile_item, active);
    b.raw("<li><a href=\"#\" data-action=\"logout\"><i class=\"fas fa-power-off fa-fw menu-icon left\"></i>Sign out</a></li>");
    b.raw("</ul></nav>");
    dom.setHtml("left-menu-nav", b.str());
}

fn item(b: *app.Buf, it: Item, active: []const u8) void {
    if (!it.visible) return;
    b.add("<li{s}><a href=\"{s}\"><i class=\"{s} fa-fw menu-icon left\"></i>{s}</a></li>", .{
        if (std.mem.eql(u8, it.name, active)) " class=\"active\"" else "",
        it.url,
        it.icon,
        it.label,
    });
}

/// Who is signed in, at the bottom of the menu; while acting as another
/// user, both and a way back (our earlier project's UserInfo).
fn userInfo() void {
    const u = state.user orelse return;
    var b: app.Buf = .{};
    if (u.real) |real| {
        b.add("<p><strong>User:</strong> {f}", .{app.esc(u.name)});
        if (u.can_unselect) b.raw(" <a href=\"#\" data-action=\"userUnselect\" class=\"unselect-user\" title=\"Back to myself\"><i class=\"fas fa-times\"></i></a>");
        b.add("</p><p><small>Signed in as {f}</small></p>", .{app.esc(real)});
    } else {
        b.add("<p><strong>User:</strong> {f}</p>", .{app.esc(u.name)});
    }
    dom.setHtml("user-info", b.str());
}
