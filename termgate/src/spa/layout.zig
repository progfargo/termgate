//! The frame of the page: our earlier project's layout, as it is. The left menu
//! (content/left_menu.zig) with the user at its bottom, the header with
//! the top menu (content/top_menu.zig) and the search box, the message
//! area, #main-content and the footer.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");
const state = @import("state.zig");
const left_menu = @import("content/left_menu.zig");
const top_menu = @import("content/top_menu.zig");

const default_layout =
    \\<div class="left-menu" id="left-menu-div"><div id="left-menu-nav"></div><div class="user-info" id="user-info"></div></div>
    \\<header>
    \\<div class="top-menu-button" id="top-menu-btn" data-action="toggleMobileMenu"><i class="fa fa-bars"></i></div>
    \\<div class="left-menu-button" id="left-menu-btn" data-action="toggleSidebar"><i class="fa fa-bars"></i></div>
    \\<div class="site-title"><h1><a href="#/">term<span>gate</span></a></h1></div>
    \\<div class="top-menu" id="top-menu"></div>
    \\<div id="search"></div>
    \\</header>
    \\<main><div class="site-message" id="site-message"></div><div id="main-content"></div><div class="row row-footer"><div class="col footer-note" id="footer-note"></div></div></main>
;

const login_layout =
    \\<main><div class="site-message" id="site-message"></div><div id="main-content"></div></main>
;

const end_layout =
    \\<main><div class="row"><div class="col col-span md2 lg3 xl4"></div><div class="col md8 lg6 xl4" id="main-content"></div><div class="col col-span md2 lg3 xl4"></div></div></main>
;

/// Which frame is on the page now
var current: enum { none, default, login, end } = .none;

// web/spa/boot.js: the header's height and its menu button on a phone
// (our earlier project's setupHeaderWatch)
extern "env" fn tg_layout_ready() void;

/// The frame of a signed-in page, with `active` marked in the menus.
pub fn renderDefault(active: []const u8) void {
    if (current != .default) {
        dom.setHtml("app", default_layout);
        current = .default;
        footerNote();
        if (@import("builtin").cpu.arch == .wasm32) tg_layout_ready();
    }
    dom.setHtml("site-message", "");
    // A list page puts its search box back (content.search)
    dom.setHtml("search", "");
    left_menu.render(active);
    top_menu.render(active);
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

/// Who is signed in, at the bottom of the menu; while acting as another
/// user, both and a way back (our earlier project's content.UserInfo).
fn userInfo() void {
    const u = state.user orelse return;
    var b: app.Buf = .{};
    b.add("<p><strong>User:</strong> {f}", .{app.esc(u.name)});
    if (u.real != null and u.can_unselect) b.raw(" <a href=\"#/user/unselect\" class=\"unselect-user\" title=\"Unselect effective user.\"><i class=\"fas fa-times\"></i></a>");
    b.raw("</p>");
    if (u.real) |real| b.add("<p><small>Signed in as {f}</small></p>", .{app.esc(real)});
    dom.setHtml("user-info", b.str());
}

fn footerNote() void {
    dom.setHtml("footer-note", "<p><small>termgate</small></p>");
}
