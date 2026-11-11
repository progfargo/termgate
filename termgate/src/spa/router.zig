//! The hash decides the page (#/user, #/user/update?id=3), as
//! our earlier project's router: a table of paths and the functions that render
//! them; the end pages (not found, bad request) are here too.

const std = @import("std");
const app = @import("app.zig");
const dom = @import("dom.zig");
const state = @import("state.zig");
const layout = @import("layout.zig");

pub const Handler = *const fn (query: []const u8) void;
pub const Route = struct { path: []const u8, handler: Handler, public: bool = false };

/// Set by main.zig
pub var routes: []const Route = &.{};
/// The page for "/" (the first one the user may open); set by main.zig
pub var home: *const fn () []const u8 = defaultHome;

fn defaultHome() []const u8 {
    return "/profile";
}

/// Renders the page for `full` ("/user?key=x").
pub fn navigate(full: []const u8) void {
    if (app.waiting) return;
    state.external_url = "";
    const q = std.mem.indexOfScalar(u8, full, '?');
    const path = if (q) |i| full[0..i] else full;
    const query = if (q) |i| full[i + 1 ..] else "";
    if (std.mem.eql(u8, path, "/") or path.len == 0) {
        if (!state.signedIn()) return navigate("/login");
        return dom.setHash(home());
    }
    for (routes) |r| {
        if (!std.mem.eql(u8, r.path, path)) continue;
        // Signed-in pages need a signed-in user; the sign-in page the other way round
        if (!r.public and !state.signedIn()) return dom.setHash("/login");
        return r.handler(query);
    }
    renderNotFound();
}

/// Goes to `path`; if the hash is that already, renders it again.
pub fn go(path: []const u8) void {
    if (std.mem.eql(u8, dom.hash(), path)) return navigate(path);
    dom.setHash(path);
}

fn endPage(title: []const u8, text: []const u8) void {
    layout.renderEnd();
    var b: app.Buf = .{};
    b.add("<div class=\"panel panel-default\"><div class=\"panel-heading\"><h3>{f}</h3></div><div class=\"panel-body\"><p>{f}</p>", .{ app.esc(title), app.esc(text) });
    b.raw("<p><a href=\"#/\" class=\"button button-default button-sm\">Home</a></p></div></div>");
    dom.setHtml("main-content", b.str());
}

pub fn renderNotFound() void {
    dom.setBodyId("not-found");
    endPage("Not found", "The page or the record could not be found.");
}

pub fn renderBadRequest() void {
    dom.setBodyId("bad-request");
    endPage("Not allowed", "You do not have the right to do this.");
}
