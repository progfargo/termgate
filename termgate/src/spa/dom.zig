//! The page's HTML, through zig-js (vendor/zig-js): setting a part of the
//! page, reading fields, the address. As our earlier project's dom package.

const std = @import("std");
const js = @import("zig-js");
const app = @import("app.zig");

fn document() ?js.Object {
    return js.global.get(js.Object, "document") catch null;
}

fn byId(id: []const u8) ?js.Object {
    const doc = document() orelse return null;
    defer doc.deinit();
    return doc.call(?js.Object, "getElementById", .{js.string(id)}) catch null;
}

/// The HTML inside the element `id`.
pub fn setHtml(id: []const u8, html: []const u8) void {
    if (app.waiting) return;
    const el = byId(id) orelse return;
    defer el.deinit();
    el.set("innerHTML", js.string(html)) catch {};
}

pub fn exists(id: []const u8) bool {
    const el = byId(id) orelse return false;
    el.deinit();
    return true;
}

/// A field's value ("" if there is no such field).
pub fn value(id: []const u8) []const u8 {
    const el = byId(id) orelse return "";
    defer el.deinit();
    return el.getAlloc(js.String, app.arena(), "value") catch "";
}

pub fn setValue(id: []const u8, text: []const u8) void {
    if (app.waiting) return;
    const el = byId(id) orelse return;
    defer el.deinit();
    el.set("value", js.string(text)) catch {};
}

pub fn setDisabled(id: []const u8) void {
    if (app.waiting) return;
    const el = byId(id) orelse return;
    defer el.deinit();
    el.set("disabled", true) catch {};
}

pub fn checked(id: []const u8) bool {
    const el = byId(id) orelse return false;
    defer el.deinit();
    return el.get(bool, "checked") catch false;
}

/// The first text field of the page's content gets the focus (a page
/// set as HTML does not follow `autofocus`).
pub fn focusFirstField() void {
    if (app.waiting) return;
    const tg = js.global.get(js.Object, "tg") catch return;
    defer tg.deinit();
    tg.call(void, "focusFirst", .{}) catch {};
}

/// The messages marked auto-clear go after 5 seconds (web/spa/boot.js).
pub fn autoClearMessages() void {
    if (app.waiting) return;
    const tg = js.global.get(js.Object, "tg") catch return;
    defer tg.deinit();
    tg.call(void, "autoClear", .{}) catch {};
}

pub fn focus(id: []const u8) void {
    if (app.waiting) return;
    const el = byId(id) orelse return;
    defer el.deinit();
    el.call(void, "focus", .{}) catch {};
}

pub fn addClass(id: []const u8, class: []const u8) void {
    if (app.waiting) return;
    classList(id, "add", class);
}

fn classList(id: []const u8, op: []const u8, class: []const u8) void {
    const el = byId(id) orelse return;
    defer el.deinit();
    const list = el.get(js.Object, "classList") catch return;
    defer list.deinit();
    list.call(void, op, .{js.string(class)}) catch {};
}

/// The id of the page's body (our earlier project's SetBodyId: page styles).
pub fn setBodyId(id: []const u8) void {
    if (app.waiting) return;
    const doc = document() orelse return;
    defer doc.deinit();
    const body = doc.get(js.Object, "body") catch return;
    defer body.deinit();
    body.set("id", js.string(id)) catch {};
}

/// Goes to `path` ("/user"): the hash changes and the page follows it.
pub fn setHash(path: []const u8) void {
    if (app.waiting) return;
    const loc = js.global.get(js.Object, "location") catch return;
    defer loc.deinit();
    const h = std.fmt.allocPrint(app.arena(), "#{s}", .{path}) catch return;
    loc.set("hash", js.string(h)) catch {};
}

/// The current hash without "#" ("/user?id=3"), "/" if there is none.
pub fn hash() []const u8 {
    const loc = js.global.get(js.Object, "location") catch return "/";
    defer loc.deinit();
    const h = loc.getAlloc(js.String, app.arena(), "hash") catch return "/";
    return if (h.len > 1) h[1..] else "/";
}

/// Copies text to the clipboard (the page's own helper, web/spa/boot.js).
/// Copies the full link of `url` (a page's address after the #) and
/// flashes the link button (web/spa/boot.js; our earlier project's copyUrl).
pub fn copyUrl(url: []const u8) void {
    if (app.waiting) return;
    const tg = js.global.get(js.Object, "tg") catch return;
    defer tg.deinit();
    tg.call(void, "copyUrl", .{js.string(url)}) catch {};
}

pub fn copy(text: []const u8) void {
    if (app.waiting) return;
    const tg = js.global.get(js.Object, "tg") catch return;
    defer tg.deinit();
    tg.call(void, "copy", .{js.string(text)}) catch {};
}
