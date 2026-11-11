//! Signing in (#/login): name and password, then the code from the
//! authenticator app; at the first sign-in the setup key first. As
//! our earlier project's login page; termgate has no captcha but a second step
//! (unless built with -Dsecond-step=false).

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const Form = @import("../form.zig").Form;

/// The setup key of a first sign-in, kept between the two steps
var setup_key: [64]u8 = undefined;
var setup_key_len: usize = 0;

pub fn render(_: []const u8) void {
    if (state.signedIn()) return dom.setHash("/");
    dom.setBodyId("login");
    layout.renderLogin();
    renderPassword("");
}

fn card(b: *app.Buf) void {
    b.raw("<div class=\"row login\"><div class=\"col col-span md2 lg3 xl4\"></div><div class=\"col md8 lg6 xl4 panel panel-primary\">");
    b.raw("<div class=\"panel-heading\"><h3>termgate</h3></div><div class=\"panel-body\">");
}

fn cardEnd(b: *app.Buf) void {
    b.raw("</div></div><div class=\"col col-span md2 lg3 xl4\"></div></div>");
}

fn renderPassword(name: []const u8) void {
    var b: app.Buf = .{};
    card(&b);
    b.raw("<form>");
    b.add("<div class=\"form-group\"><label class=\"required\">Name:</label><input type=\"text\" id=\"login-input\" class=\"form-control\" maxlength=\"32\" tabindex=\"1\" autocomplete=\"username\" autofocus value=\"{f}\"></div>", .{app.esc(name)});
    b.raw("<div class=\"form-group\"><label class=\"required\">Password:</label><input type=\"password\" id=\"password-input\" class=\"form-control\" maxlength=\"128\" tabindex=\"2\" autocomplete=\"current-password\"></div>");
    b.raw("<div class=\"form-group form-command\"><button type=\"button\" data-action=\"login\" class=\"button button-primary button-sm\" tabindex=\"3\">Sign in</button></div>");
    b.raw("</form>");
    cardEnd(&b);
    dom.setHtml("main-content", b.str());
    _ = state.renderMessages();
    dom.focus(if (name.len == 0) "login-input" else "password-input");
}

/// The second step: the code; at the first sign-in after the key for the
/// app.
fn renderCode() void {
    var b: app.Buf = .{};
    card(&b);
    b.raw("<form>");
    if (setup_key_len > 0) {
        b.raw("<p>First sign-in: set up the second step. Add an entry named termgate to your authenticator app (Google Authenticator or another) with this key:</p>");
        b.add("<p><strong>{f}</strong></p>", .{app.esc(setup_key[0..setup_key_len])});
        b.raw("<p>Then enter the code the app shows.</p>");
    }
    b.raw("<div class=\"form-group\"><label class=\"required\">Code:</label><input type=\"text\" id=\"code-input\" class=\"form-control\" maxlength=\"6\" tabindex=\"1\" inputmode=\"numeric\" autocomplete=\"one-time-code\" autofocus></div>");
    b.raw("<div class=\"form-group form-command\"><button type=\"button\" data-action=\"loginCode\" class=\"button button-primary button-sm\" tabindex=\"2\">Confirm</button> ");
    b.raw("<button type=\"button\" data-action=\"loginBack\" class=\"button button-default button-sm\" tabindex=\"3\">Back</button></div>");
    b.raw("</form>");
    cardEnd(&b);
    dom.setHtml("main-content", b.str());
    _ = state.renderMessages();
    dom.focus("code-input");
}

pub fn submit(f: Form) void {
    const name = f.trimmed("login-input");
    const answer = fetch.post("login", .{ .name = name, .password = f.str("password-input") }) orelse return renderPassword(name);
    if (fetch.refused()) return renderPassword(name);
    const step = if (fetch.field(answer, "step")) |s| (if (s == .string) s.string else "") else "";
    if (std.mem.eql(u8, step, "done")) return signedIn();
    setup_key_len = 0;
    if (std.mem.eql(u8, step, "setup")) {
        const key = fetch.fieldAs([]const u8, answer, "secret") orelse "";
        setup_key_len = @min(key.len, setup_key.len);
        @memcpy(setup_key[0..setup_key_len], key[0..setup_key_len]);
    }
    renderCode();
}

pub fn submitCode(f: Form) void {
    _ = fetch.post("login/code", .{ .code = f.trimmed("code-input") }) orelse return renderCode();
    if (fetch.refused()) return renderCode();
    setup_key_len = 0;
    signedIn();
}

pub fn back(_: Form) void {
    setup_key_len = 0;
    state.messages = &.{};
    renderPassword("");
}

/// Signed in: who it is and its rights, then the first page.
fn signedIn() void {
    reload();
    layout.reset();
    router.go("/");
}

/// Reads who is signed in again (/api/init).
pub fn reload() void {
    const answer = fetch.postRaw("init", "{}") orelse return;
    state.setUser(fetch.field(answer, "user"));
    if (fetch.field(answer, "second_step")) |s| if (s == .bool) {
        state.second_step = s.bool;
    };
}

pub fn logout(_: Form) void {
    _ = fetch.postRaw("logout", "{}");
    state.setUser(null);
    state.messages = &.{};
    layout.reset();
    router.go("/login");
}
