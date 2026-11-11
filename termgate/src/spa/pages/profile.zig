//! Profile (#/profile): one's own user, and changing one's own password
//! (#/profile/update_pass), as our earlier project's profile pages. While acting
//! as another user it is that user's.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const Form = @import("../form.zig").Form;

fn begin() void {
    dom.setBodyId("profile");
    layout.renderDefault("profile");
}

pub fn render(_: []const u8) void {
    if (!state.can("profile", "browse")) return router.renderBadRequest();
    begin();
    const u = state.user.?;
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Profile", "" }});
    if (state.can("profile", "update_password")) {
        content.commandStart(&b);
        b.raw("<a href=\"#/profile/update_pass\" class=\"button button-default button-sm\"><i class=\"fas fa-key fa-fw\"></i> Change Password</a>");
        content.commandEnd(&b);
    }
    content.contentStart(&b);
    b.add("<table><tbody><tr><th class=\"fixed-middle\">User Name:</th><td>{f}</td></tr>", .{app.esc(u.name)});
    if (u.superuser) b.raw("<tr><th>Rights:</th><td>Superuser: every right.</td></tr>");
    if (u.real) |real| b.add("<tr><th>Signed in as:</th><td>{f} (acting as this user)</td></tr>", .{app.esc(real)});
    b.raw("</tbody></table>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn updatePass(_: []const u8) void {
    if (!state.can("profile", "update_password")) return router.renderBadRequest();
    begin();
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Profile", "#/profile" }, .{ "Change Password", "" } });
    content.contentStart(&b);
    b.raw("<form>");
    content.field(&b, "profile-cur-password-input", "Current Password:", "", .{ .password = true, .max = 128 });
    content.field(&b, "profile-new-password-input", "New Password:", "", .{ .password = true, .max = 128, .help = "At least 8 characters." });
    content.field(&b, "profile-re-new-password-input", "Retype New Password:", "", .{ .password = true, .max = 128 });
    b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"profileUpdatePass\" class=\"button button-primary button-sm\">Submit</button> <a href=\"#/profile\" class=\"button button-default button-sm\">Cancel</a></div></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    content.show(&b);
}

pub fn submitUpdatePass(f: Form) void {
    _ = fetch.post("profile/update_pass", .{
        .current = f.str("profile-cur-password-input"),
        .new = f.str("profile-new-password-input"),
        .new2 = f.str("profile-re-new-password-input"),
    }) orelse return;
    if (fetch.refused()) {
        // The form again, empty: the messages say what was wrong
        _ = state.renderMessages();
        for ([_][]const u8{ "profile-cur-password-input", "profile-new-password-input", "profile-re-new-password-input" }) |id| dom.setValue(id, "");
        return dom.focusFirstField();
    }
    state.say("success", "Your password has been changed.");
    router.go("/profile");
}
