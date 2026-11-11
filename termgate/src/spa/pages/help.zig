//! Help (#/help): what is where in termgate, in a few lines each.

const app = @import("../app.zig");
const dom = @import("../dom.zig");
const layout = @import("../layout.zig");
const content = @import("../content.zig");
const state = @import("../state.zig");
const router = @import("../router.zig");

const Topic = struct { title: []const u8, lines: []const []const u8 };

const topics = [_]Topic{
    .{ .title = "Nodes", .lines = &.{
        "A node is a gateway that runs tgnode. New gives a key and the command to run on the device once: tgnode --registration <key>.",
        "The device then asks to be approved here. Approved nodes are online while they are connected to the relay.",
        "A disabled or deleted node is disconnected at once.",
    } },
    .{ .title = "Sessions and audit", .lines = &.{
        "Sessions lists the open terminals. Watch shows one live, read-only, from the moment you start watching; End closes it.",
        "Audit lists what users did in this panel, and the sessions; a session's Log shows the commands typed and their output.",
    } },
    .{ .title = "Users and roles", .lines = &.{
        "Every user is a user: admins, auditors, terminal users, bots. What each may do comes from its roles; a role is a set of rights.",
        "termgate makes a user's password; you hand it over. The user sets up the second step (an authenticator app) at the first sign-in.",
        "The superuser is the first user (made by termgate init): it has every right, and nobody can change it. It changes its own password in Profile.",
        "The role admin cannot be deleted and only the superuser changes it; the last user with the role admin cannot lose it.",
        "Select in Users shows the panel as that user sees it, with its rights; the cross under the menu goes back.",
        "Only an admin gives a new password, here in the panel, and it is recorded: keep more than one admin. Everyone changes their own in Profile.",
    } },
    .{ .title = "Configuration", .lines = &.{
        "How long sessions may last, how much output is kept per command and for how many days logs are kept.",
        "The relay's address and the CA fingerprint are those nodes and users connect to.",
    } },
};

pub fn render(_: []const u8) void {
    if (!state.can("help", "browse")) return router.renderBadRequest();
    dom.setBodyId("");
    layout.renderDefault("help");
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Help", "" }});
    for (topics) |t| {
        content.contentStart(&b);
        b.add("<h4>{f}</h4>", .{app.esc(t.title)});
        for (t.lines) |line| b.add("<p>{f}</p>", .{app.esc(line)});
        content.contentEnd(&b);
    }
    content.show(&b);
}
