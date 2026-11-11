//! Help screen (Admin): what the pages are for and the commands that go
//! with them, in a few lines each.

const lv = @import("lvgl");
const ui = @import("../ui.zig");

const Topic = struct { title: [*:0]const u8, lines: []const [*:0]const u8 };

const topics = [_]Topic{
    .{ .title = "Nodes", .lines = &.{
        "A node is a gateway that runs tgnode. New node gives a key and the command to run on the device once: tgnode --registration <key>.",
        "The device then asks to be approved here. Approved nodes are online while they are connected to the relay.",
        "A disabled or deleted node is disconnected at once.",
    } },
    .{ .title = "Terminal access", .lines = &.{
        "An invitation gives one person or bot terminal access: which nodes (names or patterns), as which Unix user, how many sessions and until when.",
        "The invited one runs: tgterm --invite <invitation>, then tgterm <node> like ssh.",
        "Revoking ends the access and closes the open sessions.",
    } },
    .{ .title = "Sessions and audit", .lines = &.{
        "Sessions lists the open terminals. Watch shows one live, read-only, from the moment you start watching; End closes it.",
        "Audit lists every session termgate approved and what users did in this panel. A session's row opens its log: the commands and their output.",
    } },
    .{ .title = "Users and roles", .lines = &.{
        "Users sign in to this panel with a name, a password and a code from an authenticator app. termgate makes the password; you hand it over.",
        "A role is a set of rights (browse, insert, update, delete and more, per page). A user may do what its roles allow; without a role, nothing.",
        "The superuser is the first user (made by termgate init): it has every right, and nobody can change it. It changes its own password in Profile.",
        "The role admin cannot be deleted and only the superuser changes it; the last user with the role admin cannot lose it.",
        "The eye button in Users shows the panel as that user sees it, with its rights; Back to myself at the top returns.",
        "Only an admin resets a password, here in the panel, and it is recorded: keep more than one admin. Everyone changes their own in Profile.",
    } },
    .{ .title = "Configuration", .lines = &.{
        "How long sessions may last, how much output is kept per command and for how many days logs are kept.",
        "The relay's address and the CA fingerprint are those nodes and users connect to.",
    } },
};

pub fn render() void {
    _ = ui.beginPage();
    _ = ui.header(ui.content, "Help", "What is where in termgate.");
    for (topics) |t| {
        const c = ui.card(ui.content);
        _ = ui.title(c, t.title);
        for (t.lines) |line| _ = ui.label(c, line);
    }
}
