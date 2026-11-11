//! Configuration (#/config): the session settings (longest session,
//! output kept per command, days logs are kept) and the relay nodes and
//! users connect to.

const std = @import("std");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");
const Form = @import("../form.zig").Form;

const Settings = struct { max_command_output: i64 = 10_000, max_session_minutes: i64 = 480, log_days: i64 = 30 };
const Relay = struct { host: []const u8 = "", port: u16 = 0, ca_fingerprint: []const u8 = "" };

fn begin() void {
    dom.setBodyId("");
    layout.renderDefault("config");
}

pub fn browse(_: []const u8) void {
    if (!state.can("config", "browse")) return router.renderBadRequest();
    begin();
    const answer = fetch.postRaw("config/browse", "[]") orelse return;
    const s = fetch.fieldAs(Settings, answer, "data") orelse Settings{};
    const relay = if (fetch.postRaw("config/relay", "[]")) |r| fetch.fieldAs(Relay, r, "data") orelse Relay{} else Relay{};
    render(s, relay);
}

fn render(s: Settings, relay: Relay) void {
    const can_update = state.can("config", "update");
    var b: app.Buf = .{};
    content.header(&b, &.{.{ "Configuration", "" }});
    content.contentStart(&b);
    b.raw("<form>");
    const num = struct {
        fn f(v: i64) []const u8 {
            return std.fmt.allocPrint(app.arena(), "{d}", .{v}) catch "";
        }
    }.f;
    content.field(&b, "config-minutes-input", "Longest session, minutes:", num(s.max_session_minutes), .{ .max = 9, .help = "Sessions are ended after this; 0: no limit." });
    content.field(&b, "config-output-input", "Output kept per command, characters:", num(s.max_command_output), .{ .max = 9, .help = "In the session log." });
    content.field(&b, "config-days-input", "Keep session logs, days:", num(s.log_days), .{ .max = 9, .help = "Older logs are deleted; 0: kept." });
    if (can_update) b.raw("<div class=\"form-group form-command\"><div class=\"button-group-fixed\"><button type=\"button\" data-action=\"configUpdate\" class=\"button button-primary button-sm\">Submit</button></div></div>");
    b.raw("</form>");
    content.contentEnd(&b);
    b.raw("<div class=\"row row-header\"><div class=\"col\"><div class=\"page-title\"><h3>Relay</h3></div></div></div>");
    content.contentStart(&b);
    b.add("<table><tbody><tr><th class=\"fixed-middle\">Address:</th><td>{f}:{d}</td></tr><tr><th>CA fingerprint:</th><td><small>{f}</small></td></tr></tbody></table>", .{ app.esc(relay.host), relay.port, app.esc(relay.ca_fingerprint) });
    b.raw("<p><small>Nodes and users connect to this address; set with termgate init.</small></p>");
    content.contentEnd(&b);
    content.show(&b);
    if (!can_update) for ([_][]const u8{ "config-minutes-input", "config-output-input", "config-days-input" }) |id| dom.setDisabled(id);
}

pub fn submit(f: Form) void {
    const parse = struct {
        fn number(v: []const u8) ?i64 {
            const n = std.fmt.parseInt(i64, v, 10) catch return null;
            return if (n < 0) null else n;
        }
    }.number;
    const minutes = parse(f.trimmed("config-minutes-input"));
    const output = parse(f.trimmed("config-output-input"));
    const days = parse(f.trimmed("config-days-input"));
    if (minutes == null or output == null or days == null) {
        state.say("warning", "Each value is a whole number, 0 or more.");
        return browse("");
    }
    _ = fetch.post("config/update", .{Settings{ .max_session_minutes = minutes.?, .max_command_output = output.?, .log_days = days.? }}) orelse return;
    if (fetch.refused()) state.keepMessages() else state.say("success", "Record has been changed.");
    browse("");
}
