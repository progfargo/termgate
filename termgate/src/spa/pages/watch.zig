//! Watching a session (#/session/watch?sid=..&node=..&key=..): read-only,
//! from the moment watching starts. The server decrypts the session and
//! keeps its output for this page (a tap); the page fetches it every
//! quarter second (tick), feeds it to a terminal screen (libghostty-vt,
//! lib/core's vt) and draws the screen as HTML text, so it can be selected
//! and copied.

const std = @import("std");
const vt = @import("vt");
const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const fetch = @import("../fetch.zig");
const layout = @import("../layout.zig");
const router = @import("../router.zig");
const content = @import("../content.zig");

const Watch = struct {
    /// The server's tap
    tap: u64,
    /// How much of the tap's stream has been fetched
    offset: u64 = 0,
    screen: *vt.Screen,
    state: []const u8 = "connecting",
    sid_buf: [64]u8 = undefined,
    sid_len: usize = 0,
};

var watch: ?*Watch = null;

pub fn render(query: []const u8) void {
    if (!state.can("session", "watch")) return router.renderBadRequest();
    stop();
    dom.setBodyId("");
    layout.renderDefault("session");
    const sid = app.queryValue(query, "sid");
    const node = app.queryValue(query, "node");
    const key = app.queryValue(query, "key");
    var b: app.Buf = .{};
    content.header(&b, &.{ .{ "Sessions", "#/session" }, .{ node, "" }, .{ "Watch", "" } });
    content.commandStart(&b);
    b.raw("<a href=\"#/session\" class=\"button button-default button-sm\">Back</a>");
    if (state.can("session", "end")) b.add("<button type=\"button\" data-action=\"sessionEnd\" id=\"watch-end\" data-sid=\"{s}\" data-node=\"{f}\" data-key=\"{f}\" class=\"button button-error button-sm\" title=\"Ends the user's session on the node; leaving this page only stops watching.\">End session</button>", .{ sid, app.esc(node), app.esc(key) });
    b.raw("<span class=\"label label-default\" id=\"watch-state\">connecting</span>");
    content.commandEnd(&b);
    b.raw("<div class=\"row row-content\"><div class=\"col\"><div class=\"terminal\" id=\"watch-screen\"></div></div></div>");
    content.show(&b);

    const answer = fetch.post("session/watch_start", .{ node, key, sid }) orelse return;
    if (fetch.refused()) return;
    const tap = fetch.fieldAs(u64, answer, "data") orelse return;
    // The terminal needs no system (no files, no clock): an Io that does
    // nothing (a WASM page has none)
    const screen = vt.Screen.create(app.gpa, std.Io.failing, 80, 24) catch return;
    const w = app.gpa.create(Watch) catch {
        screen.destroy();
        return;
    };
    w.* = .{ .tap = tap, .screen = screen };
    w.sid_len = @min(sid.len, w.sid_buf.len);
    @memcpy(w.sid_buf[0..w.sid_len], sid[0..w.sid_len]);
    watch = w;
    tick();
}

/// Leaving the page (or a new watch) stops the server's tap.
pub fn stop() void {
    const w = watch orelse return;
    watch = null;
    _ = fetch.post("session/watch_stop", .{w.tap});
    w.screen.destroy();
    app.gpa.destroy(w);
}

pub fn watching() bool {
    return watch != null;
}

/// Every quarter second while the page is open (web/spa/boot.js).
pub fn tick() void {
    const w = watch orelse return;
    if (!dom.exists("watch-screen")) return stop();
    if (std.mem.eql(u8, w.state, "ended") or std.mem.eql(u8, w.state, "failed")) return;
    const Chunk = struct { data: []const u8, next: u64, state: []const u8 };
    const answer = fetch.post("session/watch_read", .{ w.tap, w.offset }) orelse {
        w.state = "failed";
        return showState(w);
    };
    const chunk = fetch.fieldAs(Chunk, answer, "data") orelse return;
    w.offset = chunk.next;
    const data = unbase64(chunk.data);
    // Records (service.zig Tap): 'r' cols rows (u16 each), 'd' len (u32) bytes
    var i: usize = 0;
    while (i < data.len) {
        if (data[i] == 'r' and i + 5 <= data.len) {
            w.screen.resize(std.mem.readInt(u16, data[i + 1 ..][0..2], .big), std.mem.readInt(u16, data[i + 3 ..][0..2], .big));
            i += 5;
        } else if (data[i] == 'd' and i + 5 <= data.len) {
            const n = std.mem.readInt(u32, data[i + 1 ..][0..4], .big);
            if (i + 5 + n > data.len) break;
            w.screen.feed(data[i + 5 ..][0..n]);
            i += 5 + n;
        } else break;
    }
    const changed = data.len > 0 or !std.mem.eql(u8, w.state, chunk.state);
    w.state = stateName(chunk.state);
    if (changed) draw(w);
}

fn stateName(s: []const u8) []const u8 {
    for ([_][]const u8{ "connecting", "live", "ended", "failed", "unreadable" }) |n| if (std.mem.eql(u8, n, s)) return n;
    return "failed";
}

fn showState(w: *Watch) void {
    const text = if (std.mem.eql(u8, w.state, "live")) "live" else if (std.mem.eql(u8, w.state, "ended")) "the session has ended" else if (std.mem.eql(u8, w.state, "unreadable")) "the session's output cannot be read" else if (std.mem.eql(u8, w.state, "failed")) "watching failed" else "connecting";
    dom.setHtml("watch-state", text);
    // An ended session cannot be ended again
    if (std.mem.eql(u8, w.state, "ended")) dom.addClass("watch-end", "hidden");
}

/// The screen as HTML: one line per row, a span per run of cells with the
/// same colors.
fn draw(w: *Watch) void {
    showState(w);
    const g = w.screen.grid(app.arena()) catch return;
    var b: app.Buf = .{};
    b.add("<pre style=\"background:#{x:0>6};margin:0;padding:8px;line-height:1.2;font-family:'DejaVu Sans Mono',monospace;font-size:14px;overflow:auto\">", .{g.background.hex()});
    var y: usize = 0;
    while (y < g.rows) : (y += 1) {
        var x: usize = 0;
        while (x < g.cols) {
            const c = g.cells[y * g.cols + x];
            const is_cursor = if (g.cursor) |cur| cur.x == x and cur.y == y else false;
            // A run of cells with the same look
            var end = x + 1;
            while (end < g.cols and !is_cursor) : (end += 1) {
                const d = g.cells[y * g.cols + end];
                const next_cursor = if (g.cursor) |cur| cur.x == end and cur.y == y else false;
                if (next_cursor or d.fg.hex() != c.fg.hex() or d.bg.hex() != c.bg.hex() or d.bold != c.bold or d.underline != c.underline) break;
            }
            const fg = if (is_cursor) c.bg else c.fg;
            const bg = if (is_cursor) c.fg else c.bg;
            b.add("<span style=\"color:#{x:0>6};background:#{x:0>6}{s}{s}\">", .{ fg.hex(), bg.hex(), if (c.bold) ";font-weight:bold" else "", if (c.underline) ";text-decoration:underline" else "" });
            for (g.cells[y * g.cols + x .. y * g.cols + end]) |cell| {
                if (cell.cp == 0) continue; // the second half of a wide character
                var enc: [4]u8 = undefined;
                const n = std.unicode.utf8Encode(cell.cp, &enc) catch continue;
                b.add("{f}", .{app.esc(enc[0..n])});
            }
            b.raw("</span>");
            x = end;
        }
        b.raw("\n");
    }
    b.raw("</pre>");
    dom.setHtml("watch-screen", b.str());
}

fn unbase64(text: []const u8) []const u8 {
    const dec = std.base64.standard.Decoder;
    const out = app.arena().alloc(u8, dec.calcSizeForSlice(text) catch return "") catch return "";
    dec.decode(out, text) catch return "";
    return out;
}
