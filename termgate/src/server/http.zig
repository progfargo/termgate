//! The web panel's HTTP side: the UI's files and the API the UI calls
//! (POST /api/<page>/<function>, JSON; see api.zig). The single-page app
//! is under /spa/, its style sheet and fonts under /asset/ (as in
//! our earlier project). Plain HTTP on localhost; nginx in front terminates HTTPS.

const std = @import("std");
const Io = std.Io;
const auth_mod = @import("auth.zig");
const panel_mod = @import("panel.zig");
const api_mod = @import("api.zig");

const log = std.log.scoped(.termgate);

pub const State = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Folder with the UI's files
    web_dir: []const u8,
    auth: *auth_mod.Auth,
    panel: *panel_mod.Panel,
};

/// The browser session's cookie. HttpOnly: the page's script cannot read
/// it. SameSite=Strict: other sites cannot make the browser send it.
/// Secure: only over HTTPS (browsers also accept it on localhost). Only
/// when the proxy in front says the browser came over plain HTTP
/// (X-Forwarded-Proto: http, a local setup without a certificate) is
/// Secure left out; otherwise the browser would never send the cookie
/// back and nobody could sign in.
const cookie_name = "tg_session";

/// The only files served, with their types (the WASM needs its own type to
/// be compiled while it downloads).
const files = [_]struct { path: []const u8, name: []const u8, mime: []const u8 }{
    // The single-page app's page; its other files are under /spa/
    .{ .path = "/", .name = "spa/index.html", .mime = "text/html; charset=utf-8" },
    .{ .path = "/index.html", .name = "spa/index.html", .mime = "text/html; charset=utf-8" },
    // Installing the panel as an app (PWA)
    .{ .path = "/manifest.webmanifest", .name = "manifest.webmanifest", .mime = "application/manifest+json" },
    .{ .path = "/icon-192.png", .name = "icon-192.png", .mime = "image/png" },
    .{ .path = "/icon-512.png", .name = "icon-512.png", .mime = "image/png" },
};

pub const Listener = struct {
    state: *State,
    server: Io.net.Server,
    tasks: Io.Group = .init,

    pub fn stop(l: *Listener) void {
        l.tasks.cancel(l.state.io);
        l.server.deinit(l.state.io);
        l.state.gpa.destroy(l);
    }
};

pub fn listen(state: *State, host: []const u8, port: u16) !*Listener {
    const addr = try Io.net.IpAddress.parse(host, port);
    const l = try state.gpa.create(Listener);
    errdefer state.gpa.destroy(l);
    l.* = .{ .state = state, .server = try addr.listen(state.io, .{ .reuse_address = true }) };
    errdefer l.server.deinit(state.io);
    try l.tasks.concurrent(state.io, acceptLoop, .{l});
    return l;
}

fn acceptLoop(l: *Listener) void {
    const io = l.state.io;
    while (true) {
        const stream = l.server.accept(io) catch |e| {
            if (e == error.Canceled) return;
            log.warn("accept: {s}", .{@errorName(e)});
            continue;
        };
        l.tasks.concurrent(io, serve, .{ l.state, stream }) catch stream.close(io);
    }
}

fn serve(state: *State, stream: Io.net.Stream) void {
    const io = state.io;
    defer stream.close(io);
    var in_buf: [16 * 1024]u8 = undefined;
    var out_buf: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &in_buf);
    var writer = stream.writer(io, &out_buf);
    var server: std.http.Server = .init(&reader.interface, &writer.interface);
    while (true) {
        var req = server.receiveHead() catch return;
        handle(state, &req) catch return;
        if (!req.head.keep_alive) return;
    }
}

fn handle(state: *State, req: *std.http.Server.Request) !void {
    const path = if (std.mem.indexOfScalar(u8, req.head.target, '?')) |q| req.head.target[0..q] else req.head.target;
    if (std.mem.startsWith(u8, path, "/api/")) return api(state, req, path["/api/".len..]);
    if (req.head.method != .GET and req.head.method != .HEAD) return req.respond("", .{ .status = .method_not_allowed });
    if (std.mem.startsWith(u8, path, "/spa/") or std.mem.startsWith(u8, path, "/asset/")) return staticFile(state, req, path[1..]);
    for (files) |f| {
        if (!std.mem.eql(u8, path, f.path)) continue;
        const full = try std.fs.path.join(state.gpa, &.{ state.web_dir, f.name });
        defer state.gpa.free(full);
        const data = Io.Dir.cwd().readFileAlloc(state.io, full, state.gpa, .limited(64 << 20)) catch
            return req.respond("not found", .{ .status = .not_found });
        defer state.gpa.free(data);
        return req.respond(data, .{ .extra_headers = &.{
            .{ .name = "content-type", .value = f.mime },
            .{ .name = "cache-control", .value = "no-cache" },
        } });
    }
    return req.respond("not found", .{ .status = .not_found });
}

/// A file of the single-page app or its assets, by its path under the
/// panel's folder. Only plain names: letters, digits, "-", "_", "." and
/// "/", no "..".
fn staticFile(state: *State, req: *std.http.Server.Request, rel: []const u8) !void {
    const plain = blk: {
        if (std.mem.indexOf(u8, rel, "..") != null or rel.len == 0 or rel[rel.len - 1] == '/') break :blk false;
        for (rel) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.' and ch != '/') break :blk false;
        break :blk true;
    };
    if (!plain) return req.respond("not found", .{ .status = .not_found });
    const full = try std.fs.path.join(state.gpa, &.{ state.web_dir, rel });
    defer state.gpa.free(full);
    const data = Io.Dir.cwd().readFileAlloc(state.io, full, state.gpa, .limited(64 << 20)) catch
        return req.respond("not found", .{ .status = .not_found });
    defer state.gpa.free(data);
    return req.respond(data, .{ .extra_headers = &.{
        .{ .name = "content-type", .value = mimeOf(rel) },
        .{ .name = "cache-control", .value = "no-cache" },
    } });
}

fn mimeOf(name: []const u8) []const u8 {
    const types = [_]struct { []const u8, []const u8 }{
        .{ ".html", "text/html; charset=utf-8" },
        .{ ".js", "text/javascript; charset=utf-8" },
        .{ ".css", "text/css; charset=utf-8" },
        .{ ".wasm", "application/wasm" },
        .{ ".woff2", "font/woff2" },
        .{ ".ttf", "font/ttf" },
        .{ ".png", "image/png" },
        .{ ".svg", "image/svg+xml" },
        .{ ".json", "application/json" },
        .{ ".webmanifest", "application/manifest+json" },
    };
    for (types) |t| if (std.mem.endsWith(u8, name, t[0])) return t[1];
    return "application/octet-stream";
}

/// POST /api/<name>: JSON in, JSON out. Calls must carry the header
/// "x-termgate: 1": a form on another site cannot set it, so it cannot make
/// a signed-in browser call the API.
fn api(state: *State, req: *std.http.Server.Request, name: []const u8) !void {
    if (req.head.method != .POST) return req.respond("", .{ .status = .method_not_allowed });
    var arena: std.heap.ArenaAllocator = .init(state.gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var token: ?[]const u8 = null;
    // The single-page app says so (x-termgate: spa), which a form on
    // another site cannot
    var marked = false;
    var plain_http = false;
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-termgate")) marked = std.mem.eql(u8, h.value, "spa");
        if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-proto")) plain_http = std.ascii.eqlIgnoreCase(h.value, "http");
        if (std.ascii.eqlIgnoreCase(h.name, "cookie")) token = try cookie(a, h.value);
    }
    // The panel's API (api.zig): a page path stands for one of the calls
    // below, and its answer is given in our earlier project's form
    const call_name = if (!std.mem.eql(u8, name, "init")) api_mod.route(name) orelse
        return req.respond("{\"messages\":[{\"name\":\"notFound\",\"type\":\"error\",\"lines\":[\"Unknown call.\"]}]}", .{ .status = .not_found }) else name;
    const len = req.head.content_length orelse 0;
    if (len > 1 << 20) return req.respond("", .{ .status = .payload_too_large });
    var body_buf: [4096]u8 = undefined;
    const body_reader = req.readerExpectNone(&body_buf);
    const body = try body_reader.readAlloc(a, @intCast(len));

    const json: std.http.Header = .{ .name = "content-type", .value = "application/json" };
    if (!marked) return req.respond("{\"error\":\"missing x-termgate header\"}", .{ .status = .forbidden, .extra_headers = &.{json} });
    const now: i64 = @intCast(@divFloor(Io.Timestamp.now(state.io, .real).nanoseconds, std.time.ns_per_s));
    if (std.mem.eql(u8, name, "init")) return req.respond(try api_mod.init(state.auth, a, token, now), .{ .extra_headers = &.{json} });
    return call(state, req, a, call_name, body, token, plain_http, now);
}

/// Runs a call (by its internal name) and answers it in the panel API's
/// form.
fn call(state: *State, req: *std.http.Server.Request, a: std.mem.Allocator, name: []const u8, body: []const u8, token: ?[]const u8, plain_http: bool, now: i64) !void {
    const json: std.http.Header = .{ .name = "content-type", .value = "application/json" };

    // Who is calling, and what a changing call is about, before it runs
    const who = try auth_mod.caller(state.auth, a, token, now);
    const recorded = who != null and panel_mod.changes(name);
    const detail = if (recorded) panel_mod.describe(state.panel, a, name, body) else "";
    if (try auth_mod.call(state.auth, a, name, body, token, now)) |r| {
        if (recorded) {
            panel_mod.record(state.panel, now, who.?.auditName(a), name, detail, r.status == .ok);
            // A change may take a user's right to connect to nodes
            if (r.status == .ok) panel_mod.enforceTerminal(state.panel);
        }
        // Sign-ins are recorded too, the failed ones with the name tried
        if (std.mem.eql(u8, name, "login") and r.status != .ok) panel_mod.record(state.panel, now, "", name, signInName(a, body), false);
        // Built without the second step, the password alone signs in
        if (std.mem.eql(u8, name, "login") and r.status == .ok and !state.auth.second_step) panel_mod.record(state.panel, now, signInName(a, body), "login", "signed in (no second step)", true);
        if (std.mem.eql(u8, name, "login2")) {
            const signed = if (r.status == .ok) (try auth_mod.caller(state.auth, a, token, now)) else null;
            panel_mod.record(state.panel, now, if (signed) |s| s.name else "", "login", if (r.status == .ok) "signed in" else "wrong code", r.status == .ok);
        }
        var headers: [2]std.http.Header = .{ json, undefined };
        var n: usize = 1;
        if (r.set_token) |t| {
            headers[1] = .{ .name = "set-cookie", .value = try std.fmt.allocPrint(a, cookie_name ++ "={s}; Max-Age={d}; Path=/; HttpOnly; SameSite=Strict{s}", .{ t, r.token_max_age, if (plain_http) "" else "; Secure" }) };
            n = 2;
        } else if (r.clear_token) {
            headers[1] = .{ .name = "set-cookie", .value = if (plain_http) cookie_name ++ "=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict" else cookie_name ++ "=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict; Secure" };
            n = 2;
        }
        const out = try api_mod.answer(a, r.status, r.body);
        return req.respond(out.body, .{ .status = out.status, .extra_headers = headers[0..n] });
    }
    // Everything else is for signed-in users
    const user = who orelse {
        const out = try api_mod.answer(a, .unauthorized, "{\"error\":\"not signed in\"}");
        return req.respond(out.body, .{ .status = out.status, .extra_headers = &.{json} });
    };
    if (try panel_mod.call(state.panel, a, name, body, &user, now)) |r| {
        if (recorded) panel_mod.record(state.panel, now, user.auditName(a), name, detail, r.status == .ok and !std.mem.startsWith(u8, r.body, "{\"err\""));
        if (recorded and r.status == .ok) panel_mod.enforceTerminal(state.panel);
        const out = try api_mod.answer(a, r.status, r.body);
        return req.respond(out.body, .{ .status = out.status, .extra_headers = &.{json} });
    }
    return req.respond("{\"error\":\"unknown call\"}", .{ .status = .not_found, .extra_headers = &.{json} });
}

/// The name a sign-in was tried with (never the password).
fn signInName(a: std.mem.Allocator, body: []const u8) []const u8 {
    const Req = struct { name: []const u8 = "" };
    const r = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return "";
    return r.name;
}

/// The session token in a Cookie header, copied into `a`.
fn cookie(a: std.mem.Allocator, header: []const u8) !?[]const u8 {
    var parts = std.mem.splitScalar(u8, header, ';');
    while (parts.next()) |p| {
        const kv = std.mem.trim(u8, p, " ");
        if (std.mem.startsWith(u8, kv, cookie_name ++ "=")) return try a.dupe(u8, kv[cookie_name.len + 1 ..]);
    }
    return null;
}

test "the session cookie is found among others" {
    const a = std.testing.allocator;
    const t = (try cookie(a, "theme=dark; tg_session=abc123; other=1")).?;
    defer a.free(t);
    try std.testing.expectEqualStrings("abc123", t);
    try std.testing.expect(try cookie(a, "theme=dark; xtg_session=abc") == null);
}
