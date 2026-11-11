//! An interactive session on a node, in the user's own terminal.
//!
//! Opens the session (signed request on session.open.<node>), then relays:
//! stdin -> in.<node>.<user>.<sid>.data, window size -> .resize,
//! out.<node>.<user>.<sid>.data -> stdout until .end arrives. "~." at the
//! start of a line closes the session (sends .end), as in ssh.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const c = @import("c");
const term = @import("term.zig");
const Profile = @import("profile.zig").Profile;

/// Exit code of tgterm for a session that could not be opened.
pub const failed: u8 = 1;

fn now(io: Io) i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

fn writeAll(fd: c_int, data: []const u8) void {
    var rest = data;
    while (rest.len > 0) {
        const n = c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return;
        rest = rest[@intCast(n)..];
    }
}

fn say(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeAll(2, s);
}

const Shared = struct {
    conn: *Conn,
    io: Io,
    in_prefix: []const u8,
    /// Keys typed, encrypted to the node (end to end)
    input: core.e2e.Sealer,
    gpa: std.mem.Allocator,
    done: std.atomic.Value(bool) = .init(false),
};

/// Runs a session on `node`; returns tgterm's exit code.
pub fn run(gpa: std.mem.Allocator, io: Io, p: Profile, node: []const u8) !u8 {
    if (!core.node.isValidName(node)) {
        say("tgterm: invalid node name \"{s}\"\n", .{node});
        return failed;
    }
    const key = try core.nkeys.KeyPair.decodeSeed(p.seed);
    const upub = key.publicKey().encode();
    var inbox_buf: [80]u8 = undefined;
    const conn = Conn.connect(gpa, io, .{
        .host = p.relay_host,
        .port = p.relay_port,
        .key = key,
        .name = "tgterm",
        .inbox_prefix = try std.fmt.bufPrint(&inbox_buf, "_INBOX.{s}", .{upub}),
        .tls = if (p.ca_pem.len > 0) .{ .ca_pem = p.ca_pem } else null,
    }) catch |e| {
        say("tgterm: cannot connect to {s}:{d}: {s}\n", .{ p.relay_host, p.relay_port, @errorName(e) });
        return failed;
    };
    defer conn.close();

    // Our grant: who issued it (termgate, as we got it with the invitation)
    // and its id, to check termgate's approval against
    const g = core.jwt.decodeLeeway(gpa, core.grant.GrantClaims, p.grant, now(io), std.math.maxInt(i32)) catch {
        say("tgterm: the stored grant is not valid; use a new invitation\n", .{});
        return failed;
    };
    defer g.deinit();

    // Open the session, with our session public key (end to end)
    const eph = core.e2e.Ephemeral.generate(io);
    const user_kx = eph.publicText();
    const req = try core.session.create(gpa, io, key, p.grant, node, &user_kx, now(io));
    defer req.deinit(gpa);
    var subj_buf: [160]u8 = undefined;
    const answer = conn.request(try std.fmt.bufPrint(&subj_buf, "session.open.{s}", .{node}), req.body, Conn.seconds(20)) catch |e| {
        say("tgterm: {s}: {s}\n", .{ node, switch (e) {
            error.NoResponders => "node is offline",
            error.Timeout => "no answer from the node",
            else => @errorName(e),
        } });
        return failed;
    };
    defer answer.deinit(gpa);
    const Reply = struct { sid: ?[]const u8 = null, approval: ?[]const u8 = null, @"error": ?[]const u8 = null };
    const reply = std.json.parseFromSlice(Reply, gpa, answer.payload, .{ .ignore_unknown_fields = true }) catch {
        say("tgterm: {s}: unexpected answer\n", .{node});
        return failed;
    };
    defer reply.deinit();
    if (reply.value.@"error") |why| {
        say("tgterm: {s}: {s}\n", .{ node, why });
        return failed;
    }
    // The node's session key, from termgate's signed approval: the relay
    // cannot have swapped it
    const ok = core.approval.verifyForUser(gpa, reply.value.approval orelse "", .{
        .issuers = &.{g.value.iss},
        .user = &upub,
        .grant_jti = g.value.jti orelse "",
        .node = node,
        .nonce = &req.nonce,
        .kx_user = &user_kx,
        .now = now(io),
    }) catch |e| {
        say("tgterm: {s}: the session is not approved by termgate ({s})\n", .{ node, @errorName(e) });
        return failed;
    };
    defer gpa.free(ok.sid);
    defer gpa.free(ok.kx_node);
    const sid = ok.sid;
    const keys = eph.keys(core.e2e.decodePublic(ok.kx_node) catch return failed, sid, &user_kx, ok.kx_node) catch return failed;
    var output: core.e2e.Opener = .{ .key = keys.down };

    var out_buf: [160]u8 = undefined;
    const out = try conn.subscribe(try std.fmt.bufPrint(&out_buf, "out.{s}.{s}.{s}.*", .{ node, &upub, sid }));
    try conn.flush(Conn.seconds(10));
    var in_buf: [160]u8 = undefined;
    var shared: Shared = .{
        .conn = conn,
        .io = io,
        .in_prefix = try std.fmt.bufPrint(&in_buf, "in.{s}.{s}.{s}", .{ node, &upub, sid }),
        .input = .{ .key = keys.up, .sender = .user },
        .gpa = gpa,
    };

    // Terminal: raw mode while the session runs
    const interactive = term.isTerminal(0);
    const raw: ?term.Raw = if (interactive) term.Raw.enter(0) catch null else null;
    defer if (raw) |r| r.restore();

    var resize_task = try io.concurrent(watchSize, .{&shared});
    defer resize_task.cancel(io);
    // Reads stdin until the process exits; not awaited (a blocked read
    // cannot be interrupted portably). tgterm exits right after run().
    _ = try io.concurrent(pumpInput, .{&shared});

    var closed_by_node = false;
    while (!shared.done.load(.acquire)) {
        const m = out.next(Conn.seconds(1)) catch |e| switch (e) {
            error.Timeout => continue,
            else => break,
        };
        defer m.deinit(gpa);
        if (std.mem.endsWith(u8, m.subject, ".end")) {
            closed_by_node = true;
            break;
        }
        // Only what the node (or termgate) encrypted is shown
        const plain = output.open(gpa, m.payload) catch continue;
        defer gpa.free(plain);
        writeAll(1, plain);
    }
    if (!closed_by_node) {
        var end_buf: [200]u8 = undefined;
        conn.publish(std.fmt.bufPrint(&end_buf, "{s}.end", .{shared.in_prefix}) catch "", "") catch {};
        conn.flush(Conn.seconds(2)) catch {};
    }
    if (raw) |r| r.restore();
    say("\r\nConnection to {s} closed.\r\n", .{node});
    return 0;
}

fn pumpInput(s: *Shared) void {
    var data_buf: [200]u8 = undefined;
    const data_subject = std.fmt.bufPrint(&data_buf, "{s}.data", .{s.in_prefix}) catch return;
    var escape: term.Escape = .{};
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = c.read(0, &buf, buf.len);
        if (n <= 0) break; // end of input
        const chunk = buf[0..@intCast(n)];
        for (chunk, 0..) |b, i| {
            if (escape.feed(b)) {
                // Send what came before "~." (minus the "~"), then close
                if (i > 1) _ = send(s, data_subject, chunk[0 .. i - 1]);
                s.done.store(true, .release);
                return;
            }
        }
        if (!send(s, data_subject, chunk)) break;
    }
    // stdin closed (e.g. piped input ended): close the session
    s.done.store(true, .release);
}

/// Encrypts and sends keys; false when the connection is gone.
fn send(s: *Shared, subject: []const u8, plain: []const u8) bool {
    const sealed = s.input.seal(s.gpa, plain) catch return false;
    defer s.gpa.free(sealed);
    s.conn.publish(subject, sealed) catch return false;
    return true;
}

fn watchSize(s: *Shared) void {
    var resize_buf: [200]u8 = undefined;
    const subject = std.fmt.bufPrint(&resize_buf, "{s}.resize", .{s.in_prefix}) catch return;
    var last: ?term.Size = null;
    while (!s.done.load(.acquire)) {
        if (term.size(0) orelse term.size(1)) |sz| {
            if (last == null or last.?.cols != sz.cols or last.?.rows != sz.rows) {
                const msg = term.encodeSize(sz);
                s.conn.publish(subject, &msg) catch return;
                last = sz;
            }
        }
        s.io.sleep(.fromMilliseconds(250), .awake) catch return;
    }
}
