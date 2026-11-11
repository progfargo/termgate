//! The running agent: connects to the relay, reports its system info and
//! serves terminal sessions.
//!
//! No heartbeat: termgate sees the node's connection come and go through the
//! relay's connection events. System info goes to status.<node> once after
//! connecting and whenever termgate asks (status.req.<node>, status.req.all).
//!
//! Session flow (see docs/architecture.md):
//!   session.open.<node>  request from tgterm, verified (grant, signature,
//!                        freshness, replay)
//!   authorize.<node>     request to termgate; its signed approval must match
//!   PTY                  reply {"sid": ..., "approval": ...} to tgterm
//!
//! Session data is end-to-end encrypted (core e2e.zig): tgterm's session
//! public key comes in the signed request, this node's goes to termgate in
//! the approval request (with the session keys sealed to termgate) and
//! back in termgate's signed approval, which tgterm checks.
//!   out.<node>.<user>.<sid>.data|end    terminal output, session closed
//!   in.<node>.<user>.<sid>.data|resize|end   input, window size, close
//!   audit.<node>         session end, retried until termgate acknowledges
//!
//! termgate closed means the system is closed: while sessions are open the
//! node asks termgate every few seconds whether it is there (audit.<node>,
//! event "alive"). Without an answer for termgate_grace_s the open sessions
//! are ended: nobody would log, watch or time-limit them. The grace covers
//! a termgate restart or a short relay outage.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const Config = @import("config.zig").Config;
const pty = @import("pty.zig");
const sysinfo = @import("sysinfo.zig");

const log = std.log.scoped(.tgnode);

/// How long to wait for termgate's approval.
const approval_timeout_s = 10;
/// Session end events are retried this often and this many times.
const audit_retry_s = 5;
const audit_attempts = 60;

/// Connects and serves; when the connection cannot be made or is lost (relay
/// restarting, termgate not answering the auth callout yet, network down),
/// tries again after 2 s, doubling up to 30 s, for ever. A node in the field
/// must never give up.
pub fn serveForever(gpa: std.mem.Allocator, io: Io, cfg: Config, key: core.nkeys.KeyPair, root: Io.Dir) !void {
    var backoff_s: i64 = 2;
    while (true) {
        if (Agent.connect(gpa, io, cfg, key, root)) |a| {
            backoff_s = 2;
            a.run() catch |e| log.warn("connection lost: {s}", .{@errorName(e)});
            a.deinit();
        } else |e| {
            log.warn("cannot connect to {s}:{d}: {s}; retrying in {d} s", .{ cfg.relay_host, cfg.relay_port, @errorName(e), backoff_s });
        }
        try io.sleep(.fromSeconds(backoff_s), .awake);
        backoff_s = @min(backoff_s * 2, 30);
    }
}

pub const Agent = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    key: core.nkeys.KeyPair,
    conn: *Conn,
    /// Used only by the session.open loop, so no lock is needed
    replay: core.session.ReplayCache,
    sessions: Io.Group = .init,
    /// Trusted signers of grants and approvals: termgate's issuer key
    issuers: [1][]const u8,
    /// Root for sysinfo (/ in production)
    root: Io.Dir,
    /// Sessions open now
    open_sessions: std.atomic.Value(u32) = .init(0),
    /// Set while termgate has been unreachable for too long: open sessions
    /// end themselves
    cut: std.atomic.Value(bool) = .init(false),
    /// Cleared when run() ends; stops the watchdog
    serving: std.atomic.Value(bool) = .init(false),
    /// How long termgate may be unreachable before sessions are ended,
    /// and how often it is asked
    termgate_grace_s: i64 = 60,
    termgate_check_s: i64 = 10,

    pub fn connect(gpa: std.mem.Allocator, io: Io, cfg: Config, key: core.nkeys.KeyPair, root: Io.Dir) !*Agent {
        var inbox_buf: [80]u8 = undefined;
        const inbox = try std.fmt.bufPrint(&inbox_buf, "_INBOX.{s}", .{cfg.name});
        const a = try gpa.create(Agent);
        errdefer gpa.destroy(a);
        const inbox_owned = try gpa.dupe(u8, inbox);
        errdefer gpa.free(inbox_owned);
        a.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .key = key,
            .conn = try Conn.connect(gpa, io, .{
                .host = cfg.relay_host,
                .port = cfg.relay_port,
                .key = key,
                .name = cfg.name,
                .inbox_prefix = inbox_owned,
                .tls = if (cfg.ca_pem.len > 0) .{ .ca_pem = cfg.ca_pem } else null,
            }),
            .replay = .init(gpa),
            .root = root,
            .issuers = .{cfg.issuer},
        };
        return a;
    }

    pub fn deinit(a: *Agent) void {
        const inbox = a.conn.inbox_prefix;
        a.sessions.cancel(a.io);
        a.conn.close();
        a.replay.deinit();
        a.gpa.free(inbox);
        a.gpa.destroy(a);
    }

    fn now(a: *Agent) i64 {
        return @intCast(@divFloor(Io.Timestamp.now(a.io, .real).nanoseconds, std.time.ns_per_s));
    }

    /// Serves until the connection closes.
    pub fn run(a: *Agent) !void {
        var buf: [3][96]u8 = undefined;
        const open_sub = try a.conn.subscribe(try std.fmt.bufPrint(&buf[0], "session.open.{s}", .{a.cfg.name}));
        const req_sub = try a.conn.subscribe(try std.fmt.bufPrint(&buf[1], "status.req.{s}", .{a.cfg.name}));
        const all_sub = try a.conn.subscribe("status.req.all");
        a.serving.store(true, .release);
        var watchdog = try a.io.concurrent(watchTermgate, .{a});
        defer {
            a.serving.store(false, .release);
            watchdog.cancel(a.io);
        }
        a.publishStatus() catch |e| switch (e) {
            error.Canceled => return e,
            else => log.warn("status: {s}", .{@errorName(e)}),
        };
        log.info("{s}: serving", .{a.cfg.name});

        while (true) {
            if (try nextOrNull(open_sub, 200)) |m| {
                defer m.deinit(a.gpa);
                if (m.reply) |reply| a.handleOpen(m.payload, reply) catch |e| {
                    log.warn("session.open failed: {s}", .{@errorName(e)});
                    a.replyError(reply, @errorName(e));
                };
            }
            // Several requests at once (both subjects) need one answer
            var asked = false;
            for ([_]*Conn.Sub{ req_sub, all_sub }) |sub| {
                while (try nextOrNull(sub, 0)) |m| {
                    m.deinit(a.gpa);
                    asked = true;
                }
            }
            if (asked) a.publishStatus() catch |e| switch (e) {
                error.Canceled => return e,
                else => log.warn("status: {s}", .{@errorName(e)}),
            };
        }
    }

    /// While sessions are open: is termgate there? Sets `cut` after
    /// termgate_grace_s without an answer, clears it when termgate answers.
    fn watchTermgate(a: *Agent) void {
        var subj_buf: [96]u8 = undefined;
        const subject = std.fmt.bufPrint(&subj_buf, "audit.{s}", .{a.cfg.name}) catch return;
        var last_ok = a.now();
        var last_check: i64 = 0;
        while (a.serving.load(.acquire)) {
            a.io.sleep(.fromMilliseconds(200), .awake) catch return;
            const t = a.now();
            if (a.open_sessions.load(.acquire) == 0) {
                last_ok = t;
                a.cut.store(false, .release);
                continue;
            }
            if (t - last_check < a.termgate_check_s) continue;
            last_check = t;
            var body_buf: [96]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "{{\"event\":\"alive\",\"sid\":\"\",\"at\":{d}}}", .{t}) catch return;
            if (a.conn.request(subject, body, Conn.seconds(5))) |ack| {
                ack.deinit(a.gpa);
                last_ok = a.now();
                a.cut.store(false, .release);
            } else |e| {
                if (e == error.Canceled) return;
                if (a.now() - last_ok >= a.termgate_grace_s and !a.cut.swap(true, .acq_rel))
                    log.warn("termgate unreachable for {d} s: ending open sessions", .{a.now() - last_ok});
            }
        }
    }

    /// The next message, or null after `ms` milliseconds without one.
    fn nextOrNull(sub: *Conn.Sub, ms: i64) !?Conn.Message {
        return sub.next(Conn.millis(ms)) catch |e| switch (e) {
            error.Timeout => null,
            else => e,
        };
    }

    /// System info (memory, disk, uptime, version) to status.<node>.
    fn publishStatus(a: *Agent) !void {
        var arena: std.heap.ArenaAllocator = .init(a.gpa);
        defer arena.deinit();
        const al = arena.allocator();
        const status = try sysinfo.collect(al, a.io, a.root, "/");
        const body = try std.json.Stringify.valueAlloc(al, status, .{});
        try a.conn.publish(try std.fmt.allocPrint(al, "status.{s}", .{a.cfg.name}), body);
    }

    fn replyError(a: *Agent, reply: []const u8, msg: []const u8) void {
        const body = std.json.Stringify.valueAlloc(a.gpa, .{ .@"error" = msg }, .{}) catch return;
        defer a.gpa.free(body);
        a.conn.publish(reply, body) catch {};
    }

    fn handleOpen(a: *Agent, body: []const u8, reply: []const u8) !void {
        const gpa = a.gpa;
        const v = try core.session.verify(gpa, body, .{
            .issuers = &a.issuers,
            .node = a.cfg.name,
            .now = a.now(),
            .replay = &a.replay,
        });
        defer v.deinit();
        const g = v.grant.value;

        // Session id: 16 random bytes, base64url (a valid subject token)
        var raw: [16]u8 = undefined;
        a.io.random(&raw);
        var sid: [22]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&sid, &raw);

        // Session keys: tgterm's public key (signed in the request) and ours
        const user_kx = try core.e2e.decodePublic(v.kx);
        const eph = core.e2e.Ephemeral.generate(a.io);
        const node_kx = eph.publicText();
        const keys = try eph.keys(user_kx, &sid, v.kx, &node_kx);
        const issuer = try core.nkeys.PublicKey.decode(a.cfg.issuer);
        const keys_box = try core.e2e.sealForTermgate(gpa, a.io, issuer, keys, &sid, v.kx, &node_kx);
        defer gpa.free(keys_box);

        // Ask termgate
        const areq: core.approval.Request = .{ .grant = v.grant_token, .node = a.cfg.name, .nonce = v.nonce, .sid = &sid, .kx_user = v.kx, .kx_node = &node_kx, .keys = keys_box };
        const areq_json = try std.json.Stringify.valueAlloc(gpa, areq, .{});
        defer gpa.free(areq_json);
        var auth_buf: [96]u8 = undefined;
        const auth_subject = try std.fmt.bufPrint(&auth_buf, "authorize.{s}", .{a.cfg.name});
        const answer = a.conn.request(auth_subject, areq_json, Conn.seconds(approval_timeout_s)) catch |e| switch (e) {
            error.NoResponders, error.Timeout => {
                a.replyError(reply, "termgate is offline");
                return;
            },
            else => return e,
        };
        defer answer.deinit(gpa);

        const expect: core.approval.Expect = .{ .issuers = &a.issuers, .request = areq, .user = g.sub, .grant_jti = g.jti orelse "", .now = a.now() };
        core.approval.verify(gpa, answer.payload, expect) catch |e| switch (e) {
            error.Denied => {
                const why = try core.approval.denialReason(gpa, answer.payload, expect);
                defer gpa.free(why);
                a.replyError(reply, why);
                return;
            },
            else => return e,
        };

        // termgate answered: it is there
        a.cut.store(false, .release);
        // Open the shell and hand the session to its own task
        const s = try Session.create(a, g.sub, g.jti orelse "", &sid, keys);
        errdefer {
            s.shell.hangup();
            _ = s.shell.wait();
            s.destroy();
        }
        // tgterm takes our session key from termgate's signed approval
        const ok = try std.json.Stringify.valueAlloc(gpa, .{ .sid = @as([]const u8, &sid), .approval = answer.payload }, .{});
        defer gpa.free(ok);
        // Subscribe to the input before answering, so nothing tgterm sends
        // right after the reply (first resize, first keys) is lost
        s.sub = try a.conn.subscribe(s.in_subject);
        errdefer s.sub.?.unsubscribe();
        try a.conn.flush(Conn.seconds(5));
        try a.sessions.concurrent(a.io, Session.run, .{s});
        try a.conn.publish(reply, ok);
        log.info("session {s} opened for {s}", .{ &sid, g.sub });
    }
};

const Session = struct {
    agent: *Agent,
    shell: pty.Shell,
    user: []u8,
    grant_jti: []u8,
    sid: [22]u8,
    /// out.<node>.<user>.<sid> (".data" / ".end" appended when publishing)
    out_subject: []u8,
    in_subject: []u8,
    /// Input subscription, made before the session is announced
    sub: ?*Conn.Sub = null,
    /// Input from the user (decrypted), output to the user (encrypted)
    input: core.e2e.Opener,
    output: core.e2e.Sealer,
    /// Output is sent by the pump and, for a last message, by run()
    output_lock: Io.Mutex = .init,
    done: std.atomic.Value(bool) = .init(false),

    fn create(a: *Agent, user: []const u8, grant_jti: []const u8, sid: *const [22]u8, keys: core.e2e.Keys) !*Session {
        const gpa = a.gpa;
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        const shell = try pty.spawn(gpa, .{});
        errdefer {
            shell.hangup();
            _ = shell.wait();
        }
        s.* = .{
            .agent = a,
            .input = .{ .key = keys.up },
            .output = .{ .key = keys.down, .sender = .node },
            .shell = shell,
            .user = try gpa.dupe(u8, user),
            .grant_jti = try gpa.dupe(u8, grant_jti),
            .sid = sid.*,
            .out_subject = try std.fmt.allocPrint(gpa, "out.{s}.{s}.{s}", .{ a.cfg.name, user, sid }),
            .in_subject = try std.fmt.allocPrint(gpa, "in.{s}.{s}.{s}.*", .{ a.cfg.name, user, sid }),
        };
        return s;
    }

    fn destroy(s: *Session) void {
        const gpa = s.agent.gpa;
        gpa.free(s.user);
        gpa.free(s.grant_jti);
        gpa.free(s.out_subject);
        gpa.free(s.in_subject);
        gpa.destroy(s);
    }

    /// Runs the session: output pump on its own task, input here. Ends when
    /// the shell exits or an .end arrives; then reports the end to termgate.
    fn run(s: *Session) void {
        const a = s.agent;
        const io = a.io;
        defer s.destroy();

        const sub = s.sub.?;
        _ = a.open_sessions.fetchAdd(1, .release);
        var pump = io.concurrent(pumpOutput, .{s}) catch {
            _ = a.open_sessions.fetchSub(1, .release);
            sub.unsubscribe();
            s.shell.hangup();
            _ = s.shell.wait();
            return;
        };

        while (!s.done.load(.acquire)) {
            if (a.cut.load(.acquire)) {
                _ = s.send("\r\n[tgnode: termgate is not reachable; the session is closed]\r\n");
                break;
            }
            const m = sub.next(Conn.seconds(1)) catch |e| switch (e) {
                error.Timeout => continue,
                else => break,
            };
            defer m.deinit(a.gpa);
            const kind = m.subject[std.mem.lastIndexOfScalar(u8, m.subject, '.').? + 1 ..];
            if (std.mem.eql(u8, kind, "data")) {
                // Only what tgterm encrypted is typed; anything else is dropped
                const plain = s.input.open(a.gpa, m.payload) catch |e| {
                    log.warn("session {s}: input dropped: {s}", .{ &s.sid, @errorName(e) });
                    continue;
                };
                defer a.gpa.free(plain);
                s.shell.write(plain) catch break;
            } else if (std.mem.eql(u8, kind, "resize") and m.payload.len == 4) {
                s.shell.resize(.{
                    .cols = std.mem.readInt(u16, m.payload[0..2], .big),
                    .rows = std.mem.readInt(u16, m.payload[2..4], .big),
                });
            } else if (std.mem.eql(u8, kind, "end")) {
                break;
            }
        }
        sub.unsubscribe();
        s.shell.hangup();
        pump.await(io);
        const status = s.shell.wait();
        // Tell the user's terminal that the session is over
        var subj: [160]u8 = undefined;
        if (std.fmt.bufPrint(&subj, "{s}.end", .{s.out_subject})) |end| {
            a.conn.publish(end, "") catch {};
        } else |_| {}
        // Closed for the watchdog before the (possibly long) end report
        _ = a.open_sessions.fetchSub(1, .release);
        s.reportEnd(status);
    }

    fn pumpOutput(s: *Session) void {
        defer s.done.store(true, .release);
        var buf: [16 * 1024]u8 = undefined;
        while (true) {
            const n = s.shell.read(&buf) catch return;
            if (n == 0) return;
            if (!s.send(buf[0..n])) return;
        }
    }

    /// Encrypts and publishes output; false when it could not be sent.
    fn send(s: *Session, bytes: []const u8) bool {
        const a = s.agent;
        var subj: [160]u8 = undefined;
        const data = std.fmt.bufPrint(&subj, "{s}.data", .{s.out_subject}) catch return false;
        s.output_lock.lockUncancelable(a.io);
        defer s.output_lock.unlock(a.io);
        const sealed = s.output.seal(a.gpa, bytes) catch return false;
        defer a.gpa.free(sealed);
        a.conn.publish(data, sealed) catch return false;
        return true;
    }

    /// Sends the session end to audit.<node> until termgate acknowledges it.
    fn reportEnd(s: *Session, status: c_int) void {
        const a = s.agent;
        const body = std.json.Stringify.valueAlloc(a.gpa, .{
            .event = "end",
            .node = a.cfg.name,
            .sid = @as([]const u8, &s.sid),
            .user = s.user,
            .grant = s.grant_jti,
            .at = a.now(),
            .status = status,
        }, .{}) catch return;
        defer a.gpa.free(body);
        var subj_buf: [96]u8 = undefined;
        const subject = std.fmt.bufPrint(&subj_buf, "audit.{s}", .{a.cfg.name}) catch return;
        for (0..audit_attempts) |_| {
            if (a.conn.request(subject, body, Conn.seconds(5))) |ack| {
                ack.deinit(a.gpa);
                return;
            } else |e| {
                // Cancellation arrives once: do not swallow it and go on
                // retrying for minutes
                if (e == error.Canceled or e == error.ConnectionClosed) return;
            }
            a.io.sleep(.fromSeconds(audit_retry_s), .awake) catch return;
        }
        log.warn("session {s}: end not acknowledged by termgate", .{&s.sid});
    }
};
