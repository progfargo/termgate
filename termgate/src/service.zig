//! termgate on the relay: the decisions the rest of the system waits for.
//!
//! Three connections to the relay:
//!   - the callout connection (termgate's user in the AUTH account) answers
//!     $SYS.REQ.USER.AUTH for every client connection;
//!   - the application connection, which termgate's own callout lets into the
//!     account where nodes and users are, serves ca.get, register.<id>,
//!     access.<id>, authorize.<node>, audit.<node>, records status.<node>,
//!     and follows every session (out.*.*.*.*, in.*.*.*.data) into the
//!     recorder, which writes the session logs;
//!   - the system connection (termgate's user in the SYS account) follows
//!     connections coming and going in that account (which nodes are online;
//!     nodes send no heartbeat) and closes the connection of a node that is
//!     disabled or deleted and of a user who may not connect any more.
//!
//! Every decision reads the database. The UI uses the same database; all
//! access from here goes through `lock`, which the UI must hold as well.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const Conn = core.nats.Conn;
const KeyPair = core.nkeys.KeyPair;
const dbm = @import("db");
const Recorder = @import("recorder").Recorder;

const log = std.log.scoped(.termgate);

/// termgate's keys and the relay's address.
pub const Config = struct {
    relay_host: []const u8,
    relay_port: u16,
    /// PEM of termgate's CA (also served on ca.get)
    ca_pem: []const u8,
    /// Signs callout answers and session approvals
    issuer: KeyPair,
    /// termgate's user in the AUTH account (bypasses the callout)
    callout_user: KeyPair,
    /// termgate's own key for the application connection
    app_user: KeyPair,
    /// termgate's user in the SYS account (bypasses the callout)
    system_user: KeyPair,
    /// Account nodes and users are placed in
    account: []const u8 = "APP",
};

// relay.json in termgate's folder:
//   {"relay_host": "...", "relay_port": 4222, "ca_pem_file": "/path/ca.pem",
//    "issuer_seed": "SA...", "callout_seed": "SU...", "app_seed": "SU...",
//    "system_seed": "SU..."}
// It holds termgate's private keys and must be readable by termgate only.

pub const LoadedConfig = struct {
    arena: std.heap.ArenaAllocator,
    cfg: Config,
    ca_fingerprint: [32]u8,

    pub fn deinit(r: *LoadedConfig) void {
        r.arena.deinit();
    }
};

/// Reads relay.json at `path` and the CA file it names.
pub fn loadConfig(gpa: std.mem.Allocator, io: Io, path: []const u8) !LoadedConfig {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();
    const data = try Io.Dir.cwd().readFileAlloc(io, path, a, .limited(1024 * 1024));
    const File = struct {
        relay_host: []const u8,
        relay_port: u16 = 4222,
        ca_pem_file: []const u8,
        issuer_seed: []const u8,
        callout_seed: []const u8,
        app_seed: []const u8,
        system_seed: []const u8,
    };
    const f = try std.json.parseFromSliceLeaky(File, a, data, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    // A relative CA path is relative to relay.json's folder
    const ca_path = if (std.fs.path.isAbsolute(f.ca_pem_file)) f.ca_pem_file else try std.fs.path.join(a, &.{ std.fs.path.dirname(path) orelse ".", f.ca_pem_file });
    const ca_pem = try Io.Dir.cwd().readFileAlloc(io, ca_path, a, .limited(64 * 1024));
    return .{
        .arena = arena,
        .cfg = .{
            .relay_host = f.relay_host,
            .relay_port = f.relay_port,
            .ca_pem = ca_pem,
            .issuer = try KeyPair.decodeSeed(f.issuer_seed),
            .callout_user = try KeyPair.decodeSeed(f.callout_seed),
            .app_user = try KeyPair.decodeSeed(f.app_seed),
            .system_user = try KeyPair.decodeSeed(f.system_seed),
        },
        .ca_fingerprint = try core.code.caFingerprint(a, ca_pem),
    };
}

pub const Service = struct {
    gpa: std.mem.Allocator,
    io: Io,
    cfg: Config,
    issuer_pub: [56]u8,
    app_pub: [56]u8,
    db: *dbm.Db,
    /// Serializes database use between the service tasks and the UI
    lock: *Io.Mutex,
    /// Session logs; owned by the caller, outlives the service
    recorder: *Recorder,
    svc: *Conn = undefined,
    app: *Conn = undefined,
    sys: *Conn = undefined,
    tasks: Io.Group = .init,
    /// Set by stop(). The tasks' loops check it: cancellation alone is not
    /// enough, since it reaches a task only once and a call deep inside a
    /// handler may take it and carry on
    stopping: std.atomic.Value(bool) = .init(false),
    /// When status.req.all was last sent (requestStatus)
    status_asked: std.atomic.Value(i64) = .init(0),
    /// The sessions open now: added when termgate approves one, removed
    /// when the node reports its end, when the node is no longer connected
    /// or no longer has it (its status). Not stored: the database keeps when
    /// each session started and ended.
    live_lock: Io.Mutex = .init,
    live: std.ArrayList(dbm.Session) = .empty,

    pub fn start(gpa: std.mem.Allocator, io: Io, cfg: Config, db: *dbm.Db, lock: *Io.Mutex, recorder: *Recorder) !*Service {
        const s = try gpa.create(Service);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .cfg = cfg,
            .issuer_pub = cfg.issuer.publicKey().encode(),
            .app_pub = cfg.app_user.publicKey().encode(),
            .db = db,
            .lock = lock,
            .recorder = recorder,
        };
        const tls: Conn.Tls = .{ .ca_pem = cfg.ca_pem };

        s.svc = try Conn.connect(gpa, io, .{ .host = cfg.relay_host, .port = cfg.relay_port, .key = cfg.callout_user, .name = "termgate-callout", .tls = tls });
        errdefer s.svc.close();
        const callout_sub = try s.svc.subscribe(core.callout.subject);
        try s.svc.flush(Conn.seconds(10));
        try s.tasks.concurrent(io, calloutLoop, .{ s, callout_sub });
        errdefer s.tasks.cancel(io);

        s.app = try Conn.connect(gpa, io, .{ .host = cfg.relay_host, .port = cfg.relay_port, .key = cfg.app_user, .name = "termgate", .tls = tls });
        errdefer s.app.close();
        const subs: AppSubs = .{
            try s.app.subscribe("ca.get"),
            try s.app.subscribe("register.*"),
            try s.app.subscribe("access.*"),
            try s.app.subscribe("authorize.*"),
            try s.app.subscribe("audit.*"),
            try s.app.subscribe("status.*"),
        };
        const session_subs: [2]*Conn.Sub = .{
            try s.app.subscribe("out.*.*.*.*"),
            try s.app.subscribe("in.*.*.*.data"),
        };
        try s.app.flush(Conn.seconds(10));
        try s.tasks.concurrent(io, appLoop, .{ s, subs });
        try s.tasks.concurrent(io, recordLoop, .{ s, session_subs });
        try s.tasks.concurrent(io, housekeeping, .{s});

        s.sys = try Conn.connect(gpa, io, .{ .host = cfg.relay_host, .port = cfg.relay_port, .key = cfg.system_user, .name = "termgate-system", .tls = tls });
        errdefer s.sys.close();
        var buf: [2][96]u8 = undefined;
        const events: [2]*Conn.Sub = .{
            try s.sys.subscribe(try std.fmt.bufPrint(&buf[0], "$SYS.ACCOUNT.{s}.CONNECT", .{cfg.account})),
            try s.sys.subscribe(try std.fmt.bufPrint(&buf[1], "$SYS.ACCOUNT.{s}.DISCONNECT", .{cfg.account})),
        };
        try s.sys.flush(Conn.seconds(10));
        try s.tasks.concurrent(io, presenceLoop, .{ s, events });
        return s;
    }

    /// false once either connection to the relay is gone (relay restarted,
    /// network down); main then starts a new Service.
    pub fn alive(s: *Service) bool {
        return !s.svc.isClosed() and !s.app.isClosed() and !s.sys.isClosed();
    }

    /// Without the relay nothing is known to be online.
    pub fn stop(s: *Service) void {
        s.stopping.store(true, .release);
        s.tasks.cancel(s.io);
        s.sys.close();
        s.app.close();
        s.svc.close();
        {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            s.db.nodeSetOnline(&.{}, s.now()) catch {};
        }
        for (s.live.items) |x| freeLive(s.gpa, x);
        s.live.deinit(s.gpa);
        s.gpa.destroy(s);
    }

    /// Asks one node for fresh system info (status.req.<node>).
    pub fn requestStatusOf(s: *Service, node: []const u8) void {
        var buf: [96]u8 = undefined;
        const subject = std.fmt.bufPrint(&buf, "status.req.{s}", .{node}) catch return;
        s.app.publish(subject, "") catch {};
    }

    /// Asks every online node for fresh system info (status.req.all); at most
    /// once every 30 seconds, however often the UI asks.
    pub fn requestStatus(s: *Service) void {
        const t = s.now();
        if (t - s.status_asked.load(.acquire) < 30) return;
        s.status_asked.store(t, .release);
        s.app.publish("status.req.all", "") catch {};
    }

    /// Ends a session from termgate's side: the node hangs up the shell and
    /// reports the end as usual.
    pub fn endSession(s: *Service, node: []const u8, user_key: []const u8, sid: []const u8) !void {
        var buf: [256]u8 = undefined;
        const subject = try std.fmt.bufPrint(&buf, "in.{s}.{s}.{s}.end", .{ node, user_key, sid });
        try s.app.publish(subject, "");
        try s.app.flush(Conn.seconds(5));
    }

    fn now(s: *Service) i64 {
        return @intCast(@divFloor(Io.Timestamp.now(s.io, .real).nanoseconds, std.time.ns_per_s));
    }

    // --- auth callout -------------------------------------------------------

    fn calloutLoop(s: *Service, sub: *Conn.Sub) void {
        while (!s.stopping.load(.acquire)) {
            const m = sub.next(Conn.seconds(1)) catch |e| switch (e) {
                error.Timeout => continue,
                else => return,
            };
            defer m.deinit(s.gpa);
            s.answerCallout(m) catch |e| log.warn("callout: {s}", .{@errorName(e)});
        }
    }

    fn answerCallout(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const req = try core.callout.decodeRequest(a, m.payload, s.now());
        const r = req.value.nats;
        const decision = try s.decide(a, r);
        const resp = try core.callout.respond(a, s.cfg.issuer, r, decision, s.now());
        try s.svc.publish(m.reply orelse return, resp);
    }

    /// Who is connecting, and what may they do?
    fn decide(s: *Service, a: std.mem.Allocator, r: core.callout.RequestNats) !core.callout.Decision {
        const key = core.callout.clientKey(r) catch return .{ .deny = "no valid key signature" };
        const k = try a.dupe(u8, &key.encode());
        const account = s.cfg.account;
        if (std.mem.eql(u8, k, &s.app_pub))
            return .{ .allow = .{ .name = "termgate", .account = account, .permissions = core.perms.termgate() } };

        s.lock.lockUncancelable(s.io);
        defer s.lock.unlock(s.io);
        // A code (node key or access key) decides first: a node that has just
        // been approved still needs registering permissions to hear about it
        if (r.connect_opts.auth_token) |tok| {
            const hash = dbm.tokenHash(tok);
            const id = core.code.tokenId(tok);
            if (try s.db.nodeByNodeKey(a, &hash, s.now())) |_|
                return .{ .allow = .{ .name = "registering", .account = account, .permissions = try core.perms.registering(a, &id, k) } };
            if (try s.db.terminalByAccessKey(a, &hash, s.now())) |_|
                return .{ .allow = .{ .name = "access-key", .account = account, .permissions = try core.perms.usingAccessKey(a, &id, k) } };
            return .{ .deny = "unknown, used or expired code" };
        }
        // The name shows in the relay's connection list, where termgate finds
        // connections to mark online or to close: node:<name> (unique) and
        // user:<key>; only users who may connect (terminal:connect)
        if (try s.db.nodeByHardwareKey(a, k)) |n|
            return .{ .allow = .{ .name = try std.fmt.allocPrint(a, "{s}{s}", .{ node_prefix, n.name }), .account = account, .permissions = try core.perms.node(a, n.name, k) } };
        if (try s.db.terminalByKey(a, k)) |_|
            return .{ .allow = .{ .name = try std.fmt.allocPrint(a, "{s}{s}", .{ user_prefix, k }), .account = account, .permissions = try core.perms.user(a, k) } };
        return .{ .allow = .{ .name = "anonymous", .account = account, .permissions = try core.perms.anonymous(a, k) } };
    }

    const node_prefix = "node:";
    const user_prefix = "user:";

    // --- the sessions open now -----------------------------------------------

    fn freeLive(gpa: std.mem.Allocator, x: dbm.Session) void {
        gpa.free(x.sid);
        gpa.free(x.node);
        gpa.free(x.user_key);
        gpa.free(x.user);
    }

    /// A session termgate approved is open (also used by the tests).
    pub fn liveAdd(s: *Service, x: dbm.Session) void {
        s.live_lock.lockUncancelable(s.io);
        defer s.live_lock.unlock(s.io);
        for (s.live.items) |y| if (std.mem.eql(u8, y.sid, x.sid)) return;
        const copy: dbm.Session = .{
            .sid = s.gpa.dupe(u8, x.sid) catch return,
            .node = s.gpa.dupe(u8, x.node) catch return,
            .user_key = s.gpa.dupe(u8, x.user_key) catch return,
            .user = s.gpa.dupe(u8, x.user) catch return,
            .started = x.started,
            .ended = null,
            .exit_status = null,
            .open = true,
        };
        s.live.append(s.gpa, copy) catch freeLive(s.gpa, copy);
    }

    /// Removes the open sessions `drop` says (node, sid) to drop; their sids
    /// in `a`, for the record of their end.
    fn liveRemove(s: *Service, a: std.mem.Allocator, ctx: anytype, comptime drop: fn (@TypeOf(ctx), dbm.Session) bool) []const []const u8 {
        var gone: std.ArrayList([]const u8) = .empty;
        s.live_lock.lockUncancelable(s.io);
        defer s.live_lock.unlock(s.io);
        var i: usize = 0;
        while (i < s.live.items.len) {
            const x = s.live.items[i];
            if (drop(ctx, x)) {
                gone.append(a, a.dupe(u8, x.sid) catch "") catch {};
                freeLive(s.gpa, x);
                _ = s.live.swapRemove(i);
            } else i += 1;
        }
        return gone.items;
    }

    /// The sessions open now (copies in `a`), newest first.
    pub fn sessionsOpen(s: *Service, a: std.mem.Allocator) ![]dbm.Session {
        s.live_lock.lockUncancelable(s.io);
        defer s.live_lock.unlock(s.io);
        const out = try a.alloc(dbm.Session, s.live.items.len);
        for (s.live.items, out) |x, *o| o.* = .{ .sid = try a.dupe(u8, x.sid), .node = try a.dupe(u8, x.node), .user_key = try a.dupe(u8, x.user_key), .user = try a.dupe(u8, x.user), .started = x.started, .ended = null, .exit_status = null, .open = true };
        std.mem.sort(dbm.Session, out, {}, struct {
            fn newer(_: void, l: dbm.Session, r: dbm.Session) bool {
                return l.started > r.started;
            }
        }.newer);
        return out;
    }

    /// Marks which of `rows` (from the database) are open now.
    pub fn markOpen(s: *Service, rows: []dbm.Session) void {
        s.live_lock.lockUncancelable(s.io);
        defer s.live_lock.unlock(s.io);
        for (rows) |*r| {
            r.open = for (s.live.items) |x| (if (std.mem.eql(u8, x.sid, r.sid)) break true) else false;
        }
    }

    /// Ends the open sessions of nodes that are not connected (`online`:
    /// the names of those that are); their end time is recorded now.
    fn liveKeepOnline(s: *Service, a: std.mem.Allocator, online: []const []const u8) void {
        const Ctx = struct { names: []const []const u8 };
        const gone = s.liveRemove(a, Ctx{ .names = online }, struct {
            fn f(c: Ctx, x: dbm.Session) bool {
                for (c.names) |n| if (std.mem.eql(u8, n, x.node)) return false;
                return true;
            }
        }.f);
        s.recordClosed(gone);
    }

    /// The node says which sessions it has open (its status): the open
    /// sessions of the node are those, as far as termgate approved them.
    fn liveSetNode(s: *Service, a: std.mem.Allocator, node: []const u8, open_now: []const []const u8) void {
        // A session approved in the last seconds may not be in the node's
        // list yet
        const Ctx = struct { node: []const u8, open_now: []const []const u8, before: i64 };
        const gone = s.liveRemove(a, Ctx{ .node = node, .open_now = open_now, .before = s.now() - 15 }, struct {
            fn f(c: Ctx, x: dbm.Session) bool {
                if (!std.mem.eql(u8, x.node, c.node) or x.started >= c.before) return false;
                for (c.open_now) |sid| if (std.mem.eql(u8, sid, x.sid)) return false;
                return true;
            }
        }.f);
        s.recordClosed(gone);
        if (gone.len > 0) log.info("{d} session(s) on {s} closed: the node no longer has them", .{ gone.len, node });
        // Open on the node but not known open here (termgate's relay
        // connection was gone for a while): back in, if termgate approved it
        for (open_now) |sid| {
            const rec = blk: {
                s.lock.lockUncancelable(s.io);
                defer s.lock.unlock(s.io);
                break :blk s.db.sessionGet(a, sid) catch null;
            };
            if (rec) |r| if (r.ended == null and std.mem.eql(u8, r.node, node)) s.liveAdd(r);
        }
    }

    /// The end time of sessions that closed without their node's report.
    fn recordClosed(s: *Service, sids: []const []const u8) void {
        if (sids.len == 0) return;
        s.lock.lockUncancelable(s.io);
        defer s.lock.unlock(s.io);
        for (sids) |sid| s.db.sessionClose(sid, s.now()) catch {};
    }

    // --- closing connections -------------------------------------------------

    /// Closes the connections of node `name` (disabled or deleted). The
    /// callout refuses it from now on; this ends the connection it has. Its
    /// open sessions end with it and are marked ended now, since the node
    /// cannot report them any more.
    pub fn kickNode(s: *Service, name: []const u8) void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        s.liveSetNode(arena.allocator(), name, &.{});
        s.kickLater(node_prefix, name);
    }

    /// Closes the connections of the user with `key` (who may not connect
    /// any more) and ends its open sessions on the nodes (the nodes report
    /// the ends).
    pub fn kickUser(s: *Service, key: []const u8) void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const sessions = s.sessionsOpen(arena.allocator()) catch &.{};
        for (sessions) |x| if (std.mem.eql(u8, x.user_key, key)) s.endSession(x.node, x.user_key, x.sid) catch {};
        s.kickLater(user_prefix, key);
    }

    /// The UI must not wait for the relay: the kick runs as a service task.
    fn kickLater(s: *Service, prefix: []const u8, id: []const u8) void {
        const who = std.fmt.allocPrint(s.gpa, "{s}{s}", .{ prefix, id }) catch return;
        s.tasks.concurrent(s.io, kickTask, .{ s, who }) catch {
            kickTask(s, who);
        };
    }

    fn kickTask(s: *Service, who: []u8) void {
        defer s.gpa.free(who);
        const n = s.kick(who) catch |e| {
            if (e != error.Canceled) log.warn("closing the connection of {s}: {s}", .{ who, @errorName(e) });
            return;
        };
        if (n > 0) log.info("closed {d} connection(s) of {s}", .{ n, who });
    }

    /// Finds the connections named `who` in the account and asks the relay
    /// to close each ($SYS.REQ.SERVER.<id>.KICK). Returns how many.
    fn kick(s: *Service, who: []const u8) !usize {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const subject = try std.fmt.allocPrint(a, "$SYS.REQ.ACCOUNT.{s}.CONNZ", .{s.cfg.account});
        const body = try std.json.Stringify.valueAlloc(a, .{ .auth = true, .user = who, .limit = 1024 }, .{});
        const m = try s.sys.request(subject, body, Conn.seconds(5));
        defer m.deinit(s.gpa);
        const Resp = struct {
            server: struct { id: []const u8 },
            data: ?struct { connections: []const struct { cid: u64 } = &.{} } = null,
        };
        const r = try std.json.parseFromSliceLeaky(Resp, a, m.payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        const d = r.data orelse return error.NoConnectionList;
        const kick_subject = try std.fmt.allocPrint(a, "$SYS.REQ.SERVER.{s}.KICK", .{r.server.id});
        for (d.connections) |c| {
            const req = try std.fmt.allocPrint(a, "{{\"cid\":{d}}}", .{c.cid});
            const k = try s.sys.request(kick_subject, req, Conn.seconds(5));
            defer k.deinit(s.gpa);
            if (std.mem.indexOf(u8, k.payload, "\"error\"") != null) return error.KickFailed;
        }
        return d.connections.len;
    }

    // --- presence ------------------------------------------------------------

    /// Connection events say that something changed; the relay's connection
    /// list (CONNZ) says what is connected. A burst of events (relay
    /// restarted, many nodes reconnecting) leads to one list query a second.
    fn presenceLoop(s: *Service, events: [2]*Conn.Sub) void {
        var dirty = true; // the first query finds the nodes already connected
        var last_sync: i64 = 0;
        while (!s.stopping.load(.acquire)) {
            for (events) |sub| {
                const m = sub.next(Conn.millis(100)) catch |e| switch (e) {
                    error.Timeout => continue,
                    else => return,
                };
                m.deinit(s.gpa);
                dirty = true;
            }
            const t = s.nowMs();
            if (dirty and t - last_sync >= 1000) {
                last_sync = t;
                s.syncOnline() catch |e| switch (e) {
                    error.Canceled => return,
                    else => {
                        log.warn("connection list: {s}", .{@errorName(e)});
                        continue;
                    },
                };
                dirty = false;
            }
        }
    }

    fn nowMs(s: *Service) i64 {
        return @intCast(@divFloor(Io.Timestamp.now(s.io, .awake).nanoseconds, std.time.ns_per_ms));
    }

    /// Reads the account's connections, page by page, and marks the nodes
    /// among them online.
    fn syncOnline(s: *Service) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const subject = try std.fmt.allocPrint(a, "$SYS.REQ.ACCOUNT.{s}.CONNZ", .{s.cfg.account});
        const Resp = struct {
            data: ?struct {
                total: usize = 0,
                connections: []const struct { authorized_user: []const u8 = "" } = &.{},
            } = null,
        };
        var names: std.ArrayList([]const u8) = .empty;
        const page = 1024;
        var offset: usize = 0;
        while (true) {
            const body = try std.fmt.allocPrint(a, "{{\"auth\":true,\"offset\":{d},\"limit\":{d}}}", .{ offset, page });
            const m = try s.sys.request(subject, body, Conn.seconds(5));
            defer m.deinit(s.gpa);
            const r = try std.json.parseFromSliceLeaky(Resp, a, m.payload, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
            const d = r.data orelse return error.NoConnectionList;
            for (d.connections) |c|
                if (std.mem.startsWith(u8, c.authorized_user, node_prefix))
                    try names.append(a, c.authorized_user[node_prefix.len..]);
            offset += d.connections.len;
            if (d.connections.len == 0 or offset >= d.total) break;
        }
        {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            try s.db.nodeSetOnline(names.items, s.now());
        }
        // A node no longer connected has no session open
        s.liveKeepOnline(a, names.items);
    }

    // --- application subjects -----------------------------------------------

    const AppSubs = [6]*Conn.Sub;

    fn appLoop(s: *Service, subs: AppSubs) void {
        while (!s.stopping.load(.acquire)) {
            var idle = true;
            for (subs, 0..) |sub, i| {
                const m = sub.next(Conn.millis(20)) catch |e| switch (e) {
                    error.Timeout => continue,
                    else => return,
                };
                idle = false;
                defer m.deinit(s.gpa);
                const result = switch (i) {
                    0 => s.answerCaGet(m),
                    1 => s.answerRegister(m),
                    2 => s.answerAccessKey(m),
                    3 => s.answerAuthorize(m),
                    4 => s.answerAudit(m),
                    else => s.recordStatus(m),
                };
                result catch |e| log.warn("{s}: {s}", .{ m.subject, @errorName(e) });
            }
            if (idle) s.io.sleep(.fromMilliseconds(10), .awake) catch return;
        }
    }

    // --- session logs and limits -----------------------------------------------

    /// Session traffic into the recorder: out.<node>.<user>.<sid>.data|end,
    /// in.<node>.<user>.<sid>.data.
    fn recordLoop(s: *Service, subs: [2]*Conn.Sub) void {
        // Session data is end-to-end encrypted; termgate has each session's
        // keys (stored at approval)
        var sessions: std.StringHashMapUnmanaged(Openers) = .empty;
        defer {
            var it = sessions.keyIterator();
            while (it.next()) |k| s.gpa.free(k.*);
            sessions.deinit(s.gpa);
        }
        var last_prune: i64 = s.now();
        while (!s.stopping.load(.acquire)) {
            if (s.now() - last_prune > 3600) {
                last_prune = s.now();
                pruneOpeners(s.gpa, &sessions, last_prune);
            }
            var idle = true;
            for (subs) |sub| {
                const m = sub.next(Conn.millis(20)) catch |e| switch (e) {
                    error.Timeout => continue,
                    else => return,
                };
                idle = false;
                defer m.deinit(s.gpa);
                var tok: [5][]const u8 = undefined;
                var n: usize = 0;
                var it = std.mem.splitScalar(u8, m.subject, '.');
                while (it.next()) |t| : (n += 1) {
                    if (n == tok.len) break;
                    tok[n] = t;
                }
                if (n != 5) continue;
                const sid = tok[3];
                const kind = tok[4];
                const out = std.mem.eql(u8, tok[0], "out");
                if (out and std.mem.eql(u8, kind, "end")) {
                    s.recorder.end(sid);
                    if (sessions.fetchRemove(sid)) |kv| s.gpa.free(kv.key);
                    continue;
                }
                const o = s.openers(&sessions, sid) orelse continue;
                o.seen = s.now();
                const plain = (if (out) o.down.open(s.gpa, m.payload) else o.up.open(s.gpa, m.payload)) catch |e| {
                    log.warn("session {s}: undecryptable data: {s}", .{ sid, @errorName(e) });
                    continue;
                };
                defer s.gpa.free(plain);
                if (out) s.recorder.output(sid, plain, s.now()) else s.recorder.input(sid, plain, s.now());
            }
            if (idle) s.io.sleep(.fromMilliseconds(10), .awake) catch return;
        }
    }

    const Openers = struct { up: core.e2e.Opener, down: core.e2e.Opener, seen: i64 };

    /// The decrypting state of session `sid`, from its stored keys.
    fn openers(s: *Service, map: *std.StringHashMapUnmanaged(Openers), sid: []const u8) ?*Openers {
        if (map.getPtr(sid)) |o| return o;
        const keys = blk: {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            break :blk (s.db.sessionKeys(sid) catch null) orelse return null;
        };
        const key = s.gpa.dupe(u8, sid) catch return null;
        map.put(s.gpa, key, .{ .up = .{ .key = keys.up }, .down = .{ .key = keys.down }, .seen = s.now() }) catch {
            s.gpa.free(key);
            return null;
        };
        return map.getPtr(sid);
    }

    fn pruneOpeners(gpa: std.mem.Allocator, map: *std.StringHashMapUnmanaged(Openers), now_s: i64) void {
        var it = map.iterator();
        while (it.next()) |kv| {
            if (now_s - kv.value_ptr.seen > 24 * 3600) {
                const k = kv.key_ptr.*;
                map.removeByPtr(kv.key_ptr);
                gpa.free(k);
                it = map.iterator();
            }
        }
    }

    /// Every few seconds: settings into the recorder, sessions over the time
    /// limit ended; every hour: session logs past their keeping time
    /// deleted, forgotten sessions pruned.
    fn housekeeping(s: *Service) void {
        var last_hourly: i64 = 0;
        var last_reconcile: i64 = 0;
        // Sessions already told they are over the limit
        var expired: std.StringHashMapUnmanaged(void) = .empty;
        defer {
            var it = expired.keyIterator();
            while (it.next()) |k| s.gpa.free(k.*);
            expired.deinit(s.gpa);
        }
        while (!s.stopping.load(.acquire)) {
            s.housekeep(&expired, &last_hourly, &last_reconcile) catch |e| log.warn("housekeeping: {s}", .{@errorName(e)});
            // Five seconds, in steps that notice a stop
            var waited: u32 = 0;
            while (waited < 25 and !s.stopping.load(.acquire)) : (waited += 1)
                s.io.sleep(.fromMilliseconds(200), .awake) catch return;
        }
    }

    fn housekeep(s: *Service, expired: *std.StringHashMapUnmanaged(void), last_hourly: *i64, last_reconcile: *i64) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const t = s.now();
        const settings = blk: {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            break :blk try s.db.settingsGet();
        };
        const active = try s.sessionsOpen(a);
        s.recorder.max_output.store(settings.max_command_output, .release);

        // Once a minute the nodes with open sessions say which they really
        // have (their status): an end report lost on the way leaves no
        // session open for ever
        if (t - last_reconcile.* >= 60) {
            last_reconcile.* = t;
            for (active, 0..) |x, i| {
                const asked = for (active[0..i]) |y| (if (std.mem.eql(u8, x.node, y.node)) break true) else false;
                if (!asked) s.requestStatusOf(x.node);
            }
        }

        if (settings.max_session_minutes > 0) {
            const limit = settings.max_session_minutes * 60;
            for (active) |x| {
                if (t - x.started < limit or expired.contains(x.sid)) continue;
                try expired.put(s.gpa, try s.gpa.dupe(u8, x.sid), {});
                // Told on the user's screen (encrypted like the node's output),
                // then ended like an admin's End
                const subject = try std.fmt.allocPrint(a, "out.{s}.{s}.{s}.data", .{ x.node, x.user_key, x.sid });
                const msg = try std.fmt.allocPrint(a, "\r\n[termgate: the session time limit of {d} minutes is reached]\r\n", .{settings.max_session_minutes});
                s.tellUser(subject, x.sid, msg);
                s.endSession(x.node, x.user_key, x.sid) catch {};
                log.info("session {s} on {s} ended: time limit", .{ x.sid, x.node });
            }
        }
        // Forget the ones that are no longer open
        var it = expired.keyIterator();
        while (it.next()) |k| {
            const still = for (active) |x| {
                if (std.mem.eql(u8, x.sid, k.*)) break true;
            } else false;
            if (!still) {
                const key = k.*;
                _ = expired.remove(key);
                s.gpa.free(key);
                it = expired.keyIterator();
            }
        }

        if (t - last_hourly.* >= 3600) {
            last_hourly.* = t;
            s.recorder.prune(t);
            if (settings.log_days > 0) {
                const n = blk: {
                    s.lock.lockUncancelable(s.io);
                    defer s.lock.unlock(s.io);
                    break :blk try s.db.commandsPrune(t - settings.log_days * 86400);
                };
                if (n > 0) log.info("deleted {d} logged commands older than {d} days", .{ n, settings.log_days });
            }
        }
    }

    /// Writes `msg` on a session user's screen, encrypted with the session's
    /// keys as termgate. The counter is the time in nanoseconds, so it only
    /// grows, also across restarts.
    fn tellUser(s: *Service, subject: []const u8, sid: []const u8, msg: []const u8) void {
        const keys = blk: {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            break :blk (s.db.sessionKeys(sid) catch null) orelse return;
        };
        var sealer: core.e2e.Sealer = .{ .key = keys.down, .sender = .termgate, .counter = @intCast(Io.Timestamp.now(s.io, .real).nanoseconds) };
        const sealed = sealer.seal(s.gpa, msg) catch return;
        defer s.gpa.free(sealed);
        s.app.publish(subject, sealed) catch {};
    }

    fn lastToken(subject: []const u8) []const u8 {
        const i = std.mem.lastIndexOfScalar(u8, subject, '.') orelse return subject;
        return subject[i + 1 ..];
    }

    fn reply(s: *Service, m: Conn.Message, body: []const u8) !void {
        try s.app.publish(m.reply orelse return error.NoReplySubject, body);
    }

    fn answerCaGet(s: *Service, m: Conn.Message) !void {
        try s.reply(m, s.cfg.ca_pem);
    }

    /// register.<token id>: a node with a node key asks to be registered.
    fn answerRegister(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Req = struct { hardware_key: []const u8, status: std.json.Value = .null };
        const req = try std.json.parseFromSliceLeaky(Req, a, m.payload, .{ .ignore_unknown_fields = true });
        const k = core.nkeys.PublicKey.decode(req.hardware_key) catch return error.InvalidKey;
        if (k.prefix != .user) return error.InvalidKey;
        const status_json = try std.json.Stringify.valueAlloc(a, req.status, .{});

        s.lock.lockUncancelable(s.io);
        defer s.lock.unlock(s.io);
        const n = (try s.db.nodeByNodeKeyId(a, lastToken(m.subject), s.now())) orelse
            return s.reply(m, "{\"status\":\"refused\",\"reason\":\"unknown or expired node key\"}");

        if (n.state == .approved) {
            if (n.hardware_key != null and std.mem.eql(u8, n.hardware_key.?, req.hardware_key)) {
                try s.db.nodeFinishRegistration(n.id);
                const body = try std.json.Stringify.valueAlloc(a, .{ .status = "approved", .name = n.name, .issuer = @as([]const u8, &s.issuer_pub) }, .{});
                log.info("node {s} registered", .{n.name});
                return s.reply(m, body);
            }
        }
        try s.db.nodeRecordRequest(n.id, req.hardware_key, status_json, s.now());
        try s.reply(m, "{\"status\":\"pending\"}");
    }

    /// access.<token id>: someone uses an access key with their new key.
    fn answerAccessKey(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Req = struct { user_key: []const u8 };
        const req = try std.json.parseFromSliceLeaky(Req, a, m.payload, .{ .ignore_unknown_fields = true });
        const k = core.nkeys.PublicKey.decode(req.user_key) catch return error.InvalidKey;
        if (k.prefix != .user) return error.InvalidKey;

        s.lock.lockUncancelable(s.io);
        defer s.lock.unlock(s.io);
        const p = (try s.db.terminalByAccessKeyId(a, lastToken(m.subject), s.now())) orelse
            return s.reply(m, "{\"error\":\"unknown, used or expired access key\"}");
        // The key now stands for the user; everything else stays in the
        // database. tgterm gets only the key that signs the approvals.
        try s.db.terminalUseAccessKey(p.id, req.user_key);
        log.info("access key used by {s}", .{p.name});
        try s.reply(m, try std.json.Stringify.valueAlloc(a, .{ .issuer = @as([]const u8, &s.issuer_pub) }, .{}));
    }

    /// authorize.<node>: a node asks whether a session may open.
    fn answerAuthorize(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const req = try std.json.parseFromSliceLeaky(core.approval.Request, a, m.payload, .{});
        // Node permissions only allow authorize.<own name>, so the subject
        // tells which node is asking
        const node = lastToken(m.subject);
        if (!std.mem.eql(u8, node, req.node)) return error.NodeMismatch;

        // The session keys, sealed to us by the node and bound to both public
        // keys: if they do not open, the request was changed on the way
        const keys = core.e2e.openForTermgate(s.cfg.issuer, req.keys, req.sid, req.kx_user, req.kx_node) catch null;
        const decision: core.approval.Decision = if (keys == null) .{ .deny = "the session keys do not check" } else blk: {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            const d: core.approval.Decision = switch (try s.db.terminalUse(req.user, node, req.sid, s.now())) {
                .allowed => .allow,
                .denied => |why| .{ .deny = why },
            };
            // Kept to log and watch the session
            if (d == .allow) try s.db.sessionSetKeys(req.sid, keys.?);
            break :blk d;
        };
        if (decision == .allow) {
            const rec = blk: {
                s.lock.lockUncancelable(s.io);
                defer s.lock.unlock(s.io);
                break :blk try s.db.sessionGet(a, req.sid);
            };
            if (rec) |r| s.liveAdd(r);
        }
        // Record the session from its first byte
        if (decision == .allow) s.recorder.open(req.sid, s.now());
        const tok = try core.approval.issue(a, s.cfg.issuer, req, decision, s.now());
        try s.reply(m, tok);
        switch (decision) {
            .allow => log.info("session {s} on {s} approved", .{ req.sid, node }),
            .deny => |why| log.info("session on {s} refused: {s}", .{ node, why }),
        }
    }

    /// audit.<node>: a node reports a session's end; acknowledged so it stops
    /// retrying. A node with open sessions also asks here whether termgate
    /// is there (event "alive"); with no answer for a minute it ends them.
    fn answerAudit(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const Ev = struct { event: []const u8, sid: []const u8, at: i64, status: i64 = 0 };
        const ev = try std.json.parseFromSliceLeaky(Ev, arena.allocator(), m.payload, .{ .ignore_unknown_fields = true });
        if (std.mem.eql(u8, ev.event, "end")) {
            {
                s.lock.lockUncancelable(s.io);
                defer s.lock.unlock(s.io);
                try s.db.sessionEnd(ev.sid, ev.at, ev.status);
            }
            const Ctx = struct { sid: []const u8 };
            _ = s.liveRemove(arena.allocator(), Ctx{ .sid = ev.sid }, struct {
                fn f(c: Ctx, x: dbm.Session) bool {
                    return std.mem.eql(u8, c.sid, x.sid);
                }
            }.f);
        }
        try s.reply(m, "ok");
    }

    /// status.<node>: system info, sent by the node after connecting and
    /// when asked (status.req.all, status.req.<node>).
    fn recordStatus(s: *Service, m: Conn.Message) !void {
        var arena: std.heap.ArenaAllocator = .init(s.gpa);
        defer arena.deinit();
        const node = lastToken(m.subject);
        // The sessions open on the node now (a tgnode that does not say
        // leaves them as they are)
        const Open = struct { sessions: ?[]const []const u8 = null };
        const open = std.json.parseFromSliceLeaky(Open, arena.allocator(), m.payload, .{ .ignore_unknown_fields = true }) catch Open{};
        {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            try s.db.nodeRecordStatus(node, m.payload, s.now());
        }
        if (open.sessions) |list| s.liveSetNode(arena.allocator(), node, list);
    }
};

/// A session's output for a panel in a browser, from the moment it starts:
/// decrypted here (the session keys stay on the server) and kept as records
/// until the browser fetches them (`read`). The browser's terminal draws
/// them. Records: 'd', length (u32, big-endian), terminal output; or 'r',
/// cols and rows (u16 each, big-endian).
pub const Tap = struct {
    gpa: std.mem.Allocator,
    io: Io,
    service: *Service,
    out_subject: []u8,
    resize_subject: []u8,
    opener: ?core.e2e.Opener = null,
    lock: Io.Mutex = .init,
    /// Records not fetched yet; `base` is the stream offset of buf[0]
    buf: std.ArrayList(u8) = .empty,
    base: u64 = 0,
    state: std.atomic.Value(State) = .init(.connecting),
    /// When the browser last fetched (taps nobody reads are stopped)
    last_read: std.atomic.Value(i64) = .init(0),
    task: ?Io.Future(void) = null,

    pub const State = enum(u8) {
        connecting,
        live,
        /// The session is over
        ended,
        /// The relay connection was lost
        failed,
        /// termgate has no keys for this session
        unreadable,
    };

    /// A browser that stops fetching must not make the server keep
    /// everything: beyond this the oldest records are dropped
    const max_pending = 4 << 20;

    pub fn start(s: *Service, node: []const u8, user_key: []const u8, sid: []const u8) !*Tap {
        const gpa = s.gpa;
        const t = try gpa.create(Tap);
        errdefer gpa.destroy(t);
        const out_subject = try std.fmt.allocPrint(gpa, "out.{s}.{s}.{s}.*", .{ node, user_key, sid });
        errdefer gpa.free(out_subject);
        const resize_subject = try std.fmt.allocPrint(gpa, "in.{s}.{s}.{s}.resize", .{ node, user_key, sid });
        errdefer gpa.free(resize_subject);
        t.* = .{ .gpa = gpa, .io = s.io, .service = s, .out_subject = out_subject, .resize_subject = resize_subject };
        t.last_read.store(s.now(), .release);
        const keys = blk: {
            s.lock.lockUncancelable(s.io);
            defer s.lock.unlock(s.io);
            break :blk s.db.sessionKeys(sid) catch null;
        };
        if (keys) |k| t.opener = .{ .key = k.down } else t.state.store(.unreadable, .release);
        t.task = try s.io.concurrent(run, .{t});
        return t;
    }

    pub fn stop(t: *Tap) void {
        if (t.task) |*task| task.cancel(t.io);
        t.buf.deinit(t.gpa);
        t.gpa.free(t.out_subject);
        t.gpa.free(t.resize_subject);
        t.gpa.destroy(t);
    }

    pub const Chunk = struct { data: []u8, next: u64, state: State };

    /// The records from stream offset `offset` on (in `a`); what came
    /// before is forgotten.
    pub fn read(t: *Tap, a: std.mem.Allocator, offset: u64, now_s: i64) !Chunk {
        t.last_read.store(now_s, .release);
        t.lock.lockUncancelable(t.io);
        defer t.lock.unlock(t.io);
        const skip: usize = @intCast(@min(offset -| t.base, t.buf.items.len));
        const data = try a.dupe(u8, t.buf.items[skip..]);
        const next = t.base + t.buf.items.len;
        t.buf.clearRetainingCapacity();
        t.base = next;
        return .{ .data = data, .next = next, .state = t.state.load(.acquire) };
    }

    fn record(t: *Tap, kind: u8, payload: []const u8) void {
        t.lock.lockUncancelable(t.io);
        defer t.lock.unlock(t.io);
        if (t.buf.items.len + payload.len > max_pending) {
            t.base += t.buf.items.len;
            t.buf.clearRetainingCapacity();
        }
        t.buf.append(t.gpa, kind) catch return;
        if (kind == 'd') {
            var len: [4]u8 = undefined;
            std.mem.writeInt(u32, &len, @intCast(payload.len), .big);
            t.buf.appendSlice(t.gpa, &len) catch return;
        }
        t.buf.appendSlice(t.gpa, payload) catch return;
    }

    fn run(t: *Tap) void {
        t.follow() catch |e| switch (e) {
            error.Canceled => {},
            else => if (t.state.load(.acquire) != .ended) t.state.store(.failed, .release),
        };
    }

    fn follow(t: *Tap) !void {
        const s = t.service;
        if (t.opener == null) return;
        const out = try s.app.subscribe(t.out_subject);
        defer out.unsubscribe();
        const resize = try s.app.subscribe(t.resize_subject);
        defer resize.unsubscribe();
        try s.app.flush(Conn.seconds(5));
        t.state.store(.live, .release);
        while (true) {
            if (resize.next(Conn.millis(0))) |m| {
                defer m.deinit(t.gpa);
                if (m.payload.len == 4) t.record('r', m.payload);
            } else |e| if (e != error.Timeout) return e;
            const m = out.next(Conn.millis(200)) catch |e| switch (e) {
                error.Timeout => continue,
                else => return e,
            };
            defer m.deinit(t.gpa);
            if (std.mem.endsWith(u8, m.subject, ".end")) {
                t.state.store(.ended, .release);
                return;
            }
            const plain = t.opener.?.open(t.gpa, m.payload) catch continue;
            defer t.gpa.free(plain);
            t.record('d', plain);
        }
    }
};
