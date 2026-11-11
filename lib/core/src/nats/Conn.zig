//! A NATS connection: connect and authenticate, publish, subscribe, flush.
//!
//! A background task (started with io.concurrent) reads from the socket,
//! answers server PINGs and queues incoming messages on their subscription.
//! Callers wait on a subscription with a timeout. Writes are serialized with a
//! mutex, so a Conn can be used from several tasks.
//!
//! TLS (optional) starts with the first byte (server option
//! tls.handshake_first) and trusts only the given CA certificates. The server
//! key must be ECDSA (P-256): Zig 0.17's TLS client does not accept Ed25519
//! handshake signatures. The reader task and writers use the TLS client at the
//! same time; they touch separate state except on a TLS KeyUpdate from the
//! server, which nats-server (Go) does not initiate.

const std = @import("std");
const Io = std.Io;
const protocol = @import("protocol.zig");
const nkeys = @import("../nkeys.zig");

const Conn = @This();

pub const Options = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 4222,
    /// User JWT (decentralized auth); sent with the nonce signature
    jwt: ?[]const u8 = null,
    /// Key that signs the server nonce (user key with jwt, or a plain nkey user)
    key: ?nkeys.KeyPair = null,
    /// Auth token sent in CONNECT (auth callout: node key or invitation)
    token: ?[]const u8 = null,
    /// Client name shown in server monitoring
    name: []const u8 = "termgate",
    /// Receive our own publications (off in production, useful in tests)
    echo: bool = false,
    /// Prefix of reply subjects for request(); users get "_INBOX.<user key>"
    /// so that only they may subscribe to their replies.
    inbox_prefix: []const u8 = "_INBOX",
    /// TLS; null = plain TCP (tests only)
    tls: ?Tls = null,
};

pub const Tls = struct {
    /// PEM certificates to trust (termgate's CA). Server certificates must
    /// chain to one of these. The host name is not checked: the CA is private
    /// to the customer and only signs their relay.
    ca_pem: []const u8,
    /// Skip certificate verification. Only for fetching termgate's CA during
    /// registration, whose fingerprint the caller then checks; nothing secret
    /// may be sent over such a connection.
    insecure: bool = false,
};

/// Timeout of n seconds on the monotonic clock.
pub fn seconds(n: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromSeconds(n), .clock = .awake } };
}

/// Timeout of n milliseconds on the monotonic clock.
pub fn millis(n: i64) Io.Timeout {
    return .{ .duration = .{ .raw = .fromMilliseconds(n), .clock = .awake } };
}

pub const Error = error{
    ConnectionClosed,
    /// request(): nobody is subscribed to the subject
    NoResponders,
    /// The server answered CONNECT with -ERR (usually an auth failure)
    ServerRejected,
    ProtocolError,
    Timeout,
};

/// A received message. Owns its memory; release with deinit.
pub const Message = struct {
    subject: []const u8,
    reply: ?[]const u8,
    headers: ?[]const u8,
    payload: []const u8,
    /// Single allocation holding all the slices above
    buf: []u8,

    pub fn deinit(m: Message, gpa: std.mem.Allocator) void {
        gpa.free(m.buf);
    }

    fn copy(gpa: std.mem.Allocator, m: protocol.Msg) !Message {
        const reply_len = if (m.reply) |r| r.len else 0;
        const hdr_len = if (m.headers) |h| h.len else 0;
        const buf = try gpa.alloc(u8, m.subject.len + reply_len + hdr_len + m.payload.len);
        var i: usize = 0;
        const take = struct {
            fn take(b: []u8, at: *usize, s: []const u8) []const u8 {
                @memcpy(b[at.*..][0..s.len], s);
                defer at.* += s.len;
                return b[at.*..][0..s.len];
            }
        }.take;
        return .{
            .subject = take(buf, &i, m.subject),
            .reply = if (m.reply) |r| take(buf, &i, r) else null,
            .headers = if (m.headers) |h| take(buf, &i, h) else null,
            .payload = take(buf, &i, m.payload),
            .buf = buf,
        };
    }
};

pub const Sub = struct {
    conn: *Conn,
    sid: u64,
    /// Guarded by conn.mutex
    pending: std.ArrayList(Message) = .empty,
    cond: Io.Condition = .init,
    /// Removed from the connection; next() returns ConnectionClosed once drained
    done: bool = false,

    /// Waits for the next message. The caller owns it (Message.deinit).
    pub fn next(s: *Sub, timeout: Io.Timeout) !Message {
        const c = s.conn;
        const deadline = timeout.toDeadline(c.io);
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        while (s.pending.items.len == 0) {
            if (s.done or c.closed) return error.ConnectionClosed;
            s.cond.waitTimeout(c.io, &c.mutex, deadline) catch |e| switch (e) {
                error.Timeout => return error.Timeout,
                error.Canceled => return error.Canceled,
            };
        }
        return s.pending.orderedRemove(0);
    }

    /// Unsubscribes and frees the subscription and its queued messages.
    pub fn unsubscribe(s: *Sub) void {
        const c = s.conn;
        c.writeOp(protocol.writeUnsub, .{ s.sid, null }) catch {};
        c.mutex.lockUncancelable(c.io);
        _ = c.subs.remove(s.sid);
        c.mutex.unlock(c.io);
        s.destroy();
    }

    fn destroy(s: *Sub) void {
        const gpa = s.conn.gpa;
        for (s.pending.items) |m| m.deinit(gpa);
        s.pending.deinit(gpa);
        gpa.destroy(s);
    }
};

gpa: std.mem.Allocator,
io: Io,
stream: Io.net.Stream,
/// Plaintext buffers (the protocol reads and writes through these)
read_buf: []u8,
write_buf: []u8,
stream_reader: Io.net.Stream.Reader,
stream_writer: Io.net.Stream.Writer,
/// Ciphertext buffers of the socket when TLS is on
tls_in_buf: []u8 = &.{},
tls_out_buf: []u8 = &.{},
tls_client: ?std.crypto.tls.Client = null,
/// What the protocol reads from and writes to: the socket, or the TLS client
in: *Io.Reader = undefined,
out: *Io.Writer = undefined,
/// Serializes writes to the socket
write_mutex: Io.Mutex = .init,
/// Guards subs, closed, pongs and every Sub's queue
mutex: Io.Mutex = .init,
subs: std.AutoHashMapUnmanaged(u64, *Sub) = .empty,
next_sid: u64 = 1,
closed: bool = false,
/// PONGs received / PINGs sent by flush
pongs: u64 = 0,
pings: u64 = 0,
pong_cond: Io.Condition = .init,
/// Error text of the last -ERR from the server
last_error: [256]u8 = undefined,
last_error_len: usize = 0,
read_task: ?Io.Future(void) = null,
/// Largest payload the server accepts (from INFO)
max_payload: usize = 1024 * 1024,
inbox_prefix: []const u8 = "_INBOX",

const read_buf_size = 1024 * 1024 + protocol.max_control_line + 64;
const tls_write_buffer_len = 8 * 1024;

/// Connects, authenticates and starts the reader task.
pub fn connect(gpa: std.mem.Allocator, io: Io, opts: Options) !*Conn {
    const host = try Io.net.HostName.init(opts.host);
    // No connect timeout: Zig 0.17's threaded Io does not implement one yet.
    const stream = try host.connect(io, opts.port, .{ .mode = .stream });
    errdefer stream.close(io);

    const c = try gpa.create(Conn);
    errdefer gpa.destroy(c);
    const read_buf = try gpa.alloc(u8, read_buf_size);
    errdefer gpa.free(read_buf);
    const write_buf = try gpa.alloc(u8, 64 * 1024);
    errdefer gpa.free(write_buf);

    c.* = .{
        .gpa = gpa,
        .io = io,
        .stream = stream,
        .read_buf = read_buf,
        .write_buf = write_buf,
        .stream_reader = undefined,
        .stream_writer = undefined,
        .inbox_prefix = opts.inbox_prefix,
    };
    errdefer c.subs.deinit(gpa);
    errdefer c.freeTlsBuffers();

    if (opts.tls) |t| {
        c.tls_in_buf = try gpa.alloc(u8, std.crypto.tls.Client.min_buffer_len);
        c.tls_out_buf = try gpa.alloc(u8, std.crypto.tls.Client.min_buffer_len);
        c.stream_reader = stream.reader(io, c.tls_in_buf);
        c.stream_writer = stream.writer(io, c.tls_out_buf);
        try c.startTls(t);
        c.in = &c.tls_client.?.reader;
        c.out = &c.tls_client.?.writer;
    } else {
        c.stream_reader = stream.reader(io, read_buf);
        c.stream_writer = stream.writer(io, write_buf);
        c.in = &c.stream_reader.interface;
        c.out = &c.stream_writer.interface;
    }

    try c.handshake(opts);
    c.read_task = try io.concurrent(readLoop, .{c});
    return c;
}

/// Closes the socket, stops the reader task and frees everything. Pending
/// next() calls return ConnectionClosed. Subscriptions must not be used after.
pub fn close(c: *Conn) void {
    const io = c.io;
    c.mutex.lockUncancelable(io);
    c.closed = true;
    c.mutex.unlock(io);
    c.stream.shutdown(io, .both) catch {};
    if (c.read_task) |*t| t.cancel(io);
    c.stream.close(io);

    var it = c.subs.valueIterator();
    while (it.next()) |s| s.*.destroy();
    c.subs.deinit(c.gpa);
    c.freeTlsBuffers();
    c.gpa.free(c.read_buf);
    c.gpa.free(c.write_buf);
    c.gpa.destroy(c);
}

fn freeTlsBuffers(c: *Conn) void {
    if (c.tls_in_buf.len > 0) c.gpa.free(c.tls_in_buf);
    if (c.tls_out_buf.len > 0) c.gpa.free(c.tls_out_buf);
}

/// TLS handshake over the connected socket, trusting only the given CA.
fn startTls(c: *Conn, t: Tls) !void {
    const gpa = c.gpa;
    const io = c.io;
    const now = Io.Timestamp.now(io, .real);

    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    if (!t.insecure) {
        try addPemCerts(&bundle, gpa, t.ca_pem, @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s)));
        if (bundle.map.count() == 0) return error.NoCaCertificate;
    }
    var lock: Io.RwLock = .init;

    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    c.tls_client = std.crypto.tls.Client.init(&c.stream_reader.interface, &c.stream_writer.interface, .{
        .host = .no_verification,
        .ca = if (t.insecure) .no_verification else .{ .bundle = .{ .gpa = gpa, .io = io, .lock = &lock, .bundle = &bundle } },
        .read_buffer = c.read_buf,
        // Zig 0.17's tls.Client.flush() encrypts what fits in the output
        // buffer and drops the rest. Keeping the plaintext buffer well below
        // one record makes flush() always fit; larger writes go through
        // drain(), which handles partial writes correctly.
        .write_buffer = c.write_buf[0..tls_write_buffer_len],
        .entropy = &entropy,
        .realtime_now = now,
    }) catch return error.TlsFailed;
}

/// Adds every PEM certificate in `pem` to the bundle.
fn addPemCerts(bundle: *std.crypto.Certificate.Bundle, gpa: std.mem.Allocator, pem: []const u8, now_sec: i64) !void {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, pem, pos, begin)) |b| {
        const start = b + begin.len;
        const stop = std.mem.indexOfPos(u8, pem, start, end) orelse return error.InvalidPem;
        pos = stop + end.len;
        // Strip whitespace and line breaks from the base64 body
        var b64: std.ArrayList(u8) = .empty;
        defer b64.deinit(gpa);
        for (pem[start..stop]) |ch| if (!std.ascii.isWhitespace(ch)) try b64.append(gpa, ch);
        const dec = std.base64.standard.Decoder;
        const der_len = dec.calcSizeForSlice(b64.items) catch return error.InvalidPem;
        const at: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.ensureUnusedCapacity(gpa, der_len);
        dec.decode(bundle.bytes.unusedCapacitySlice()[0..der_len], b64.items) catch return error.InvalidPem;
        bundle.bytes.items.len += der_len;
        bundle.parseCert(gpa, at, now_sec) catch return error.InvalidPem;
    }
}

/// Writes out everything buffered, through TLS when it is on.
fn flushOut(c: *Conn) !void {
    try c.out.flush();
    if (c.tls_client != null) try c.stream_writer.interface.flush();
}

/// Reads INFO, sends CONNECT and a PING, and waits for PONG (or -ERR).
fn handshake(c: *Conn, opts: Options) !void {
    const info_json = switch (try c.readOpSync()) {
        .info => |j| j,
        else => return error.ProtocolError,
    };
    const Info = struct { nonce: ?[]const u8 = null, max_payload: ?usize = null, headers: bool = false };
    const info = std.json.parseFromSlice(Info, c.gpa, info_json, .{ .ignore_unknown_fields = true }) catch
        return error.ProtocolError;
    defer info.deinit();
    if (info.value.max_payload) |m| c.max_payload = @min(m, read_buf_size - protocol.max_control_line - 64);

    // Signature of the nonce, base64url without padding
    var sig_text: [std.base64.url_safe_no_pad.Encoder.calcSize(nkeys.signature_len)]u8 = undefined;
    var sig: ?[]const u8 = null;
    var nkey_pub: [nkeys.public_len]u8 = undefined;
    if (opts.key) |k| {
        const nonce = info.value.nonce orelse return error.ProtocolError;
        const raw = try k.sign(nonce);
        sig = std.base64.url_safe_no_pad.Encoder.encode(&sig_text, &raw);
        nkey_pub = k.publicKey().encode();
    }

    const connect_opts = .{
        .verbose = false,
        .pedantic = false,
        .lang = "zig",
        .version = "0.0.0",
        .protocol = 1,
        .name = opts.name,
        .echo = opts.echo,
        .headers = true,
        .no_responders = true,
        .jwt = opts.jwt,
        // Plain nkey users (no JWT) identify themselves with the public key
        .nkey = if (opts.key != null and opts.jwt == null) @as(?[]const u8, &nkey_pub) else null,
        .sig = sig,
        .auth_token = opts.token,
    };
    const json = try std.json.Stringify.valueAlloc(c.gpa, connect_opts, .{ .emit_null_optional_fields = false });
    defer c.gpa.free(json);

    const w = c.out;
    try protocol.writeConnect(w, json);
    try protocol.writePing(w);
    try c.flushOut();

    while (true) switch (try c.readOpSync()) {
        .pong => return,
        .ping => {
            try protocol.writePong(w);
            try c.flushOut();
        },
        .ok, .info => {},
        .err => |text| {
            c.setLastError(text);
            return error.ServerRejected;
        },
        .msg => return error.ProtocolError,
    };
}

/// Reads one operation before the reader task runs. Slices are valid until
/// the next read.
fn readOpSync(c: *Conn) !protocol.Op {
    const r = c.in;
    while (true) {
        if (protocol.parse(r.buffered()) catch return error.ProtocolError) |p| {
            r.toss(p.consumed);
            return p.op;
        }
        r.fillMore() catch return error.ConnectionClosed;
    }
}

fn setLastError(c: *Conn, text: []const u8) void {
    const n = @min(text.len, c.last_error.len);
    @memcpy(c.last_error[0..n], text[0..n]);
    c.last_error_len = n;
}

/// Error text of the last -ERR received from the server.
pub fn lastError(c: *const Conn) []const u8 {
    return c.last_error[0..c.last_error_len];
}

fn readLoop(c: *Conn) void {
    c.readLoopInner() catch {};
    const io = c.io;
    c.mutex.lockUncancelable(io);
    defer c.mutex.unlock(io);
    c.closed = true;
    var it = c.subs.valueIterator();
    while (it.next()) |s| s.*.cond.broadcast(io);
    c.pong_cond.broadcast(io);
}

fn readLoopInner(c: *Conn) !void {
    const r = c.in;
    while (true) {
        while (try protocol.parse(r.buffered())) |p| {
            try c.handleOp(p.op);
            r.toss(p.consumed);
        }
        try r.fillMore();
    }
}

fn handleOp(c: *Conn, op: protocol.Op) !void {
    const io = c.io;
    switch (op) {
        .ping => try c.writeOp(protocol.writePong, .{}),
        .pong => {
            c.mutex.lockUncancelable(io);
            defer c.mutex.unlock(io);
            c.pongs += 1;
            c.pong_cond.broadcast(io);
        },
        .msg => |m| {
            c.mutex.lockUncancelable(io);
            defer c.mutex.unlock(io);
            const s = c.subs.get(m.sid) orelse return; // already unsubscribed
            const owned = try Message.copy(c.gpa, m);
            s.pending.append(c.gpa, owned) catch |e| {
                owned.deinit(c.gpa);
                return e;
            };
            s.cond.signal(io);
        },
        .err => |text| {
            c.mutex.lockUncancelable(io);
            defer c.mutex.unlock(io);
            c.setLastError(text);
        },
        .ok, .info => {},
    }
}

/// Runs a protocol write function under the write lock and flushes.
fn writeOp(c: *Conn, comptime f: anytype, args: anytype) !void {
    c.write_mutex.lockUncancelable(c.io);
    defer c.write_mutex.unlock(c.io);
    try @call(.auto, f, .{c.out} ++ args);
    try c.flushOut();
}

pub fn publish(c: *Conn, subject: []const u8, payload: []const u8) !void {
    return c.publishReply(subject, null, payload);
}

pub fn publishReply(c: *Conn, subject: []const u8, reply: ?[]const u8, payload: []const u8) !void {
    if (payload.len > c.max_payload) return error.PayloadTooLarge;
    if (c.isClosed()) return error.ConnectionClosed;
    try c.writeOp(protocol.writePub, .{ subject, reply, payload });
}

/// Sends a request and waits for the first reply. The reply subject is a
/// fresh inbox under the connection's inbox prefix. The caller owns the reply.
pub fn request(c: *Conn, subject: []const u8, payload: []const u8, timeout: Io.Timeout) !Message {
    var rand: [12]u8 = undefined;
    c.io.random(&rand);
    var token: [16]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&token, &rand);
    // base64url may produce '-' and '_' only, both valid in a subject token
    const inbox = try std.fmt.allocPrint(c.gpa, "{s}.{s}", .{ c.inbox_prefix, token });
    defer c.gpa.free(inbox);

    const s = try c.subscribeMax(inbox, 1);
    defer s.unsubscribe();
    try c.publishReply(subject, inbox, payload);

    const m = try s.next(timeout);
    if (m.headers) |h| {
        const parsed = protocol.Headers.parse(h) catch {
            m.deinit(c.gpa);
            return error.ProtocolError;
        };
        if (parsed.status == 503 and m.payload.len == 0) {
            m.deinit(c.gpa);
            return error.NoResponders;
        }
    }
    return m;
}

/// Subscription that the server ends after `max` messages.
fn subscribeMax(c: *Conn, subject: []const u8, max: u64) !*Sub {
    const s = try c.subscribe(subject);
    errdefer s.unsubscribe();
    try c.writeOp(protocol.writeUnsub, .{ s.sid, max });
    return s;
}

pub fn subscribe(c: *Conn, subject: []const u8) !*Sub {
    if (!protocol.isSubscribeSubject(subject)) return error.InvalidSubject;
    const s = try c.gpa.create(Sub);
    errdefer c.gpa.destroy(s);
    {
        c.mutex.lockUncancelable(c.io);
        defer c.mutex.unlock(c.io);
        if (c.closed) return error.ConnectionClosed;
        s.* = .{ .conn = c, .sid = c.next_sid };
        c.next_sid += 1;
        try c.subs.put(c.gpa, s.sid, s);
    }
    errdefer {
        c.mutex.lockUncancelable(c.io);
        _ = c.subs.remove(s.sid);
        c.mutex.unlock(c.io);
    }
    try c.writeOp(protocol.writeSub, .{ subject, null, s.sid });
    return s;
}

/// Sends a PING and waits for its PONG: everything written before has been
/// processed by the server.
pub fn flush(c: *Conn, timeout: Io.Timeout) !void {
    const io = c.io;
    const deadline = timeout.toDeadline(io);
    c.mutex.lockUncancelable(io);
    c.pings += 1;
    const want = c.pings;
    c.mutex.unlock(io);
    try c.writeOp(protocol.writePing, .{});

    c.mutex.lockUncancelable(io);
    defer c.mutex.unlock(io);
    while (c.pongs < want) {
        if (c.closed) return error.ConnectionClosed;
        c.pong_cond.waitTimeout(io, &c.mutex, deadline) catch |e| switch (e) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
        };
    }
}

pub fn isClosed(c: *Conn) bool {
    c.mutex.lockUncancelable(c.io);
    defer c.mutex.unlock(c.io);
    return c.closed;
}
