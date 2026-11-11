//! NATS client protocol: parsing server operations and encoding client
//! operations. No I/O; the connection feeds bytes in and writes bytes out.
//!
//! Server -> client: INFO, MSG, HMSG, PING, PONG, +OK, -ERR.
//! Client -> server: CONNECT, PUB, HPUB, SUB, UNSUB, PING, PONG.
//! Reference: https://docs.nats.io/reference/reference-protocols/nats-protocol

const std = @import("std");

/// Longest control line accepted from the server (the server's default).
pub const max_control_line = 4096;

pub const ParseError = error{ ProtocolError, ControlLineTooLong };

pub const Msg = struct {
    subject: []const u8,
    sid: u64,
    reply: ?[]const u8,
    /// Raw header block ("NATS/1.0 ...\r\n...\r\n\r\n") for HMSG, null for MSG
    headers: ?[]const u8,
    payload: []const u8,
};

pub const Op = union(enum) {
    /// JSON body of INFO
    info: []const u8,
    msg: Msg,
    ping,
    pong,
    ok,
    /// Message of -ERR, without quotes
    err: []const u8,
};

pub const Parsed = struct {
    op: Op,
    /// Bytes of the input this operation used
    consumed: usize,
};

/// Parses one server operation from the start of `buf`. Returns null when
/// `buf` does not hold a whole operation yet. Slices in the result point
/// into `buf`.
pub fn parse(buf: []const u8) ParseError!?Parsed {
    const eol = std.mem.indexOf(u8, buf, "\r\n") orelse {
        if (buf.len > max_control_line) return error.ControlLineTooLong;
        return null;
    };
    if (eol > max_control_line) return error.ControlLineTooLong;
    const line = buf[0..eol];
    const after = eol + 2;

    const sp = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
    const name = line[0..sp];
    const rest = std.mem.trim(u8, line[sp..], " \t");

    if (eqlUpper(name, "MSG")) return parseMsg(buf, rest, after, false);
    if (eqlUpper(name, "HMSG")) return parseMsg(buf, rest, after, true);
    if (eqlUpper(name, "PING")) return .{ .op = .ping, .consumed = after };
    if (eqlUpper(name, "PONG")) return .{ .op = .pong, .consumed = after };
    if (eqlUpper(name, "+OK")) return .{ .op = .ok, .consumed = after };
    if (eqlUpper(name, "-ERR")) return .{ .op = .{ .err = std.mem.trim(u8, rest, "'") }, .consumed = after };
    if (eqlUpper(name, "INFO")) return .{ .op = .{ .info = rest }, .consumed = after };
    return error.ProtocolError;
}

fn eqlUpper(a: []const u8, comptime upper: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, upper);
}

/// MSG <subject> <sid> [reply-to] <#bytes>
/// HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>
fn parseMsg(buf: []const u8, args: []const u8, start: usize, with_headers: bool) ParseError!?Parsed {
    var fields: [5][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, args, " \t");
    while (it.next()) |f| {
        if (n == fields.len) return error.ProtocolError;
        fields[n] = f;
        n += 1;
    }
    const sizes: usize = if (with_headers) 2 else 1;
    if (n != 2 + sizes and n != 3 + sizes) return error.ProtocolError;
    const has_reply = n == 3 + sizes;

    const total = parseSize(fields[n - 1]) orelse return error.ProtocolError;
    const hdr_len: usize = if (with_headers) parseSize(fields[n - 2]) orelse return error.ProtocolError else 0;
    if (hdr_len > total) return error.ProtocolError;

    // Payload plus trailing CRLF must be in the buffer
    if (buf.len < start + total + 2) return null;
    if (!std.mem.eql(u8, buf[start + total ..][0..2], "\r\n")) return error.ProtocolError;

    const body = buf[start..][0..total];
    return .{
        .op = .{ .msg = .{
            .subject = fields[0],
            .sid = std.fmt.parseInt(u64, fields[1], 10) catch return error.ProtocolError,
            .reply = if (has_reply) fields[2] else null,
            .headers = if (with_headers) body[0..hdr_len] else null,
            .payload = body[hdr_len..],
        } },
        .consumed = start + total + 2,
    };
}

fn parseSize(s: []const u8) ?usize {
    return std.fmt.parseInt(usize, s, 10) catch null;
}

// ---------------------------------------------------------------------------
// Subjects

/// A subject a client may publish to: non-empty dot-separated tokens of
/// printable characters, no whitespace, no wildcards.
pub fn isPublishSubject(s: []const u8) bool {
    return checkSubject(s, false);
}

/// A subject a client may subscribe to: like isPublishSubject, but a token may
/// be the wildcard "*", and the last token may be ">".
pub fn isSubscribeSubject(s: []const u8) bool {
    return checkSubject(s, true);
}

fn checkSubject(s: []const u8, wildcards: bool) bool {
    if (s.len == 0) return false;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |tok| {
        if (tok.len == 0) return false;
        if (std.mem.eql(u8, tok, "*") or std.mem.eql(u8, tok, ">")) {
            if (!wildcards) return false;
            if (tok[0] == '>' and it.peek() != null) return false;
            continue;
        }
        for (tok) |c| {
            if (c <= ' ' or c == 0x7f) return false;
            if (c == '*' or c == '>') return false;
        }
    }
    return true;
}

/// A single subject token (e.g. a node name used inside a subject).
pub fn isToken(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (c <= ' ' or c == 0x7f or c == '.' or c == '*' or c == '>') return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Client operations

pub const EncodeError = error{InvalidSubject} || std.Io.Writer.Error;

pub fn writeConnect(w: *std.Io.Writer, options_json: []const u8) std.Io.Writer.Error!void {
    try w.print("CONNECT {s}\r\n", .{options_json});
}

pub fn writePub(w: *std.Io.Writer, subject: []const u8, reply: ?[]const u8, payload: []const u8) EncodeError!void {
    if (!isPublishSubject(subject)) return error.InvalidSubject;
    if (reply) |r| {
        if (!isPublishSubject(r)) return error.InvalidSubject;
        try w.print("PUB {s} {s} {d}\r\n", .{ subject, r, payload.len });
    } else {
        try w.print("PUB {s} {d}\r\n", .{ subject, payload.len });
    }
    try w.writeAll(payload);
    try w.writeAll("\r\n");
}

/// `headers` is a full header block ending in "\r\n\r\n" (see writeHeaders).
pub fn writeHpub(w: *std.Io.Writer, subject: []const u8, reply: ?[]const u8, headers: []const u8, payload: []const u8) EncodeError!void {
    if (!isPublishSubject(subject)) return error.InvalidSubject;
    const total = headers.len + payload.len;
    if (reply) |r| {
        if (!isPublishSubject(r)) return error.InvalidSubject;
        try w.print("HPUB {s} {s} {d} {d}\r\n", .{ subject, r, headers.len, total });
    } else {
        try w.print("HPUB {s} {d} {d}\r\n", .{ subject, headers.len, total });
    }
    try w.writeAll(headers);
    try w.writeAll(payload);
    try w.writeAll("\r\n");
}

pub fn writeSub(w: *std.Io.Writer, subject: []const u8, queue: ?[]const u8, sid: u64) EncodeError!void {
    if (!isSubscribeSubject(subject)) return error.InvalidSubject;
    if (queue) |q| {
        if (!isToken(q)) return error.InvalidSubject;
        try w.print("SUB {s} {s} {d}\r\n", .{ subject, q, sid });
    } else {
        try w.print("SUB {s} {d}\r\n", .{ subject, sid });
    }
}

pub fn writeUnsub(w: *std.Io.Writer, sid: u64, max_msgs: ?u64) std.Io.Writer.Error!void {
    if (max_msgs) |m| {
        try w.print("UNSUB {d} {d}\r\n", .{ sid, m });
    } else {
        try w.print("UNSUB {d}\r\n", .{sid});
    }
}

pub fn writePing(w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("PING\r\n");
}

pub fn writePong(w: *std.Io.Writer) std.Io.Writer.Error!void {
    try w.writeAll("PONG\r\n");
}

// ---------------------------------------------------------------------------
// Headers

pub const Header = struct { name: []const u8, value: []const u8 };

/// Writes a header block: "NATS/1.0\r\n" + "Name: value\r\n"... + "\r\n".
pub fn writeHeaders(w: *std.Io.Writer, headers: []const Header) EncodeError!void {
    try w.writeAll("NATS/1.0\r\n");
    for (headers) |h| {
        if (!validHeaderName(h.name) or std.mem.indexOfAny(u8, h.value, "\r\n") != null)
            return error.InvalidSubject;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
    try w.writeAll("\r\n");
}

fn validHeaderName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (c <= ' ' or c == ':' or c == 0x7f) return false;
    return true;
}

/// Parsed view of a received header block.
pub const Headers = struct {
    /// Status code from the first line ("NATS/1.0 503"), 0 if none
    status: u16,
    /// Status description after the code, may be empty
    description: []const u8,
    block: []const u8,

    pub fn parse(block: []const u8) ParseError!Headers {
        const eol = std.mem.indexOf(u8, block, "\r\n") orelse return error.ProtocolError;
        const first = block[0..eol];
        if (!std.mem.startsWith(u8, first, "NATS/1.0")) return error.ProtocolError;
        var rest = std.mem.trim(u8, first["NATS/1.0".len..], " ");
        var status: u16 = 0;
        var description: []const u8 = "";
        if (rest.len >= 3) {
            status = std.fmt.parseInt(u16, rest[0..3], 10) catch return error.ProtocolError;
            description = std.mem.trim(u8, rest[3..], " ");
        } else if (rest.len != 0) return error.ProtocolError;
        rest = "";
        return .{ .status = status, .description = description, .block = block[eol + 2 ..] };
    }

    /// First value of a header, matched case-insensitively.
    pub fn get(self: Headers, name: []const u8) ?[]const u8 {
        var it = std.mem.splitSequence(u8, self.block, "\r\n");
        while (it.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (std.ascii.eqlIgnoreCase(line[0..colon], name))
                return std.mem.trim(u8, line[colon + 1 ..], " ");
        }
        return null;
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

fn parseAll(buf: []const u8) !Parsed {
    return (try parse(buf)) orelse error.Incomplete;
}

test "control operations" {
    try testing.expectEqual(Op.ping, (try parseAll("PING\r\n")).op);
    try testing.expectEqual(Op.pong, (try parseAll("pong\r\n")).op);
    try testing.expectEqual(Op.ok, (try parseAll("+OK\r\n")).op);
    const e = try parseAll("-ERR 'Authorization Violation'\r\n");
    try testing.expectEqualStrings("Authorization Violation", e.op.err);
    const i = try parseAll("INFO {\"server_id\":\"x\",\"nonce\":\"abc\"}\r\nPING\r\n");
    try testing.expectEqualStrings("{\"server_id\":\"x\",\"nonce\":\"abc\"}", i.op.info);
    try testing.expectEqual(@as(usize, 38), i.consumed);
}

test "MSG with and without reply" {
    const p = try parseAll("MSG out.gw17.U1.s1 9 11\r\nhello world\r\n");
    try testing.expectEqualStrings("out.gw17.U1.s1", p.op.msg.subject);
    try testing.expectEqual(@as(u64, 9), p.op.msg.sid);
    try testing.expectEqual(@as(?[]const u8, null), p.op.msg.reply);
    try testing.expectEqualStrings("hello world", p.op.msg.payload);
    try testing.expectEqual(@as(usize, 38), p.consumed);

    const r = try parseAll("MSG session.open.gw17 2 _INBOX.U1.x 2\r\nhi\r\n");
    try testing.expectEqualStrings("_INBOX.U1.x", r.op.msg.reply.?);
    try testing.expectEqualStrings("hi", r.op.msg.payload);

    // Binary payload that contains CRLF
    const b = try parseAll("MSG a 1 4\r\n\r\n\r\n\r\n");
    try testing.expectEqualStrings("\r\n\r\n", b.op.msg.payload);
}

test "HMSG splits headers and payload" {
    const hdr = "NATS/1.0 503\r\n\r\n";
    const line = std.fmt.comptimePrint("HMSG _INBOX.U1.x 3 {d} {d}\r\n", .{ hdr.len, hdr.len });
    const p = try parseAll(line ++ hdr ++ "\r\n");
    try testing.expectEqualStrings(hdr, p.op.msg.headers.?);
    try testing.expectEqualStrings("", p.op.msg.payload);
    const h = try Headers.parse(p.op.msg.headers.?);
    try testing.expectEqual(@as(u16, 503), h.status);

    const kv_hdr = "NATS/1.0\r\nKV-Operation: DEL\r\nNats-Sequence: 42\r\n\r\n";
    const kv = try Headers.parse(kv_hdr);
    try testing.expectEqual(@as(u16, 0), kv.status);
    try testing.expectEqualStrings("DEL", kv.get("kv-operation").?);
    try testing.expectEqualStrings("42", kv.get("Nats-Sequence").?);
    try testing.expectEqual(@as(?[]const u8, null), kv.get("Missing"));
}

test "incomplete input returns null" {
    try testing.expectEqual(@as(?Parsed, null), try parse(""));
    try testing.expectEqual(@as(?Parsed, null), try parse("PIN"));
    try testing.expectEqual(@as(?Parsed, null), try parse("MSG a 1 5\r\nhel"));
    try testing.expectEqual(@as(?Parsed, null), try parse("MSG a 1 5\r\nhello"));
}

test "malformed input is rejected" {
    try testing.expectError(error.ProtocolError, parse("BOGUS\r\n"));
    try testing.expectError(error.ProtocolError, parse("MSG a 1\r\n"));
    try testing.expectError(error.ProtocolError, parse("MSG a x 1\r\nx\r\n"));
    try testing.expectError(error.ProtocolError, parse("MSG a 1 2\r\nhiXX"));
    try testing.expectError(error.ProtocolError, parse("HMSG a 1 5 2\r\nhi\r\n"));
    const long: [max_control_line + 8]u8 = @splat('a');
    try testing.expectError(error.ControlLineTooLong, parse(&long));
}

test "encoding client operations" {
    var buf: [256]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeConnect(&w, "{\"verbose\":false}");
    try writePub(&w, "in.gw17.U1.s1", null, "ls\n");
    try writePub(&w, "session.open.gw17", "_INBOX.U1.a", "{}");
    try writeSub(&w, "out.*.U1.>", null, 7);
    try writeSub(&w, "jobs", "workers", 8);
    try writeUnsub(&w, 7, null);
    try writeUnsub(&w, 8, 1);
    try writePing(&w);
    try testing.expectEqualStrings(
        "CONNECT {\"verbose\":false}\r\n" ++
            "PUB in.gw17.U1.s1 3\r\nls\n\r\n" ++
            "PUB session.open.gw17 _INBOX.U1.a 2\r\n{}\r\n" ++
            "SUB out.*.U1.> 7\r\n" ++
            "SUB jobs workers 8\r\n" ++
            "UNSUB 7\r\nUNSUB 8 1\r\nPING\r\n",
        w.buffered(),
    );
}

test "HPUB with a header block" {
    var hbuf: [64]u8 = undefined;
    var hw: std.Io.Writer = .fixed(&hbuf);
    try writeHeaders(&hw, &.{.{ .name = "KV-Operation", .value = "PURGE" }});
    var buf: [128]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeHpub(&w, "$KV.grants.g1", null, hw.buffered(), "x");
    try testing.expectEqualStrings("HPUB $KV.grants.g1 33 34\r\nNATS/1.0\r\nKV-Operation: PURGE\r\n\r\nx\r\n", w.buffered());
}

test "subjects that would break the protocol are refused" {
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidSubject, writePub(&w, "a b", null, ""));
    try testing.expectError(error.InvalidSubject, writePub(&w, "a\r\nPUB x 0", null, ""));
    try testing.expectError(error.InvalidSubject, writePub(&w, "a.*", null, ""));
    try testing.expectError(error.InvalidSubject, writePub(&w, "a..b", null, ""));
    try testing.expectError(error.InvalidSubject, writeSub(&w, "a.>.b", null, 1));
    try testing.expectError(error.InvalidSubject, writeSub(&w, "", null, 1));
    try testing.expect(isSubscribeSubject("in.*.U1.>"));
    try testing.expect(isToken("ist_kadikoy_gw01"));
    try testing.expect(!isToken("gw.17"));
    try testing.expect(!isToken("gw 17"));
}
