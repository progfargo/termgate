//! First contact with a relay from a node key or an invitation.
//!
//! The code carries only the SHA-256 of termgate's CA. fetchCa connects
//! without certificate verification, asks for the CA (ca.get, allowed for any
//! key) and returns it only if it matches the fingerprint. Nothing secret is
//! sent on that connection; the token goes out only over a connection verified
//! against the returned CA.

const std = @import("std");
const Io = std.Io;
const nkeys = @import("nkeys.zig");
const code_mod = @import("code.zig");
const Conn = @import("nats/Conn.zig");

pub const Error = error{
    /// The relay's CA does not match the code: wrong relay or someone in between
    WrongCa,
};

/// Fetches termgate's CA (PEM) and checks it against the code. `inbox` is the
/// caller's inbox prefix ("_INBOX.<key>"). The result lives in `arena`.
pub fn fetchCa(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, code: code_mod.Code, key: nkeys.KeyPair, inbox: []const u8, client_name: []const u8) ![]const u8 {
    const conn = try Conn.connect(gpa, io, .{
        .host = code.host,
        .port = code.port,
        .key = key,
        .name = client_name,
        .inbox_prefix = inbox,
        .tls = .{ .ca_pem = "", .insecure = true },
    });
    defer conn.close();
    const m = try conn.request("ca.get", "", Conn.seconds(15));
    defer m.deinit(gpa);
    const fp = code_mod.caFingerprint(gpa, m.payload) catch return error.WrongCa;
    if (!std.mem.eql(u8, &fp, &code.ca_fingerprint)) return error.WrongCa;
    return arena.dupe(u8, m.payload);
}
