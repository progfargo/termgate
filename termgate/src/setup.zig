//! First start: creates termgate's keys, its CA, the relay's certificate,
//! termgate's relay configuration and the relay kit.
//!
//! In termgate's app folder:
//!   relay.json        relay address, CA file, termgate's four keys (0600)
//!   ca.pem            termgate's CA certificate (public)
//!   keys/ca.key       the CA's private key (0600), to renew the relay's
//!                     certificate later
//!   keys/log.key      the key session logs are encrypted with (0600)
//!   relay-kit/        what the relay needs, copied to the relay's server:
//!     nats-server.conf  TLS from the first byte, auth callout to termgate
//!     server.pem        the relay's certificate, signed by the CA
//!     server.key        the relay's private key (0600)
//!     README.txt        how to start it
//! The relay kit holds no key that grants access: the relay's TLS key only
//! proves the relay's identity, and termgate decides every connection.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const x509 = core.x509;
const KeyPair = core.nkeys.KeyPair;

pub const Input = struct {
    /// Address nodes and users reach the relay at (DNS name or IP)
    relay_host: []const u8,
    relay_port: u16 = 4222,
};

pub const Error = error{ AlreadySetUp, InvalidHost };

const ca_years = 20;
const relay_cert_years = 10;
const year_s: i64 = 365 * 86400;

/// Creates everything in `app_dir` (absolute path of termgate's app folder).
pub fn create(gpa: std.mem.Allocator, io: Io, app_dir: []const u8, input: Input, now: i64) !void {
    if (!validHost(input.relay_host)) return error.InvalidHost;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cwd = Io.Dir.cwd();

    const relay_json = try std.fs.path.join(a, &.{ app_dir, "relay.json" });
    if (cwd.statFile(io, relay_json, .{})) |_| return error.AlreadySetUp else |e| switch (e) {
        error.FileNotFound => {},
        else => return e,
    }

    // termgate's keys
    const issuer = try KeyPair.generate(.account, io);
    const callout = try KeyPair.generate(.user, io);
    const app = try KeyPair.generate(.user, io);
    // Reads connection events in the system account (who is online)
    const system = try KeyPair.generate(.user, io);

    // CA and the relay's certificate
    const ca_key = x509.KeyPair.generate(io);
    const relay_key = x509.KeyPair.generate(io);
    var serial1: [16]u8 = undefined;
    io.random(&serial1);
    var serial2: [16]u8 = undefined;
    io.random(&serial2);
    const ca_cn = "termgate CA";
    const ca_der = try x509.caCert(a, ca_key, ca_cn, .{ .not_before = now - 3600, .not_after = now + ca_years * year_s }, serial1);
    const relay_der = try x509.serverCert(a, ca_key, ca_cn, relay_key.public_key, input.relay_host, &.{input.relay_host}, .{ .not_before = now - 3600, .not_after = now + relay_cert_years * year_s }, serial2);
    const ca_pem = try x509.pem(a, "CERTIFICATE", ca_der);

    // Files
    try cwd.createDirPath(io, app_dir);
    const keys_dir = try std.fs.path.join(a, &.{ app_dir, "keys" });
    const kit_dir = try std.fs.path.join(a, &.{ app_dir, "relay-kit" });
    try cwd.createDirPath(io, keys_dir);
    try cwd.createDirPath(io, kit_dir);

    const ca_path = try std.fs.path.join(a, &.{ app_dir, "ca.pem" });
    try writeFile(io, ca_path, ca_pem, 0o644);
    try writeFile(io, try std.fs.path.join(a, &.{ keys_dir, "ca.key" }), try x509.pem(a, "EC PRIVATE KEY", try x509.ecPrivateKeyDer(a, ca_key)), 0o600);
    _ = try logKey(io, app_dir);

    try writeFile(io, try std.fs.path.join(a, &.{ kit_dir, "server.pem" }), try x509.pem(a, "CERTIFICATE", relay_der), 0o644);
    try writeFile(io, try std.fs.path.join(a, &.{ kit_dir, "server.key" }), try x509.pem(a, "EC PRIVATE KEY", try x509.ecPrivateKeyDer(a, relay_key)), 0o600);
    try writeFile(io, try std.fs.path.join(a, &.{ kit_dir, "nats-server.conf" }), try natsConfig(a, input.relay_port, &issuer.publicKey().encode(), &callout.publicKey().encode(), &system.publicKey().encode()), 0o644);
    try writeFile(io, try std.fs.path.join(a, &.{ kit_dir, "README.txt" }), try readme(a, input), 0o644);

    // Last, so a failed setup can simply be run again
    const cfg = try std.json.Stringify.valueAlloc(a, .{
        .relay_host = input.relay_host,
        .relay_port = input.relay_port,
        // Relative to relay.json: the folder can be moved
        .ca_pem_file = "ca.pem",
        .issuer_seed = @as([]const u8, &issuer.encodeSeed()),
        .callout_seed = @as([]const u8, &callout.encodeSeed()),
        .app_seed = @as([]const u8, &app.encodeSeed()),
        .system_seed = @as([]const u8, &system.encodeSeed()),
    }, .{ .whitespace = .indent_2 });
    try writeFile(io, relay_json, cfg, 0o600);
}

fn writeFile(io: Io, path: []const u8, data: []const u8, mode: u32) !void {
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data, .flags = .{ .permissions = .fromMode(mode) } });
}

/// A DNS name or an IP address.
pub fn validHost(h: []const u8) bool {
    if (h.len == 0 or h.len > 253) return false;
    if (std.Io.net.IpAddress.parse(h, 0)) |_| return true else |_| {}
    var it = std.mem.splitScalar(u8, h, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-')) return false;
    }
    return true;
}

/// The session log key in `app_dir`/keys/log.key: read, or made (32
/// random bytes, 0600) if there is none yet. Whoever has it can read the
/// logs; it belongs with termgate's other keys.
pub fn logKey(io: Io, app_dir: []const u8) ![32]u8 {
    var buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&buf, "{s}/keys/log.key", .{app_dir});
    const cwd = Io.Dir.cwd();
    var key: [32]u8 = undefined;
    var read_buf: [64]u8 = undefined;
    if (cwd.readFile(io, path, &read_buf)) |data| {
        if (data.len != key.len) return error.InvalidLogKey;
        @memcpy(&key, data);
        return key;
    } else |e| if (e != error.FileNotFound) return e;
    io.random(&key);
    try cwd.createDirPath(io, std.fs.path.dirname(path).?);
    try writeFile(io, path, &key, 0o600);
    return key;
}

/// nats-server configuration of the relay: TLS from the first byte, every
/// client put to termgate's auth callout. termgate's callout user sits in the
/// AUTH account and its system user in SYS (connection events); nodes and
/// users are placed in APP.
fn natsConfig(a: std.mem.Allocator, port: u16, issuer_pub: []const u8, callout_pub: []const u8, system_pub: []const u8) ![]u8 {
    return std.fmt.allocPrint(a,
        \\# termgate relay, generated by termgate. Holds no key that grants access:
        \\# termgate decides every connection through the auth callout.
        \\listen: 0.0.0.0:{d}
        \\tls {{
        \\  cert_file: "server.pem"
        \\  key_file: "server.key"
        \\  handshake_first: true
        \\}}
        \\accounts {{
        \\  AUTH {{ users: [ {{ nkey: {s} }} ] }}
        \\  APP {{}}
        \\  SYS {{ users: [ {{ nkey: {s} }} ] }}
        \\}}
        \\system_account: SYS
        \\authorization {{
        \\  auth_callout {{
        \\    issuer: {s}
        \\    auth_users: [ {s}, {s} ]
        \\    account: AUTH
        \\  }}
        \\}}
        \\
    , .{ port, callout_pub, system_pub, issuer_pub, callout_pub, system_pub });
}

fn readme(a: std.mem.Allocator, input: Input) ![]u8 {
    return std.fmt.allocPrint(a,
        \\termgate relay kit
        \\
        \\The relay's files. termgate runs the relay itself from this folder
        \\(the official nats-server, as "nats-server -c nats-server.conf").
        \\Nodes and users reach it at {s}:{d}.
        \\
        \\The port {d} must be reachable from the nodes and the users.
        \\server.key is the relay's TLS key: keep it readable by the relay only.
        \\
    , .{ input.relay_host, input.relay_port, input.relay_port });
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "setup creates the files once; the certificate is for the relay host" {
    const a = testing.allocator;
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const app_dir = try std.fs.path.join(a, &.{ path_buf[0..n], "app" });
    defer a.free(app_dir);

    const t0: i64 = 1794289057;
    try create(a, io, app_dir, .{ .relay_host = "relay.example.com", .relay_port = 4222 }, t0);
    try testing.expectError(error.AlreadySetUp, create(a, io, app_dir, .{ .relay_host = "relay.example.com" }, t0));

    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const ar = arena.allocator();
    const read = struct {
        fn f(al: std.mem.Allocator, dir: []const u8, name: []const u8) ![]u8 {
            const p = try std.fs.path.join(al, &.{ dir, name });
            return Io.Dir.cwd().readFileAlloc(testing.io, p, al, .limited(1 << 20));
        }
    }.f;

    // relay.json: readable by the admin only, keys decode
    const cfg_path = try std.fs.path.join(ar, &.{ app_dir, "relay.json" });
    const st = try Io.Dir.cwd().statFile(io, cfg_path, .{});
    try testing.expectEqual(@as(u32, 0o600), st.permissions.toMode() & 0o777);
    const Cfg = struct { relay_host: []const u8, relay_port: u16, ca_pem_file: []const u8, issuer_seed: []const u8, callout_seed: []const u8, app_seed: []const u8, system_seed: []const u8 };
    const cfg = try std.json.parseFromSliceLeaky(Cfg, ar, try read(ar, app_dir, "relay.json"), .{});
    const issuer = try KeyPair.decodeSeed(cfg.issuer_seed);
    try testing.expectEqual(core.nkeys.Prefix.account, issuer.prefix);
    const callout = try KeyPair.decodeSeed(cfg.callout_seed);

    // The relay certificate verifies under the CA and names the relay host
    const ca_der = try core.code.firstCertDer(ar, try read(ar, app_dir, "ca.pem"));
    const srv_der = try core.code.firstCertDer(ar, try read(ar, app_dir, "relay-kit/server.pem"));
    const C = std.crypto.Certificate;
    const ca_p = try C.parse(.{ .buffer = ca_der, .index = 0 });
    const srv_p = try C.parse(.{ .buffer = srv_der, .index = 0 });
    try srv_p.verify(ca_p, t0);
    try srv_p.verifyHostName("relay.example.com");

    // The kit names termgate's keys; the CA and relay keys read back
    const conf = try read(ar, app_dir, "relay-kit/nats-server.conf");
    try testing.expect(std.mem.indexOf(u8, conf, &issuer.publicKey().encode()) != null);
    try testing.expect(std.mem.indexOf(u8, conf, &callout.publicKey().encode()) != null);
    try testing.expect(std.mem.indexOf(u8, conf, "listen: 0.0.0.0:4222") != null);
    // The log key: made at setup, 0600, read back the same
    const lk = try logKey(io, app_dir);
    try testing.expectEqualSlices(u8, &lk, &(try logKey(io, app_dir)));
    const lst = try Io.Dir.cwd().statFile(io, try std.fs.path.join(ar, &.{ app_dir, "keys/log.key" }), .{});
    try testing.expectEqual(@as(u32, 0o600), lst.permissions.toMode() & 0o777);
    const system = try KeyPair.decodeSeed(cfg.system_seed);
    try testing.expect(std.mem.indexOf(u8, conf, &system.publicKey().encode()) != null);
    _ = try x509.ecPrivateKeyFromDer(try core.code.firstPemBlockDer(ar, try read(ar, app_dir, "keys/ca.key"), "EC PRIVATE KEY"));
}

test "relay host check" {
    try testing.expect(validHost("relay.example.com"));
    try testing.expect(validHost("10.0.0.5"));
    try testing.expect(validHost("::1"));
    try testing.expect(validHost("relay-1"));
    try testing.expect(!validHost(""));
    try testing.expect(!validHost("relay..example.com"));
    try testing.expect(!validHost("-relay.com"));
    try testing.expect(!validHost("relay example.com"));
    try testing.expect(!validHost("relay.com:4222"));
}
