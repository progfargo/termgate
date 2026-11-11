//! X.509 certificates for termgate's private CA and the relay (ECDSA P-256,
//! SHA-256). Zig's standard library parses and verifies certificates but does
//! not write them, so this file has a small DER writer.
//!
//! - caCert: self-signed CA (basicConstraints CA:TRUE, keyCertSign).
//! - serverCert: the relay's certificate signed by the CA (serverAuth, the
//!   relay's DNS names and IP addresses as subjectAltName).
//! - ecPrivateKeyDer: SEC1 "EC PRIVATE KEY", which nats-server reads.
//! P-256 because Zig's TLS client does not accept Ed25519 server keys.

const std = @import("std");
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const KeyPair = Ecdsa.KeyPair;

// Object identifiers (DER contents, without tag and length)
const oid_ecdsa_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 }; // 1.2.840.10045.4.3.2
const oid_ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 }; // 1.2.840.10045.2.1
const oid_prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 }; // 1.2.840.10045.3.1.7
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 }; // 2.5.4.3
const oid_basic_constraints = [_]u8{ 0x55, 0x1d, 0x13 }; // 2.5.29.19
const oid_key_usage = [_]u8{ 0x55, 0x1d, 0x0f }; // 2.5.29.15
const oid_ext_key_usage = [_]u8{ 0x55, 0x1d, 0x25 }; // 2.5.29.37
const oid_subject_alt_name = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17
const oid_subject_key_id = [_]u8{ 0x55, 0x1d, 0x0e }; // 2.5.29.14
const oid_authority_key_id = [_]u8{ 0x55, 0x1d, 0x23 }; // 2.5.29.35
const oid_server_auth = [_]u8{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }; // 1.3.6.1.5.5.7.3.1

// ---------------------------------------------------------------------------
// DER writer

const Der = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    fn deinit(d: *Der) void {
        d.buf.deinit(d.gpa);
    }

    /// Starts a constructed element; finish it with end(start).
    fn begin(d: *Der, tag: u8) !usize {
        try d.buf.append(d.gpa, tag);
        try d.buf.append(d.gpa, 0); // length placeholder
        return d.buf.items.len;
    }

    /// Fixes the length of the element begun at `start` (its content start).
    fn end(d: *Der, start: usize) !void {
        const len = d.buf.items.len - start;
        if (len < 0x80) {
            d.buf.items[start - 1] = @intCast(len);
            return;
        }
        var lb: [4]u8 = undefined;
        var n: usize = 0;
        var v = len;
        while (v > 0) : (v >>= 8) n += 1;
        for (0..n) |i| lb[i] = @truncate(len >> @intCast(8 * (n - 1 - i)));
        d.buf.items[start - 1] = 0x80 | @as(u8, @intCast(n));
        try d.buf.insertSlice(d.gpa, start, lb[0..n]);
    }

    fn raw(d: *Der, tag: u8, content: []const u8) !void {
        const s = try d.begin(tag);
        try d.buf.appendSlice(d.gpa, content);
        try d.end(s);
    }

    /// Non-negative integer from big-endian bytes, minimal encoding.
    fn uint(d: *Der, be: []const u8) !void {
        var v = be;
        while (v.len > 1 and v[0] == 0) v = v[1..];
        const s = try d.begin(0x02);
        if (v[0] & 0x80 != 0) try d.buf.append(d.gpa, 0);
        try d.buf.appendSlice(d.gpa, v);
        try d.end(s);
    }

    fn oid(d: *Der, o: []const u8) !void {
        try d.raw(0x06, o);
    }

    fn boolean(d: *Der, v: bool) !void {
        try d.raw(0x01, &.{if (v) 0xff else 0x00});
    }

    /// BIT STRING with no unused bits
    fn bits(d: *Der, content: []const u8) !void {
        const s = try d.begin(0x03);
        try d.buf.append(d.gpa, 0);
        try d.buf.appendSlice(d.gpa, content);
        try d.end(s);
    }

    /// UTCTime until 2049, GeneralizedTime after (RFC 5280)
    fn time(d: *Der, unix: i64) !void {
        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix) };
        const yd = es.getEpochDay().calculateYearDay();
        const md = yd.calculateMonthDay();
        const ds = es.getDaySeconds();
        var b: [16]u8 = undefined;
        if (yd.year < 2050) {
            const t = try std.fmt.bufPrint(&b, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ yd.year % 100, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
            try d.raw(0x17, t);
        } else {
            const t = try std.fmt.bufPrint(&b, "{d:0>4}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{ yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() });
            try d.raw(0x18, t);
        }
    }

    /// Name with a single CN (UTF8String)
    fn name(d: *Der, cn: []const u8) !void {
        const s = try d.begin(0x30);
        const set = try d.begin(0x31);
        const atv = try d.begin(0x30);
        try d.oid(&oid_common_name);
        try d.raw(0x0c, cn);
        try d.end(atv);
        try d.end(set);
        try d.end(s);
    }

    fn algorithm(d: *Der) !void {
        const s = try d.begin(0x30);
        try d.oid(&oid_ecdsa_sha256);
        try d.end(s);
    }

    fn publicKeyInfo(d: *Der, pk: Ecdsa.PublicKey) !void {
        const s = try d.begin(0x30);
        const alg = try d.begin(0x30);
        try d.oid(&oid_ec_public_key);
        try d.oid(&oid_prime256v1);
        try d.end(alg);
        try d.bits(&pk.toUncompressedSec1());
        try d.end(s);
    }

    /// Extension: OID, optional critical flag, OCTET STRING with `inner` DER
    fn extension(d: *Der, o: []const u8, critical: bool, inner: []const u8) !void {
        const s = try d.begin(0x30);
        try d.oid(o);
        if (critical) try d.boolean(true);
        try d.raw(0x04, inner);
        try d.end(s);
    }
};

/// SHA-1 of the public key bits (RFC 5280 key identifier, method 1)
fn keyId(pk: Ecdsa.PublicKey) [20]u8 {
    var out: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(&pk.toUncompressedSec1(), &out, .{});
    return out;
}

pub const Validity = struct { not_before: i64, not_after: i64 };

/// Self-signed CA certificate (DER). The caller owns the result.
pub fn caCert(gpa: std.mem.Allocator, key: KeyPair, cn: []const u8, validity: Validity, serial: [16]u8) ![]u8 {
    var ext: Der = .{ .gpa = gpa };
    defer ext.deinit();
    {
        var bc: Der = .{ .gpa = gpa };
        defer bc.deinit();
        const s = try bc.begin(0x30);
        try bc.boolean(true);
        try bc.end(s);
        try ext.extension(&oid_basic_constraints, true, bc.buf.items);
    }
    // keyCertSign (bit 5) and cRLSign (bit 6): 0b0000_0110 shifted, 1 unused bit
    try ext.extension(&oid_key_usage, true, &.{ 0x03, 0x02, 0x01, 0x06 });
    {
        const id = keyId(key.public_key);
        var ski: Der = .{ .gpa = gpa };
        defer ski.deinit();
        try ski.raw(0x04, &id);
        try ext.extension(&oid_subject_key_id, false, ski.buf.items);
    }
    return certificate(gpa, key, cn, cn, key.public_key, validity, serial, ext.buf.items);
}

/// The relay's certificate (DER), signed by the CA. `hosts` are DNS names or
/// IP addresses (both v4 and v6 are recognized).
pub fn serverCert(gpa: std.mem.Allocator, ca_key: KeyPair, ca_cn: []const u8, server_key: Ecdsa.PublicKey, cn: []const u8, hosts: []const []const u8, validity: Validity, serial: [16]u8) ![]u8 {
    var ext: Der = .{ .gpa = gpa };
    defer ext.deinit();
    {
        var bc: Der = .{ .gpa = gpa };
        defer bc.deinit();
        const s = try bc.begin(0x30);
        try bc.end(s);
        try ext.extension(&oid_basic_constraints, true, bc.buf.items);
    }
    // digitalSignature (bit 0), 7 unused bits
    try ext.extension(&oid_key_usage, true, &.{ 0x03, 0x02, 0x07, 0x80 });
    {
        var eku: Der = .{ .gpa = gpa };
        defer eku.deinit();
        const s = try eku.begin(0x30);
        try eku.oid(&oid_server_auth);
        try eku.end(s);
        try ext.extension(&oid_ext_key_usage, false, eku.buf.items);
    }
    {
        var san: Der = .{ .gpa = gpa };
        defer san.deinit();
        const s = try san.begin(0x30);
        for (hosts) |h| {
            if (std.Io.net.IpAddress.parse(h, 0)) |ip| switch (ip) {
                .ip4 => |a| try san.raw(0x87, &a.bytes),
                .ip6 => |a| try san.raw(0x87, &a.bytes),
            } else |_| try san.raw(0x82, h);
        }
        try san.end(s);
        try ext.extension(&oid_subject_alt_name, false, san.buf.items);
    }
    {
        const id = keyId(ca_key.public_key);
        var aki: Der = .{ .gpa = gpa };
        defer aki.deinit();
        const s = try aki.begin(0x30);
        try aki.raw(0x80, &id);
        try aki.end(s);
        try ext.extension(&oid_authority_key_id, false, aki.buf.items);
    }
    return certificate(gpa, ca_key, ca_cn, cn, server_key, validity, serial, ext.buf.items);
}

fn certificate(gpa: std.mem.Allocator, signer: KeyPair, issuer_cn: []const u8, subject_cn: []const u8, subject_key: Ecdsa.PublicKey, validity: Validity, serial: [16]u8, extensions: []const u8) ![]u8 {
    var tbs: Der = .{ .gpa = gpa };
    defer tbs.deinit();
    const t = try tbs.begin(0x30);
    {
        const v = try tbs.begin(0xa0);
        try tbs.uint(&.{2}); // v3
        try tbs.end(v);
    }
    var ser = serial;
    ser[0] &= 0x7f; // positive
    if (std.mem.allEqual(u8, &ser, 0)) ser[15] = 1;
    try tbs.uint(&ser);
    try tbs.algorithm();
    try tbs.name(issuer_cn);
    {
        const v = try tbs.begin(0x30);
        try tbs.time(validity.not_before);
        try tbs.time(validity.not_after);
        try tbs.end(v);
    }
    try tbs.name(subject_cn);
    try tbs.publicKeyInfo(subject_key);
    {
        const e = try tbs.begin(0xa3);
        const seq = try tbs.begin(0x30);
        try tbs.buf.appendSlice(gpa, extensions);
        try tbs.end(seq);
        try tbs.end(e);
    }
    try tbs.end(t);

    const sig = try signer.sign(tbs.buf.items, null);
    var sig_buf: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig_der = sig.toDer(&sig_buf);

    var cert: Der = .{ .gpa = gpa };
    errdefer cert.deinit();
    const c = try cert.begin(0x30);
    try cert.buf.appendSlice(gpa, tbs.buf.items);
    try cert.algorithm();
    try cert.bits(sig_der);
    try cert.end(c);
    return cert.buf.toOwnedSlice(gpa);
}

/// SEC1 EC private key (DER), the format of "-----BEGIN EC PRIVATE KEY-----".
pub fn ecPrivateKeyDer(gpa: std.mem.Allocator, key: KeyPair) ![]u8 {
    var d: Der = .{ .gpa = gpa };
    errdefer d.deinit();
    const s = try d.begin(0x30);
    try d.uint(&.{1});
    try d.raw(0x04, &key.secret_key.toBytes());
    {
        const p = try d.begin(0xa0);
        try d.oid(&oid_prime256v1);
        try d.end(p);
    }
    {
        const p = try d.begin(0xa1);
        try d.bits(&key.public_key.toUncompressedSec1());
        try d.end(p);
    }
    try d.end(s);
    return d.buf.toOwnedSlice(gpa);
}

/// Reads back a key written by ecPrivateKeyDer.
pub fn ecPrivateKeyFromDer(der: []const u8) !KeyPair {
    // SEQ { INTEGER 1, OCTET STRING (32 bytes), ... }: the secret is at a fixed place
    if (der.len < 7 + 32 or der[0] != 0x30) return error.InvalidKey;
    const body = if (der[1] & 0x80 != 0) der[2 + (der[1] & 0x7f) ..] else der[2..];
    if (body.len < 5 + 32 or !std.mem.eql(u8, body[0..3], &.{ 0x02, 0x01, 0x01 }) or body[3] != 0x04 or body[4] != 32)
        return error.InvalidKey;
    const sk = try Ecdsa.SecretKey.fromBytes(body[5..37].*);
    return KeyPair.fromSecretKey(sk);
}

/// PEM text: "-----BEGIN <label>-----", base64 in 64-character lines.
pub fn pem(gpa: std.mem.Allocator, label: []const u8, der: []const u8) ![]u8 {
    const enc = std.base64.standard.Encoder;
    const b64 = try gpa.alloc(u8, enc.calcSize(der.len));
    defer gpa.free(b64);
    _ = enc.encode(b64, der);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.print(gpa, "-----BEGIN {s}-----\n", .{label});
    var i: usize = 0;
    while (i < b64.len) : (i += 64) {
        try out.appendSlice(gpa, b64[i..@min(i + 64, b64.len)]);
        try out.append(gpa, '\n');
    }
    try out.print(gpa, "-----END {s}-----\n", .{label});
    return out.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// Tests: the standard library's parser and verifier accept what we write

const testing = std.testing;
const Certificate = std.crypto.Certificate;
const t0: i64 = 1794289057;

fn parse(der: []const u8) !Certificate.Parsed {
    return Certificate.parse(.{ .buffer = der, .index = 0 });
}

test "CA and relay certificates verify with std.crypto.Certificate" {
    const a = testing.allocator;
    const ca_key = try KeyPair.generateDeterministic(@splat(1));
    const srv_key = try KeyPair.generateDeterministic(@splat(2));
    const validity: Validity = .{ .not_before = t0 - 60, .not_after = t0 + 10 * 365 * 86400 };

    const ca = try caCert(a, ca_key, "termgate CA", validity, @splat(0x81));
    defer a.free(ca);
    const srv = try serverCert(a, ca_key, "termgate CA", srv_key.public_key, "relay", &.{ "relay.example.com", "127.0.0.1", "::1" }, validity, @splat(0x42));
    defer a.free(srv);

    const ca_p = try parse(ca);
    const srv_p = try parse(srv);
    try testing.expectEqualStrings("termgate CA", ca_p.commonName());
    try testing.expectEqualStrings("relay", srv_p.commonName());
    // Self-signature of the CA, and the relay certificate under the CA
    try ca_p.verify(ca_p, t0);
    try srv_p.verify(ca_p, t0);
    try srv_p.verifyHostName("relay.example.com");
    try testing.expectError(error.CertificateExpired, srv_p.verify(ca_p, t0 + 11 * 365 * 86400));

    // A certificate signed by another CA does not verify under this one
    const other_ca = try KeyPair.generateDeterministic(@splat(3));
    const forged = try serverCert(a, other_ca, "termgate CA", srv_key.public_key, "relay", &.{"relay.example.com"}, validity, @splat(1));
    defer a.free(forged);
    try testing.expectError(error.CertificateSignatureInvalid, (try parse(forged)).verify(ca_p, t0));
}

test "long lengths and dates past 2049" {
    const a = testing.allocator;
    const key = try KeyPair.generateDeterministic(@splat(4));
    var long_name: [300]u8 = undefined;
    @memset(&long_name, 'x');
    const ca = try caCert(a, key, &long_name, .{ .not_before = t0, .not_after = 2556143999 }, @splat(0)); // 2050-12-31
    defer a.free(ca);
    const p = try parse(ca);
    try testing.expectEqualStrings(&long_name, p.commonName());
    try p.verify(p, t0 + 1);
}

test "private key round trip and PEM" {
    const a = testing.allocator;
    const key = try KeyPair.generateDeterministic(@splat(5));
    const der = try ecPrivateKeyDer(a, key);
    defer a.free(der);
    const back = try ecPrivateKeyFromDer(der);
    try testing.expectEqualSlices(u8, &key.public_key.toUncompressedSec1(), &back.public_key.toUncompressedSec1());

    const text = try pem(a, "EC PRIVATE KEY", der);
    defer a.free(text);
    try testing.expect(std.mem.startsWith(u8, text, "-----BEGIN EC PRIVATE KEY-----\n"));
    try testing.expect(std.mem.endsWith(u8, text, "-----END EC PRIVATE KEY-----\n"));
}
