//! NATS nkeys: text encoding of Ed25519 keys.
//!
//! Public key: [prefix][32-byte key][CRC16 LE] -> unpadded base32, 56 characters.
//! Seed: [S prefix | type high bits][type low bits][32-byte seed][CRC16 LE]
//! -> base32, 58 characters ("SU...", "SA...", "SO...").
//! CRC16: XMODEM (polynomial 0x1021, initial 0). Same format as nats-io/nkeys.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const Error = error{ InvalidEncoding, InvalidChecksum, InvalidPrefix };

/// Key type prefixes (they determine the first base32 letter).
pub const Prefix = enum(u8) {
    account = 0, // A
    cluster = 2 << 3, // C
    server = 13 << 3, // N
    operator = 14 << 3, // O
    user = 20 << 3, // U
    _,
};

const prefix_seed: u8 = 18 << 3; // S

pub const public_len = 56;
pub const seed_len = 58;
pub const signature_len = Ed25519.Signature.encoded_length;

// ---------------------------------------------------------------------------
// CRC16 and base32

fn crc16(data: []const u8) u16 {
    var crc: u16 = 0;
    for (data) |byte| {
        crc ^= @as(u16, byte) << 8;
        for (0..8) |_| {
            crc = if (crc & 0x8000 != 0) (crc << 1) ^ 0x1021 else crc << 1;
        }
    }
    return crc;
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32Len(n: usize) usize {
    return (n * 8 + 4) / 5;
}

fn base32Encode(out: []u8, data: []const u8) void {
    std.debug.assert(out.len == base32Len(data.len));
    var acc: u16 = 0;
    var bits: u4 = 0;
    var o: usize = 0;
    for (data) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[o] = alphabet[(acc >> bits) & 31];
            o += 1;
        }
    }
    if (bits > 0) {
        out[o] = alphabet[(acc << (5 - bits)) & 31];
    }
}

fn base32Decode(out: []u8, text: []const u8) Error!void {
    if (base32Len(out.len) != text.len) return error.InvalidEncoding;
    var acc: u16 = 0;
    var bits: u4 = 0;
    var o: usize = 0;
    for (text) |ch| {
        const v: u16 = switch (ch) {
            'A'...'Z' => ch - 'A',
            '2'...'7' => ch - '2' + 26,
            else => return error.InvalidEncoding,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[o] = @truncate(acc >> bits);
            o += 1;
        }
    }
    // Leftover bits must be zero (canonical encoding)
    if (acc & ((@as(u16, 1) << bits) - 1) != 0) return error.InvalidEncoding;
}

/// [body][CRC16 LE] -> base32
fn encodeWithCrc(comptime n: usize, out: *[base32Len(n + 2)]u8, body: [n]u8) void {
    var raw: [n + 2]u8 = undefined;
    raw[0..n].* = body;
    std.mem.writeInt(u16, raw[n..][0..2], crc16(&body), .little);
    base32Encode(out, &raw);
}

fn decodeWithCrc(comptime n: usize, text: []const u8) Error![n]u8 {
    var raw: [n + 2]u8 = undefined;
    try base32Decode(&raw, text);
    const crc = std.mem.readInt(u16, raw[n..][0..2], .little);
    if (crc != crc16(raw[0..n])) return error.InvalidChecksum;
    return raw[0..n].*;
}

fn isKeyPrefix(p: u8) bool {
    return switch (@as(Prefix, @enumFromInt(p))) {
        .account, .cluster, .server, .operator, .user => true,
        _ => false,
    };
}

// ---------------------------------------------------------------------------
// Public key

pub const PublicKey = struct {
    prefix: Prefix,
    key: Ed25519.PublicKey,

    pub fn decode(text: []const u8) Error!PublicKey {
        const body = try decodeWithCrc(33, text);
        if (!isKeyPrefix(body[0])) return error.InvalidPrefix;
        return .{
            .prefix = @enumFromInt(body[0]),
            .key = Ed25519.PublicKey.fromBytes(body[1..33].*) catch return error.InvalidEncoding,
        };
    }

    pub fn encode(self: PublicKey) [public_len]u8 {
        var body: [33]u8 = undefined;
        body[0] = @intFromEnum(self.prefix);
        body[1..33].* = self.key.toBytes();
        var out: [public_len]u8 = undefined;
        encodeWithCrc(33, &out, body);
        return out;
    }

    /// Verifies a signature; returns an error if it is invalid.
    pub fn verify(self: PublicKey, msg: []const u8, sig: [signature_len]u8) !void {
        try Ed25519.Signature.fromBytes(sig).verify(msg, self.key);
    }
};

// ---------------------------------------------------------------------------
// Key pair

pub const KeyPair = struct {
    prefix: Prefix,
    kp: Ed25519.KeyPair,

    /// Key pair from a raw 32-byte seed (tgnode: the hardware-derived seed).
    pub fn fromRawSeed(prefix: Prefix, seed: [32]u8) !KeyPair {
        if (!isKeyPrefix(@intFromEnum(prefix))) return error.InvalidPrefix;
        return .{ .prefix = prefix, .kp = try Ed25519.KeyPair.generateDeterministic(seed) };
    }

    /// New random key pair.
    pub fn generate(prefix: Prefix, io: std.Io) !KeyPair {
        if (!isKeyPrefix(@intFromEnum(prefix))) return error.InvalidPrefix;
        return .{ .prefix = prefix, .kp = Ed25519.KeyPair.generate(io) };
    }

    /// Key pair from an "S?..." seed string.
    pub fn decodeSeed(text: []const u8) !KeyPair {
        const body = try decodeWithCrc(34, text);
        if (body[0] & 0xF8 != prefix_seed) return error.InvalidPrefix;
        const p: u8 = ((body[0] & 7) << 5) | (body[1] >> 3);
        return fromRawSeed(@enumFromInt(p), body[2..34].*);
    }

    pub fn encodeSeed(self: KeyPair) [seed_len]u8 {
        const p = @intFromEnum(self.prefix);
        var body: [34]u8 = undefined;
        body[0] = prefix_seed | (p >> 5);
        body[1] = (p & 31) << 3;
        body[2..34].* = self.kp.secret_key.seed();
        var out: [seed_len]u8 = undefined;
        encodeWithCrc(34, &out, body);
        return out;
    }

    pub fn publicKey(self: KeyPair) PublicKey {
        return .{ .prefix = self.prefix, .key = self.kp.public_key };
    }

    /// Deterministic Ed25519 signature (same output as nats-io/nkeys).
    pub fn sign(self: KeyPair, msg: []const u8) ![signature_len]u8 {
        return (try self.kp.sign(msg, null)).toBytes();
    }
};

// ---------------------------------------------------------------------------
// Tests (vectors generated with nats-io/nkeys v0.4.15: seed = 0x00..0x1f)

const test_seed: [32]u8 = blk: {
    var s: [32]u8 = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast(i);
    break :blk s;
};
const test_sig_hex = "33bed6d376ea2350b7fc55c8675c25b4b8cdf76a12ba83cadaab82e81647812365515d9cc2ab6e311adcce563f2971b05447fde4ee519edb546e44ceb934a701";

test "same seed, public key and signature as nats-io/nkeys" {
    const cases = [_]struct { p: Prefix, seed: []const u8, public: []const u8 }{
        .{ .p = .user, .seed = "SUAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4H776Y", .public = "UAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3RLKK" },
        .{ .p = .account, .seed = "SAAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4HYMHI", .public = "AAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3QPZV" },
        .{ .p = .operator, .seed = "SOAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4H2AJA", .public = "OAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3QZVT" },
    };
    var want_sig: [signature_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want_sig, test_sig_hex);

    for (cases) |c| {
        const kp = try KeyPair.fromRawSeed(c.p, test_seed);
        try std.testing.expectEqualStrings(c.seed, &kp.encodeSeed());
        try std.testing.expectEqualStrings(c.public, &kp.publicKey().encode());

        const back = try KeyPair.decodeSeed(c.seed);
        try std.testing.expectEqual(c.p, back.prefix);
        try std.testing.expectEqualSlices(u8, &test_seed, &back.kp.secret_key.seed());

        const sig = try kp.sign("termgate");
        try std.testing.expectEqualSlices(u8, &want_sig, &sig);

        const pk = try PublicKey.decode(c.public);
        try std.testing.expectEqual(c.p, pk.prefix);
        try pk.verify("termgate", sig);
        try std.testing.expectError(error.SignatureVerificationFailed, pk.verify("termgatE", sig));
    }
}

test "malformed strings are rejected" {
    const good = "UAB2CB576PHBBPQ5ODORRZ2LYCMWPZGWGCN2KDK7DXOIMZASKUY3RLKK";
    var bad = good.*;
    bad[10] = if (bad[10] == 'A') 'B' else 'A';
    try std.testing.expectError(error.InvalidChecksum, PublicKey.decode(&bad));
    try std.testing.expectError(error.InvalidEncoding, PublicKey.decode(good[0..55]));
    try std.testing.expectError(error.InvalidEncoding, PublicKey.decode("uab2cb576phbbpq5odorrz2lycmwpzgwgcn2kdk7doimzaskuy3rlkk!"));
    // A seed string is not accepted as a public key (different length)
    try std.testing.expectError(error.InvalidEncoding, PublicKey.decode("SUAAAAICAMCAKBQHBAEQUCYMBUHA6EARCIJRIFIWC4MBSGQ3DQOR4H776Y"));
    // A public key is not accepted as a seed
    try std.testing.expectError(error.InvalidEncoding, KeyPair.decodeSeed(good));
}

test "random key: seed and public key round trip" {
    const kp = try KeyPair.generate(.user, std.testing.io);
    const seed = kp.encodeSeed();
    try std.testing.expect(std.mem.startsWith(u8, &seed, "SU"));
    const back = try KeyPair.decodeSeed(&seed);
    try std.testing.expectEqualStrings(&kp.publicKey().encode(), &back.publicKey().encode());
    const sig = try back.sign("hello");
    try (try PublicKey.decode(&kp.publicKey().encode())).verify("hello", sig);
}
