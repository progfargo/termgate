//! End-to-end encryption of session data: the relay carries only ciphertext.
//!
//! Key agreement (X25519, one key pair per session on each side):
//!   - tgterm puts its public key in the signed session request (session.zig),
//!     so the relay cannot replace it;
//!   - tgnode answers with its own public key inside termgate's signed
//!     approval (approval.zig), which tgterm verifies;
//!   - both derive the same session keys: `up` for in.<...>.data (user to
//!     node), `down` for out.<...>.data (node to user).
//! termgate, which logs and watches sessions, gets the session keys from the
//! node sealed to termgate's issuer key (converted to X25519), so no new key
//! has to be handed out.
//!
//! A data message is: sender (4 bytes) | counter (8 bytes) | ciphertext | tag
//! (ChaCha20-Poly1305; the nonce is sender and counter). Several senders may
//! use one key without reusing a nonce (termgate writes to the user's screen
//! with `down` too), and a receiver refuses a counter it has seen (replays).
//! Window sizes and the end of a session are not encrypted: they carry no
//! content.

const std = @import("std");
const nkeys = @import("nkeys.zig");
const X25519 = std.crypto.dh.X25519;
const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const XAead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const b64 = std.base64.url_safe_no_pad;

pub const key_len = 32;
pub const PublicKey = [X25519.public_length]u8;
/// base64url of a public key
pub const public_text_len = b64.Encoder.calcSize(X25519.public_length);
pub const overhead = 12 + Aead.tag_length;

pub const Keys = struct {
    /// User to node (in.<node>.<user>.<sid>.data)
    up: [key_len]u8,
    /// Node to user (out.<node>.<user>.<sid>.data)
    down: [key_len]u8,
};

pub const Sender = enum(u32) { user = 1, node = 2, termgate = 3 };

/// One side's key pair for one session.
pub const Ephemeral = struct {
    kp: X25519.KeyPair,

    pub fn generate(io: std.Io) Ephemeral {
        return .{ .kp = X25519.KeyPair.generate(io) };
    }

    pub fn publicText(e: Ephemeral) [public_text_len]u8 {
        var out: [public_text_len]u8 = undefined;
        _ = b64.Encoder.encode(&out, &e.kp.public_key);
        return out;
    }

    /// The session keys, from this side's key pair and the other side's
    /// public key. `user_pub` and `node_pub` as sent (base64url).
    pub fn keys(e: Ephemeral, other: PublicKey, sid: []const u8, user_pub: []const u8, node_pub: []const u8) !Keys {
        const shared = try X25519.scalarmult(e.kp.secret_key, other);
        return derive(shared, sid, user_pub, node_pub);
    }
};

pub fn decodePublic(text: []const u8) !PublicKey {
    if (text.len != public_text_len) return error.InvalidKey;
    var k: PublicKey = undefined;
    b64.Decoder.decode(&k, text) catch return error.InvalidKey;
    return k;
}

fn derive(shared: [32]u8, sid: []const u8, user_pub: []const u8, node_pub: []const u8) Keys {
    const prk = Hkdf.extract("termgate-e2e-v1", &shared);
    var info_buf: [256]u8 = undefined;
    const info = std.fmt.bufPrint(&info_buf, "{s}\x00{s}\x00{s}", .{ sid, user_pub, node_pub }) catch unreachable;
    var out: [2 * key_len]u8 = undefined;
    Hkdf.expand(&out, info, prk);
    return .{ .up = out[0..key_len].*, .down = out[key_len..].* };
}

/// Encrypts one direction's messages as one sender.
pub const Sealer = struct {
    key: [key_len]u8,
    sender: Sender,
    counter: u64 = 0,

    /// The message for `plain`; caller owns it.
    pub fn seal(s: *Sealer, gpa: std.mem.Allocator, plain: []const u8) ![]u8 {
        s.counter += 1;
        const out = try gpa.alloc(u8, overhead + plain.len);
        const nonce = out[0..12];
        std.mem.writeInt(u32, nonce[0..4], @intFromEnum(s.sender), .big);
        std.mem.writeInt(u64, nonce[4..12], s.counter, .big);
        Aead.encrypt(out[12..][0..plain.len], out[12 + plain.len ..][0..Aead.tag_length], plain, "termgate-e2e-v1", nonce.*, s.key);
        return out;
    }
};

/// Decrypts one direction's messages; refuses a sender's counter that is not
/// newer than the last one (replay or reordering).
pub const Opener = struct {
    key: [key_len]u8,
    last: [4]u64 = @splat(0),

    pub fn open(o: *Opener, gpa: std.mem.Allocator, msg: []const u8) ![]u8 {
        if (msg.len < overhead) return error.InvalidMessage;
        const nonce = msg[0..12];
        const sender = std.mem.readInt(u32, nonce[0..4], .big);
        const counter = std.mem.readInt(u64, nonce[4..12], .big);
        if (sender == 0 or sender >= o.last.len) return error.InvalidMessage;
        if (counter <= o.last[sender]) return error.Replay;
        const n = msg.len - overhead;
        const out = try gpa.alloc(u8, n);
        errdefer gpa.free(out);
        Aead.decrypt(out, msg[12..][0..n], msg[12 + n ..][0..Aead.tag_length].*, "termgate-e2e-v1", nonce.*, o.key) catch return error.InvalidMessage;
        o.last[sender] = counter;
        return out;
    }
};

/// The session keys sealed to termgate (node side), base64url. Bound to the
/// session id and both public keys.
pub fn sealForTermgate(gpa: std.mem.Allocator, io: std.Io, issuer: nkeys.PublicKey, keys: Keys, sid: []const u8, user_pub: []const u8, node_pub: []const u8) ![]u8 {
    const tg = try X25519.publicKeyFromEd25519(issuer.key);
    const eph = X25519.KeyPair.generate(io);
    const shared = try X25519.scalarmult(eph.secret_key, tg);
    const k = boxKey(shared, eph.public_key);
    var raw: [32 + XAead.nonce_length + 2 * key_len + XAead.tag_length]u8 = undefined;
    raw[0..32].* = eph.public_key;
    const nonce = raw[32..][0..XAead.nonce_length];
    io.random(nonce);
    var plain: [2 * key_len]u8 = undefined;
    plain[0..key_len].* = keys.up;
    plain[key_len..].* = keys.down;
    defer std.crypto.secureZero(u8, &plain);
    var ad_buf: [256]u8 = undefined;
    const ad = boxAd(&ad_buf, sid, user_pub, node_pub);
    XAead.encrypt(raw[32 + XAead.nonce_length ..][0 .. 2 * key_len], raw[raw.len - XAead.tag_length ..], &plain, ad, nonce.*, k);
    const out = try gpa.alloc(u8, b64.Encoder.calcSize(raw.len));
    _ = b64.Encoder.encode(out, &raw);
    return out;
}

/// Opens what sealForTermgate made (termgate side, with its issuer key).
pub fn openForTermgate(issuer: nkeys.KeyPair, text: []const u8, sid: []const u8, user_pub: []const u8, node_pub: []const u8) !Keys {
    var raw: [32 + XAead.nonce_length + 2 * key_len + XAead.tag_length]u8 = undefined;
    if (text.len != b64.Encoder.calcSize(raw.len)) return error.InvalidMessage;
    b64.Decoder.decode(&raw, text) catch return error.InvalidMessage;
    const me = try X25519.KeyPair.fromEd25519(issuer.kp);
    const shared = try X25519.scalarmult(me.secret_key, raw[0..32].*);
    const k = boxKey(shared, raw[0..32].*);
    var plain: [2 * key_len]u8 = undefined;
    var ad_buf: [256]u8 = undefined;
    const ad = boxAd(&ad_buf, sid, user_pub, node_pub);
    XAead.decrypt(&plain, raw[32 + XAead.nonce_length ..][0 .. 2 * key_len], raw[raw.len - XAead.tag_length ..][0..XAead.tag_length].*, ad, raw[32..][0..XAead.nonce_length].*, k) catch return error.InvalidMessage;
    return .{ .up = plain[0..key_len].*, .down = plain[key_len..].* };
}

fn boxKey(shared: [32]u8, eph_pub: [32]u8) [32]u8 {
    const prk = Hkdf.extract("termgate-e2e-box-v1", &shared);
    var k: [32]u8 = undefined;
    Hkdf.expand(&k, &eph_pub, prk);
    return k;
}

fn boxAd(buf: []u8, sid: []const u8, user_pub: []const u8, node_pub: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}\x00{s}\x00{s}", .{ sid, user_pub, node_pub }) catch buf[0..0];
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

test "both sides derive the same keys; traffic decrypts once" {
    const a = testing.allocator;
    const io = testing.io;
    const user = Ephemeral.generate(io);
    const node = Ephemeral.generate(io);
    const up_text = user.publicText();
    const np_text = node.publicText();
    const ku = try user.keys(try decodePublic(&np_text), "S1", &up_text, &np_text);
    const kn = try node.keys(try decodePublic(&up_text), "S1", &up_text, &np_text);
    try testing.expectEqualSlices(u8, &ku.up, &kn.up);
    try testing.expectEqualSlices(u8, &ku.down, &kn.down);
    try testing.expect(!std.mem.eql(u8, &ku.up, &ku.down));
    // Another session id gives other keys
    const other = try user.keys(try decodePublic(&np_text), "S2", &up_text, &np_text);
    try testing.expect(!std.mem.eql(u8, &ku.up, &other.up));

    var tx: Sealer = .{ .key = ku.up, .sender = .user };
    var rx: Opener = .{ .key = kn.up };
    const m1 = try tx.seal(a, "ls -la\r");
    defer a.free(m1);
    try testing.expect(std.mem.indexOf(u8, m1, "ls -la") == null);
    const p1 = try rx.open(a, m1);
    defer a.free(p1);
    try testing.expectEqualStrings("ls -la\r", p1);
    // Replayed, changed or under the wrong key: refused
    try testing.expectError(error.Replay, rx.open(a, m1));
    const m2 = try tx.seal(a, "x");
    defer a.free(m2);
    m2[m2.len - 1] ^= 1;
    try testing.expectError(error.InvalidMessage, rx.open(a, m2));
    var wrong: Opener = .{ .key = kn.down };
    const m3 = try tx.seal(a, "y");
    defer a.free(m3);
    try testing.expectError(error.InvalidMessage, wrong.open(a, m3));

    // Two senders on one key: termgate writes to the user's screen too
    var node_tx: Sealer = .{ .key = kn.down, .sender = .node };
    var tg_tx: Sealer = .{ .key = kn.down, .sender = .termgate };
    var user_rx: Opener = .{ .key = ku.down };
    const n1 = try node_tx.seal(a, "out");
    defer a.free(n1);
    const t1 = try tg_tx.seal(a, "[termgate]");
    defer a.free(t1);
    const r1 = try user_rx.open(a, n1);
    defer a.free(r1);
    const r2 = try user_rx.open(a, t1);
    defer a.free(r2);
    try testing.expectEqualStrings("[termgate]", r2);
}

test "the session keys reach termgate, bound to the session" {
    const a = testing.allocator;
    const io = testing.io;
    const issuer = try nkeys.KeyPair.fromRawSeed(.account, @splat(0x1f));
    const keys: Keys = .{ .up = @splat(1), .down = @splat(2) };
    const box = try sealForTermgate(a, io, issuer.publicKey(), keys, "S1", "UPUB", "NPUB");
    defer a.free(box);
    const got = try openForTermgate(issuer, box, "S1", "UPUB", "NPUB");
    try testing.expectEqualSlices(u8, &keys.down, &got.down);
    try testing.expectError(error.InvalidMessage, openForTermgate(issuer, box, "S2", "UPUB", "NPUB"));
    try testing.expectError(error.InvalidMessage, openForTermgate(issuer, box, "S1", "UPUB", "OTHER"));
    const other = try nkeys.KeyPair.fromRawSeed(.account, @splat(0x20));
    try testing.expectError(error.InvalidMessage, openForTermgate(other, box, "S1", "UPUB", "NPUB"));
}
