//! Node names.
//!
//! The admin names each node freely; names are unique within a customer
//! (termgate enforces that when it enrolls a node). A name is an identifier
//! whose parts are separated by "_", like the labels of a subdomain:
//! "ist_kadikoy_gw01", "pump07".
//!
//! Rules: 1 to 63 characters; lowercase letters, digits and "_"; starts with a
//! letter; no "_" at the end and no "__". Lowercase only, so that "GW1" and
//! "gw1" cannot be two different nodes. A name is always a single NATS subject
//! token.

const std = @import("std");

pub const max_len = 63;

pub fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_len) return false;
    if (!std.ascii.isLower(name[0])) return false;
    if (name[name.len - 1] == '_') return false;
    var prev: u8 = 0;
    for (name) |c| {
        const ok = std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '_';
        if (!ok) return false;
        if (c == '_' and prev == '_') return false;
        prev = c;
    }
    return true;
}

/// A node name pattern in a grant: the name characters plus the wildcards
/// "*" (any run) and "?" (one character).
pub fn isValidPattern(pattern: []const u8) bool {
    if (pattern.len == 0 or pattern.len > max_len) return false;
    for (pattern) |c| {
        const ok = std.ascii.isLower(c) or std.ascii.isDigit(c) or c == '_' or c == '*' or c == '?';
        if (!ok) return false;
    }
    return true;
}

test "valid and invalid names" {
    const testing = std.testing;
    for ([_][]const u8{ "gw17", "ist_kadikoy_gw01", "pump07", "a", "a1_b2" }) |n|
        try testing.expect(isValidName(n));
    for ([_][]const u8{ "", "17gw", "_gw", "gw_", "gw__17", "GW17", "gw-17", "gw.17", "gw 17", "gw*", "ş" }) |n|
        try testing.expect(!isValidName(n));
    const long: [max_len + 1]u8 = @splat('a');
    try testing.expect(isValidName(long[0..max_len]));
    try testing.expect(!isValidName(&long));
}

test "valid and invalid patterns" {
    const testing = std.testing;
    for ([_][]const u8{ "*", "ist_*", "pump??", "gw17", "*_gw" }) |p|
        try testing.expect(isValidPattern(p));
    for ([_][]const u8{ "", "ist-*", "IST_*", "ist.*", "ist *", "ist>" }) |p|
        try testing.expect(!isValidPattern(p));
}
