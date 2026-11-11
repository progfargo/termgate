//! tgnode's configuration file: node.json (JSON) in the folder tgnode is
//! started in, as termgate keeps its data in the folder it is started in.
//!
//! Written by tgnode when its registration is approved. Holds only public
//! material: the node's name, the relay address, termgate's CA and termgate's
//! issuer key. The node's private key is never stored; it is derived from the
//! hardware, and the relay's auth callout (termgate) recognizes it.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const node_name = core.node;

pub const file_name = "node.json";

pub const Config = struct {
    /// Node name given by the admin (see core.node)
    name: []const u8,
    relay_host: []const u8,
    relay_port: u16 = 4222,
    /// PEM of termgate's CA; empty = plain TCP (tests only)
    ca_pem: []const u8 = "",
    /// termgate's issuer key ("A..."): grants and approvals must be signed by it
    issuer: []const u8,
};

pub fn load(gpa: std.mem.Allocator, io: Io, path: []const u8) !std.json.Parsed(Config) {
    const data = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(1024 * 1024));
    defer gpa.free(data);
    return parse(gpa, data);
}

pub fn parse(gpa: std.mem.Allocator, data: []const u8) !std.json.Parsed(Config) {
    const p = std.json.parseFromSlice(Config, gpa, data, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e|
        return if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidConfig;
    errdefer p.deinit();
    if (!node_name.isValidName(p.value.name)) return error.InvalidNodeName;
    const k = core.nkeys.PublicKey.decode(p.value.issuer) catch return error.InvalidConfig;
    if (k.prefix != .account) return error.InvalidConfig;
    return p;
}

const test_issuer = "ABBQI276ICJLH2KJSTVNUFO4YIGYVKQHWZMP2OKU5OHA564L3SS55F6K";

test "parse a config" {
    const p = try parse(std.testing.allocator, "{\"name\":\"ist_kadikoy_gw01\",\"relay_host\":\"relay.example.com\",\"issuer\":\"" ++ test_issuer ++ "\"}");
    defer p.deinit();
    try std.testing.expectEqualStrings("ist_kadikoy_gw01", p.value.name);
    try std.testing.expectEqual(@as(u16, 4222), p.value.relay_port);
}

test "invalid configs" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidNodeName, parse(a, "{\"name\":\"GW-1\",\"relay_host\":\"r\",\"issuer\":\"" ++ test_issuer ++ "\"}"));
    try std.testing.expectError(error.InvalidConfig, parse(a, "{\"name\":\"gw1\",\"relay_host\":\"r\",\"issuer\":\"UBAD\"}"));
    try std.testing.expectError(error.InvalidConfig, parse(a, "{"));
}

/// Writes the config (after registration). The caller chooses the path.
pub fn save(gpa: std.mem.Allocator, io: Io, path: []const u8, cfg: Config) !void {
    const json = try std.json.Stringify.valueAlloc(gpa, cfg, .{ .whitespace = .indent_2 });
    defer gpa.free(json);
    if (std.fs.path.dirname(path)) |d| try Io.Dir.cwd().createDirPath(io, d);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = json });
}
