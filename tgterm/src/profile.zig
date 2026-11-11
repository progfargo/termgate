//! tgterm's stored identity: relay, CA, termgate's issuer key and the
//! user's key. No permission is kept here: termgate decides each session
//! from its database.
//!
//! Kept in $XDG_CONFIG_HOME/tgterm/profile.json (or ~/.config/...), readable
//! by the user only. The seed is the user's private key; it never leaves this
//! machine. (Moving it into the OS key store is a later step.)

const std = @import("std");
const Io = std.Io;

pub const Profile = struct {
    relay_host: []const u8,
    relay_port: u16 = 4222,
    /// PEM of termgate's CA; empty = plain TCP (tests only)
    ca_pem: []const u8 = "",
    /// User nkey seed ("SU..."); the relay's auth callout (termgate)
    /// recognizes the key
    seed: []const u8,
    /// termgate's issuer key ("A..."): it signs the session approvals
    issuer: []const u8,
};

/// Path of the profile file. The caller owns the result.
pub fn path(gpa: std.mem.Allocator, env: *const std.process.Environ.Map) ![]u8 {
    if (env.get("XDG_CONFIG_HOME")) |x| if (x.len > 0)
        return std.fmt.allocPrint(gpa, "{s}/tgterm/profile.json", .{x});
    const home = env.get("HOME") orelse return error.NoHomeDirectory;
    return std.fmt.allocPrint(gpa, "{s}/.config/tgterm/profile.json", .{home});
}

pub fn load(gpa: std.mem.Allocator, io: Io, file_path: []const u8) !std.json.Parsed(Profile) {
    const data = Io.Dir.cwd().readFileAlloc(io, file_path, gpa, .limited(1024 * 1024)) catch |e| switch (e) {
        error.FileNotFound => return error.NoProfile,
        else => return e,
    };
    defer gpa.free(data);
    return std.json.parseFromSlice(Profile, gpa, data, .{ .ignore_unknown_fields = true, .allocate = .alloc_always }) catch |e|
        if (e == error.OutOfMemory) error.OutOfMemory else error.InvalidProfile;
}

/// Writes the profile, creating the directory; the file is mode 0600.
pub fn save(gpa: std.mem.Allocator, io: Io, file_path: []const u8, p: Profile) !void {
    const json = try std.json.Stringify.valueAlloc(gpa, p, .{ .whitespace = .indent_2 });
    defer gpa.free(json);
    if (std.fs.path.dirname(file_path)) |d| try Io.Dir.cwd().createDirPath(io, d);
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = file_path,
        .data = json,
        .flags = .{ .permissions = .fromMode(0o600) },
    });
}

test "save and load a profile" {
    const io = std.testing.io;
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &dir_buf);
    const file = try std.fmt.allocPrint(a, "{s}/sub/profile.json", .{dir_buf[0..n]});
    defer a.free(file);

    try save(a, io, file, .{ .relay_host = "relay.example.com", .seed = "SUABC", .issuer = "AISSUER" });
    const p = try load(a, io, file);
    defer p.deinit();
    try std.testing.expectEqualStrings("relay.example.com", p.value.relay_host);
    try std.testing.expectEqual(@as(u16, 4222), p.value.relay_port);
    try std.testing.expectEqualStrings("SUABC", p.value.seed);

    const st = try Io.Dir.cwd().statFile(io, file, .{});
    try std.testing.expectEqual(@as(u32, 0o600), st.permissions.toMode() & 0o777);
}
