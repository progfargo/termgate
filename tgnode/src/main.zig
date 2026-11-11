//! tgnode: the gateway agent. Derives its identity from the hardware,
//! verifies grants, opens a shell on a PTY and publishes audit events.
//! Keeps no secrets on disk.
//!
//! Usage:
//!   tgnode id                 print this node's public key (from the hardware)
//!   tgnode status             print the system info sent to termgate
//!   tgnode run [config.json]  serve sessions (default /etc/tgnode/node.json)
//!   tgnode --registration <node key> [config.json]
//!                             first run: register with termgate, store the
//!                             config once the admin approves, then serve

const std = @import("std");
const core = @import("core");
const hwkey = @import("hwkey.zig");
const sysinfo = @import("sysinfo.zig");
const pty = @import("pty.zig");
const config = @import("config.zig");
const agent = @import("agent.zig");
const register = @import("register.zig");

const usage =
    \\usage: tgnode <command>
    \\
    \\commands:
    \\  id                 print this node's public key
    \\  status             print the system info sent to termgate
    \\  run [config.json]  serve sessions (default /etc/tgnode/node.json)
    \\  --registration <node key> [config.json]
    \\                     first run: register with termgate, then serve
    \\
;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var out_buf: [256]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &out_buf);
    const out = &stdout.interface;

    if (args.len == 2 and std.mem.eql(u8, args[1], "id")) {
        var root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
        defer root.close(io);
        const kp = try hwkey.keyPair(init.gpa, io, root);
        try out.print("{s}\n", .{kp.publicKey().encode()});
        try out.flush();
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "status")) {
        var root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
        defer root.close(io);
        const s = try sysinfo.collect(init.arena.allocator(), io, root, "/");
        try std.json.Stringify.value(s, .{ .whitespace = .indent_2 }, out);
        try out.writeAll("\n");
        try out.flush();
        return;
    }
    if (args.len >= 2 and args.len <= 3 and std.mem.eql(u8, args[1], "run")) {
        const path = if (args.len == 3) args[2] else config.default_path;
        const cfg = try config.load(init.gpa, io, path);
        defer cfg.deinit();
        var root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
        defer root.close(io);
        const key = try hwkey.keyPair(init.gpa, io, root);
        return agent.serveForever(init.gpa, io, cfg.value, key, root);
    }
    if (args.len >= 3 and args.len <= 4 and std.mem.eql(u8, args[1], "--registration")) {
        const path = if (args.len == 4) args[3] else config.default_path;
        var root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
        defer root.close(io);
        const key = try hwkey.keyPair(init.gpa, io, root);
        var arena: std.heap.ArenaAllocator = .init(init.gpa);
        defer arena.deinit();
        const cfg = register.register(init.gpa, arena.allocator(), io, args[2], key, root, .{}) catch |e| {
            std.debug.print("tgnode: registration failed: {s}\n", .{switch (e) {
                error.InvalidCode => "this is not a node key",
                error.WrongCa => "the relay's certificate does not match the node key",
                error.Refused => "termgate refused it (unknown, used or expired node key)",
                error.GaveUp => "not approved in time",
                else => @errorName(e),
            }});
            std.process.exit(1);
        };
        try config.save(init.gpa, io, path, cfg);
        std.debug.print("tgnode: registered as {s}; config written to {s}\n", .{ cfg.name, path });
        return agent.serveForever(init.gpa, io, cfg, key, root);
    }
    std.debug.print("{s}", .{usage});
    std.process.exit(2);
}

test {
    _ = hwkey;
    _ = sysinfo;
    _ = pty;
    _ = config;
    _ = agent;
    _ = register;
    _ = core;
}
