//! tgnode: the gateway agent. Derives its identity from the hardware,
//! asks termgate to approve each session, opens a shell on a PTY and
//! publishes audit events.
//! Keeps no secrets on disk.
//!
//! Usage:
//!   tgnode id                 print this node's public key (from the hardware)
//!   tgnode status             print the system info sent to termgate
//!   tgnode run                serve sessions
//!   tgnode service            install and start the systemd service that
//!                             runs "tgnode run" in this folder (root)
//!   tgnode --node-key <node key>
//!                             first run: register with termgate, store the
//!                             config once the admin approves, then serve
//!
//! The config is node.json in the folder tgnode is started in.

const std = @import("std");
const core = @import("core");
const hwkey = @import("hwkey.zig");
const sysinfo = @import("sysinfo.zig");
const pty = @import("pty.zig");
const config = @import("config.zig");
const agent = @import("agent.zig");
const register = @import("register.zig");
const systemd = @import("systemd.zig");

const usage =
    \\usage: tgnode <command>
    \\
    \\commands:
    \\  id                 print this node's public key
    \\  status             print the system info sent to termgate
    \\  run                serve sessions
    \\  service            install and start the systemd service (root):
    \\                     "tgnode run" in this folder, at boot and after a stop
    \\  --node-key <node key>
    \\                     first run: register with termgate, then serve
    \\
    \\The config is node.json in the folder tgnode is started in.
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
    if (args.len == 2 and std.mem.eql(u8, args[1], "service")) {
        // Only a registered node: its node.json in this folder
        _ = std.Io.Dir.cwd().statFile(io, config.file_name, .{}) catch {
            std.debug.print("tgnode: no {s} here; register first: tgnode --node-key <node key>\n", .{config.file_name});
            std.process.exit(1);
        };
        var self_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const self_n = std.process.executablePath(io, &self_buf) catch 0;
        var dir_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const dir_n = std.process.currentPath(io, &dir_buf) catch 0;
        if (self_n == 0 or dir_n == 0) {
            std.debug.print("tgnode: cannot find its own path or this folder\n", .{});
            std.process.exit(1);
        }
        systemd.install(init.gpa, io, .{ .tgnode = self_buf[0..self_n], .dir = dir_buf[0..dir_n] }) catch |e| {
            std.debug.print("tgnode: {s}\n", .{switch (e) {
                error.AccessDenied => "permission denied: run as root",
                else => @errorName(e),
            }});
            std.process.exit(1);
        };
        std.debug.print("tgnode: service installed and started ({s}); see: systemctl status tgnode\n", .{systemd.unit_path});
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "run")) {
        const path = config.file_name;
        const cfg = try config.load(init.gpa, io, path);
        defer cfg.deinit();
        var root = try std.Io.Dir.openDirAbsolute(io, "/", .{});
        defer root.close(io);
        const key = try hwkey.keyPair(init.gpa, io, root);
        return agent.serveForever(init.gpa, io, cfg.value, key, root);
    }
    if (args.len == 3 and std.mem.eql(u8, args[1], "--node-key")) {
        const path = config.file_name;
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
    _ = systemd;
    _ = core;
}
