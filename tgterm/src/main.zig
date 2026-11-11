//! tgterm: command-line client for invited users and AI bots. Runs in the
//! user's own terminal like ssh: puts the tty in raw mode, carries input and
//! output to tgnode over NATS and sends a resize when the window changes.

const std = @import("std");
const core = @import("core");
const term = @import("term.zig");
const profile = @import("profile.zig");
const client = @import("client.zig");
const invite = @import("invite.zig");

const usage =
    \\usage:
    \\  tgterm <node>                       open a terminal on a node ("~." closes it)
    \\  tgterm --invite <invitation> [node] use an invitation, then open a terminal
    \\  tgterm whoami                       print this user's public key
    \\
;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const path = try profile.path(gpa, init.environ_map);
    defer gpa.free(path);

    if ((args.len == 3 or args.len == 4) and std.mem.eql(u8, args[1], "--invite")) {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const p = invite.redeem(gpa, arena.allocator(), io, args[2]) catch |e| fail("{s}", .{switch (e) {
            error.InvalidCode => "this is not an invitation",
            error.WrongCa => "the relay's certificate does not match the invitation",
            error.Refused => "the invitation was refused (unknown, used or expired)",
            error.TermgateOffline => "termgate is offline; try again later",
            else => @errorName(e),
        }});
        try profile.save(gpa, io, path, p);
        std.debug.print("tgterm: invitation accepted; profile stored in {s}\n", .{path});
        if (args.len == 4) std.process.exit(try client.run(gpa, io, p, args[3]));
        return;
    }

    const p = profile.load(gpa, io, path) catch |e| switch (e) {
        error.NoProfile => fail("no profile yet ({s}); use an invitation first: tgterm --invite <invitation>", .{path}),
        else => return e,
    };
    defer p.deinit();

    if (args.len == 2 and std.mem.eql(u8, args[1], "whoami")) {
        const key = try core.nkeys.KeyPair.decodeSeed(p.value.seed);
        std.debug.print("{s}\n", .{key.publicKey().encode()});
        return;
    }
    if (args.len == 2 and args[1].len > 0 and args[1][0] != '-') {
        const code = try client.run(gpa, io, p.value, args[1]);
        std.process.exit(code);
    }
    std.debug.print("{s}", .{usage});
    std.process.exit(2);
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("tgterm: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

test {
    _ = core;
    _ = term;
    _ = profile;
    _ = client;
    _ = invite;
}
