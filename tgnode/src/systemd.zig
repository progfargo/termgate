//! Installing tgnode as a systemd service (Linux), as termgate's
//! `termgate service`: tgnode runs in the folder it was registered in (its
//! node.json is there), starts when the device starts and is started again
//! if it stops.

const std = @import("std");
const Io = std.Io;

pub const unit_path = "/etc/systemd/system/tgnode.service";

pub const Options = struct {
    /// Absolute path of the tgnode binary
    tgnode: []const u8,
    /// The folder tgnode works in (node.json is there)
    dir: []const u8,
    /// The user it runs as; null: root. A session can do what this user can.
    user: ?[]const u8 = null,
};

/// The unit file. No sandboxing: a session is a shell on the device, with
/// what the user tgnode runs as (root unless `user` is given) may do.
pub fn unit(gpa: std.mem.Allocator, o: Options) ![]u8 {
    const user_line = if (o.user) |u| try std.fmt.allocPrint(gpa, "User={s}\n", .{u}) else try gpa.dupe(u8, "");
    defer gpa.free(user_line);
    return std.fmt.allocPrint(gpa,
        \\# tgnode, installed by "tgnode service"
        \\[Unit]
        \\Description=tgnode (termgate gateway agent)
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\WorkingDirectory={s}
        \\{s}ExecStart={s} run
        \\Restart=always
        \\RestartSec=5
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    , .{ o.dir, user_line, o.tgnode });
}

/// Writes the unit and enables and starts it. Needs root.
pub fn install(gpa: std.mem.Allocator, io: Io, o: Options) !void {
    const text = try unit(gpa, o);
    defer gpa.free(text);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = unit_path, .data = text });
    try systemctl(gpa, io, &.{ "systemctl", "daemon-reload" });
    try systemctl(gpa, io, &.{ "systemctl", "enable", "--now", "tgnode.service" });
}

fn systemctl(gpa: std.mem.Allocator, io: Io, argv: []const []const u8) !void {
    const r = try std.process.run(gpa, io, .{ .argv = argv });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    if (!r.term.success()) {
        std.debug.print("{s}", .{r.stderr});
        return error.SystemctlFailed;
    }
}

test "unit runs tgnode in its folder" {
    const a = std.testing.allocator;
    const u = try unit(a, .{ .tgnode = "/opt/tgnode/tgnode", .dir = "/opt/tgnode" });
    defer a.free(u);
    try std.testing.expect(std.mem.indexOf(u8, u, "WorkingDirectory=/opt/tgnode\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "ExecStart=/opt/tgnode/tgnode run\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "Restart=always\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "User=") == null);
    const with_user = try unit(a, .{ .tgnode = "/opt/tgnode/tgnode", .dir = "/opt/tgnode", .user = "operator" });
    defer a.free(with_user);
    try std.testing.expect(std.mem.indexOf(u8, with_user, "User=operator\nExecStart=") != null);
}
