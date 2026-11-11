//! Installing termgate as a systemd service (Linux).

const std = @import("std");
const Io = std.Io;

pub const unit_path = "/etc/systemd/system/termgate.service";

pub const Options = struct {
    /// Absolute path of the termgate binary
    termgate: []const u8,
    /// The folder termgate works in (its data is ./data there)
    dir: []const u8,
    listen: []const u8,
    /// Absolute path of nats-server
    nats: []const u8,
};

/// The unit file.
pub fn unit(gpa: std.mem.Allocator, o: Options) ![]u8 {
    var cmd: std.ArrayList(u8) = .empty;
    defer cmd.deinit(gpa);
    try cmd.print(gpa, "{s} run --listen {s}", .{ o.termgate, o.listen });
    try cmd.print(gpa, " --nats {s}", .{o.nats});
    return std.fmt.allocPrint(gpa,
        \\# termgate, installed by "termgate service"
        \\[Unit]
        \\Description=termgate (authority, web panel, relay)
        \\After=network-online.target
        \\Wants=network-online.target
        \\
        \\[Service]
        \\WorkingDirectory={s}
        \\ExecStart={s}
        \\Restart=always
        \\RestartSec=5
        \\# termgate only writes its data folder
        \\NoNewPrivileges=yes
        \\ProtectSystem=strict
        \\ProtectHome=yes
        \\PrivateTmp=yes
        \\ReadWritePaths={s}/data
        \\LimitNOFILE=65536
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    , .{ o.dir, cmd.items, o.dir });
}

/// Writes the unit and enables and starts it. Needs root.
pub fn install(gpa: std.mem.Allocator, io: Io, o: Options) !void {
    const text = try unit(gpa, o);
    defer gpa.free(text);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = unit_path, .data = text });
    try systemctl(gpa, io, &.{ "systemctl", "daemon-reload" });
    try systemctl(gpa, io, &.{ "systemctl", "enable", "--now", "termgate.service" });
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

test "unit runs termgate in its folder" {
    const a = std.testing.allocator;
    const u = try unit(a, .{ .termgate = "/usr/local/bin/termgate", .dir = "/var/lib/termgate", .listen = "127.0.0.1:8080", .nats = "/usr/local/bin/nats-server" });
    defer a.free(u);
    try std.testing.expect(std.mem.indexOf(u8, u, "WorkingDirectory=/var/lib/termgate\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "ExecStart=/usr/local/bin/termgate run --listen 127.0.0.1:8080 --nats /usr/local/bin/nats-server\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, u, "ReadWritePaths=/var/lib/termgate/data\n") != null);
}
