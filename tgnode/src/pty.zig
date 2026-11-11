//! Shells on a pseudo terminal (Linux).
//!
//! spawn() opens a PTY, forks, and in the child makes the PTY the controlling
//! terminal of a new session, switches to the run_as user and executes the
//! user's login shell (or the given argv). tgnode is multi-threaded, so the
//! child may only make async-signal-safe calls between fork and exec:
//! everything that allocates or reads files (user lookup, group list,
//! environment, argv) is prepared before fork.

const std = @import("std");
const c = @import("c");

pub const Error = error{ PtyFailed, ForkFailed, UnknownUser };

pub const Size = struct { cols: u16, rows: u16 };

pub const Shell = struct {
    /// Master side of the PTY: read output from it, write input to it
    master: c_int,
    pid: c.pid_t,

    pub fn resize(s: Shell, size: Size) void {
        var ws: c.struct_winsize = .{ .ws_row = size.rows, .ws_col = size.cols };
        _ = c.ioctl(s.master, c.TIOCSWINSZ, &ws);
    }

    /// Sends SIGHUP to the shell's process group (the session ends the way it
    /// does when a terminal closes; the shell passes it on to its jobs).
    pub fn hangup(s: Shell) void {
        _ = c.killpg(s.pid, c.SIGHUP);
    }

    /// Waits for the shell to exit and closes the master. Returns the raw
    /// wait status.
    pub fn wait(s: Shell) c_int {
        var status: c_int = 0;
        while (c.waitpid(s.pid, &status, 0) < 0) {
            if (std.c._errno().* != @intFromEnum(std.c.E.INTR)) break;
        }
        _ = c.close(s.master);
        return status;
    }

    /// Reads output; returns 0 at the end of the session. Linux reports EIO on
    /// the master once the last slave descriptor is closed: that is the end.
    pub fn read(s: Shell, buf: []u8) !usize {
        while (true) {
            const n = c.read(s.master, buf.ptr, buf.len);
            if (n >= 0) return @intCast(n);
            const e = std.c._errno().*;
            if (e == @intFromEnum(std.c.E.INTR)) continue;
            if (e == @intFromEnum(std.c.E.IO)) return 0;
            return error.ReadFailed;
        }
    }

    pub fn write(s: Shell, data: []const u8) !void {
        var rest = data;
        while (rest.len > 0) {
            const n = c.write(s.master, rest.ptr, rest.len);
            if (n < 0) {
                if (std.c._errno().* == @intFromEnum(std.c.E.INTR)) continue;
                return error.WriteFailed;
            }
            rest = rest[@intCast(n)..];
        }
    }
};

pub const Options = struct {
    /// Unix user the shell runs as. If it is the user tgnode runs as, no
    /// identity change is made (tests); otherwise tgnode must be root.
    run_as: []const u8,
    size: Size = .{ .cols = 80, .rows = 24 },
    /// Program and arguments; null = the user's login shell
    argv: ?[]const []const u8 = null,
    term: []const u8 = "xterm-256color",
};

pub fn spawn(gpa: std.mem.Allocator, opts: Options) !Shell {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // --- Everything the child needs, prepared before fork ---
    const user = try lookupUser(arena, opts.run_as);
    const change_identity = user.uid != c.getuid();
    var groups: [256]c.gid_t = undefined;
    var ngroups: c_int = groups.len;
    if (change_identity) {
        if (c.getgrouplist(user.name.ptr, user.gid, &groups, &ngroups) < 0) ngroups = 1;
    }

    const shell_path: [:0]const u8 = if (user.shell.len > 0) user.shell else "/bin/sh";
    // Login shell: argv[0] starts with "-"
    var argv: std.ArrayList(?[*:0]const u8) = .empty;
    if (opts.argv) |a| {
        for (a) |arg| try argv.append(arena, (try arena.dupeSentinel(u8, arg, 0)).ptr);
    } else {
        const base = std.fs.path.basename(shell_path);
        try argv.append(arena, (try std.fmt.allocPrintSentinel(arena, "-{s}", .{base}, 0)).ptr);
    }
    try argv.append(arena, null);
    const exe: [*:0]const u8 = if (opts.argv) |a| (try arena.dupeSentinel(u8, a[0], 0)).ptr else shell_path.ptr;

    const envp = [_]?[*:0]const u8{
        (try std.fmt.allocPrintSentinel(arena, "HOME={s}", .{user.home}, 0)).ptr,
        (try std.fmt.allocPrintSentinel(arena, "USER={s}", .{user.name}, 0)).ptr,
        (try std.fmt.allocPrintSentinel(arena, "LOGNAME={s}", .{user.name}, 0)).ptr,
        (try std.fmt.allocPrintSentinel(arena, "SHELL={s}", .{shell_path}, 0)).ptr,
        (try std.fmt.allocPrintSentinel(arena, "TERM={s}", .{opts.term}, 0)).ptr,
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        null,
    };

    // --- PTY ---
    const master = c.posix_openpt(c.O_RDWR | c.O_NOCTTY | c.O_CLOEXEC);
    if (master < 0) return error.PtyFailed;
    errdefer _ = c.close(master);
    if (c.grantpt(master) != 0 or c.unlockpt(master) != 0) return error.PtyFailed;
    var name_buf: [128]u8 = undefined;
    if (c.ptsname_r(master, &name_buf, name_buf.len) != 0) return error.PtyFailed;
    var ws: c.struct_winsize = .{ .ws_row = opts.size.rows, .ws_col = opts.size.cols };
    _ = c.ioctl(master, c.TIOCSWINSZ, &ws);

    const pid = c.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) {
        // Child: async-signal-safe calls only.
        _ = c.setsid();
        const slave = c.open(@ptrCast(&name_buf), c.O_RDWR);
        if (slave < 0) c._exit(126);
        _ = c.ioctl(slave, c.TIOCSCTTY, @as(c_int, 0));
        _ = c.dup2(slave, 0);
        _ = c.dup2(slave, 1);
        _ = c.dup2(slave, 2);
        if (slave > 2) _ = c.close(slave);
        if (change_identity) {
            if (c.setgroups(@intCast(ngroups), &groups) != 0) c._exit(126);
            if (c.setgid(user.gid) != 0) c._exit(126);
            if (c.setuid(user.uid) != 0) c._exit(126);
        }
        if (c.chdir(user.home.ptr) != 0) _ = c.chdir("/");
        _ = c.execve(exe, @ptrCast(argv.items.ptr), @ptrCast(&envp));
        c._exit(127);
    }
    return .{ .master = master, .pid = pid };
}

const User = struct {
    name: [:0]const u8,
    uid: c.uid_t,
    gid: c.gid_t,
    home: [:0]const u8,
    shell: [:0]const u8,
};

fn lookupUser(arena: std.mem.Allocator, name: []const u8) !User {
    const name_z = try arena.dupeSentinel(u8, name, 0);
    var pw: c.struct_passwd = undefined;
    var result: ?*c.struct_passwd = null;
    const buf = try arena.alloc(u8, 16 * 1024);
    if (c.getpwnam_r(name_z.ptr, &pw, buf.ptr, buf.len, @ptrCast(&result)) != 0 or result == null)
        return error.UnknownUser;
    return .{
        .name = name_z,
        .uid = pw.pw_uid,
        .gid = pw.pw_gid,
        .home = try arena.dupeSentinel(u8, std.mem.span(pw.pw_dir), 0),
        .shell = try arena.dupeSentinel(u8, std.mem.span(pw.pw_shell), 0),
    };
}

// ---------------------------------------------------------------------------
// Tests (run as the current user, so no identity change happens)

const testing = std.testing;

fn currentUser(buf: []u8) ![]const u8 {
    var pw: c.struct_passwd = undefined;
    var result: ?*c.struct_passwd = null;
    var tmp: [4096]u8 = undefined;
    if (c.getpwuid_r(c.getuid(), &pw, &tmp, tmp.len, @ptrCast(&result)) != 0 or result == null)
        return error.SkipZigTest;
    const n = std.mem.span(pw.pw_name);
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

fn readAll(s: Shell, out: *std.ArrayList(u8)) !void {
    var buf: [1024]u8 = undefined;
    while (true) {
        const n = try s.read(&buf);
        if (n == 0) return;
        try out.appendSlice(testing.allocator, buf[0..n]);
    }
}

test "command runs on a terminal with the given size" {
    var name_buf: [64]u8 = undefined;
    const me = try currentUser(&name_buf);
    const s = try spawn(testing.allocator, .{
        .run_as = me,
        .size = .{ .cols = 100, .rows = 30 },
        .argv = &.{ "/bin/sh", "-c", "echo hello; stty size; test -t 0 && echo tty; echo $TERM" },
    });
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try readAll(s, &out);
    const status = s.wait();
    try testing.expect(c.WIFEXITED(status) and c.WEXITSTATUS(status) == 0);
    try testing.expect(std.mem.indexOf(u8, out.items, "hello") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "30 100") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "tty") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "xterm-256color") != null);
}

test "input, resize and hangup" {
    var name_buf: [64]u8 = undefined;
    const me = try currentUser(&name_buf);
    const s = try spawn(testing.allocator, .{
        .run_as = me,
        .argv = &.{ "/bin/sh", "-c", "read line; echo got:$line; stty size; sleep 30" },
    });
    try s.write("ping\n");
    var buf: [256]u8 = undefined;
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(testing.allocator);
    while (std.mem.indexOf(u8, seen.items, "24 80") == null) {
        const n = try s.read(&buf);
        if (n == 0) break;
        try seen.appendSlice(testing.allocator, buf[0..n]);
    }
    try testing.expect(std.mem.indexOf(u8, seen.items, "got:ping") != null);
    s.resize(.{ .cols = 132, .rows = 40 });
    s.hangup();
    try readAll(s, &seen);
    const status = s.wait();
    // Ended by the signal, not by finishing the 30 s sleep
    try testing.expect(c.WIFSIGNALED(status));
}

test "unknown user" {
    try testing.expectError(error.UnknownUser, spawn(testing.allocator, .{ .run_as = "no_such_user_tg" }));
}
