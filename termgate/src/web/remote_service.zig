//! The panel's stand-in for termgate's relay service (service.zig): the
//! actions the screens trigger, each a call to the server, and watching a
//! session. The session is decrypted on the server; the panel fetches its
//! output (watch.read) and draws it in its own terminal.

const std = @import("std");
const Io = std.Io;
const rpc = @import("rpc");
const vt = @import("vt");

pub const Service = struct {
    gpa: std.mem.Allocator,
    io: Io,

    fn action(name: []const u8, args: anytype) bool {
        var buf: [1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const E = error{ Failed, NotConnected };
        rpc.result(void, E, error.Failed, fba.allocator(), name, args) catch return false;
        return true;
    }

    pub fn endSession(_: *Service, node: []const u8, user_key: []const u8, sid: []const u8) !void {
        if (!action("svc.endSession", .{ node, user_key, sid })) return error.NotConnected;
    }
    pub fn kickNode(_: *Service, name: []const u8) void {
        _ = action("svc.kickNode", .{name});
    }
    pub fn kickUser(_: *Service, key: []const u8) void {
        _ = action("svc.kickUser", .{key});
    }
    pub fn requestStatus(_: *Service) void {
        _ = action("svc.requestStatus", .{});
    }
    pub fn requestStatusOf(_: *Service, node: []const u8) void {
        _ = action("svc.requestStatusOf", .{node});
    }

    pub fn watch(s: *Service, node: []const u8, user_key: []const u8, sid: []const u8) !*Watch {
        var buf: [1024]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const E = error{ Failed, NotConnected };
        const id = try rpc.result(u64, E, error.Failed, fba.allocator(), "watch.start", .{ node, user_key, sid });
        const w = try s.gpa.create(Watch);
        errdefer s.gpa.destroy(w);
        w.* = .{ .gpa = s.gpa, .io = s.io, .id = id, .screen = try vt.Screen.create(s.gpa, s.io, 80, 24) };
        return w;
    }
};

pub const Watch = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// The server's tap
    id: u64,
    /// How much of the tap's stream has been fetched
    offset: u64 = 0,
    screen: *vt.Screen,
    lock: Io.Mutex = .init,
    /// 32 bits: the browser's WASM has no 64-bit atomics
    version: std.atomic.Value(u32) = .init(0),
    state: std.atomic.Value(State) = .init(.connecting),

    pub const State = enum(u8) { connecting, live, ended, failed, unreadable };

    pub fn stop(w: *Watch) void {
        var buf: [256]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        rpc.result(void, error{Failed}, error.Failed, fba.allocator(), "watch.stop", .{w.id}) catch {};
        w.screen.destroy();
        w.gpa.destroy(w);
    }

    /// Fetches what the session printed since the last call and draws it
    /// into the screen. Records: see service.zig Tap.
    pub fn poll(w: *Watch) void {
        const s = w.state.load(.acquire);
        if (s == .ended or s == .failed or s == .unreadable) return;
        var arena: std.heap.ArenaAllocator = .init(w.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const Chunk = struct { data: []const u8, next: u64, state: []const u8 };
        const chunk = rpc.result(Chunk, error{Failed}, error.Failed, a, "watch.read", .{ w.id, w.offset }) catch {
            w.state.store(.failed, .release);
            _ = w.version.fetchAdd(1, .release);
            return;
        };
        w.offset = chunk.next;
        const data = rpc.decodeBase64(a, chunk.data) catch return;
        var i: usize = 0;
        while (i < data.len) {
            if (data[i] == 'r' and i + 5 <= data.len) {
                w.screen.resize(std.mem.readInt(u16, data[i + 1 ..][0..2], .big), std.mem.readInt(u16, data[i + 3 ..][0..2], .big));
                i += 5;
            } else if (data[i] == 'd' and i + 5 <= data.len) {
                const n = std.mem.readInt(u32, data[i + 1 ..][0..4], .big);
                if (i + 5 + n > data.len) break;
                w.screen.feed(data[i + 5 ..][0..n]);
                i += 5 + n;
            } else break;
        }
        const new_state = std.meta.stringToEnum(State, chunk.state) orelse .failed;
        if (data.len > 0 or new_state != s) {
            w.state.store(new_state, .release);
            _ = w.version.fetchAdd(1, .release);
        }
    }
};
