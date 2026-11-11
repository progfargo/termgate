//! Hardware-bound node identity (Linux), following farlogin's flnode.
//!
//! The node's nkey is derived from a fingerprint of the machine on every start
//! and never written to disk, so a copied binary and config cannot pose as
//! this node on other hardware.
//!
//! Fingerprint (fields joined with "|"); seed = SHA-256(domain || fingerprint):
//!   - CPU vendor + "/" + model name (/proc/cpuinfo)
//!   - DMI board_serial and product_uuid (/sys/class/dmi/id/)
//!   - MACs of non-USB network interfaces, sorted, comma-joined
//!   - serial (or else WWID) of the disk holding the root filesystem
//! Missing fields are empty strings. The domain string keeps other software
//! hashing the same hardware data from arriving at the same key.

const std = @import("std");
const Io = std.Io;
const nkeys = @import("core").nkeys;
const files = @import("files.zig");
const readTrim = files.readTrim;
const afterColon = files.afterColon;

const domain = "termgate-node-v1\x00";

/// The node's key pair. `root` is "/" in production; tests pass a fake tree.
pub fn keyPair(gpa: std.mem.Allocator, io: Io, root: Io.Dir) !nkeys.KeyPair {
    const fp = try fingerprint(gpa, io, root);
    defer gpa.free(fp);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    h.update(domain);
    h.update(fp);
    var seed: [32]u8 = undefined;
    h.final(&seed);
    return nkeys.KeyPair.fromRawSeed(.user, seed);
}

/// The fingerprint string. The caller owns the result.
pub fn fingerprint(gpa: std.mem.Allocator, io: Io, root: Io.Dir) ![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const fields = [_][]const u8{
        try cpuInfo(arena, io, root),
        try readTrim(arena, io, root, "sys/class/dmi/id/board_serial"),
        try readTrim(arena, io, root, "sys/class/dmi/id/product_uuid"),
        try macAddresses(arena, io, root),
        try rootDiskSerial(arena, io, root),
    };
    return std.mem.join(gpa, "|", &fields);
}

fn cpuInfo(arena: std.mem.Allocator, io: Io, root: Io.Dir) ![]const u8 {
    const data = try readTrim(arena, io, root, "proc/cpuinfo");
    var vendor: []const u8 = "";
    var model: []const u8 = "";
    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (vendor.len == 0 and std.mem.startsWith(u8, line, "vendor_id")) vendor = afterColon(line);
        if (model.len == 0 and std.mem.startsWith(u8, line, "model name")) model = afterColon(line);
        if (vendor.len != 0 and model.len != 0) break;
    }
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ vendor, model });
}

/// MACs of every non-loopback interface whose device is not on a USB bus.
/// USB NICs come and go; onboard/PCI NICs stay with the hardware.
fn macAddresses(arena: std.mem.Allocator, io: Io, root: Io.Dir) ![]const u8 {
    var net = root.openDir(io, "sys/class/net", .{ .iterate = true }) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return "",
    };
    defer net.close(io);

    var macs: std.ArrayList([]const u8) = .empty;
    var it = net.iterate();
    while (it.next(io) catch |e| switch (e) {
        error.Canceled => return error.Canceled,
        else => return "",
    }) |entry| {
        if (std.mem.eql(u8, entry.name, "lo")) continue;
        const dev_path = try std.fmt.allocPrint(arena, "{s}/device", .{entry.name});
        var link_buf: [Io.Dir.max_path_bytes]u8 = undefined;
        const n = net.readLink(io, dev_path, &link_buf) catch continue;
        if (std.mem.indexOf(u8, link_buf[0..n], "/usb") != null) continue;
        const addr_path = try std.fmt.allocPrint(arena, "sys/class/net/{s}/address", .{entry.name});
        const addr = try readTrim(arena, io, root, addr_path);
        if (addr.len == 0 or std.mem.eql(u8, addr, "00:00:00:00:00:00")) continue;
        try macs.append(arena, addr);
    }
    std.mem.sort([]const u8, macs.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    return std.mem.join(arena, ",", macs.items);
}

/// Serial (or WWID) of the disk holding "/"; "" when the device exposes neither.
fn rootDiskSerial(arena: std.mem.Allocator, io: Io, root: Io.Dir) ![]const u8 {
    const mounts = try readTrim(arena, io, root, "proc/mounts");
    var dev: []const u8 = "";
    var lines = std.mem.splitScalar(u8, mounts, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const d = f.next() orelse continue;
        const mount_point = f.next() orelse continue;
        if (std.mem.eql(u8, mount_point, "/")) {
            dev = d;
            break;
        }
    }
    if (!std.mem.startsWith(u8, dev, "/dev/")) return "";
    var base = dev["/dev/".len..];

    // Partition suffix -> parent disk: nvme0n1p2 -> nvme0n1, mmcblk0p1 -> mmcblk0,
    // sda1 -> sda
    if (std.mem.startsWith(u8, base, "nvme") or std.mem.startsWith(u8, base, "mmcblk")) {
        const digits = trailingDigits(base);
        if (digits > 0 and base.len > digits and base[base.len - digits - 1] == 'p')
            base = base[0 .. base.len - digits - 1];
    } else {
        base = base[0 .. base.len - trailingDigits(base)];
    }
    // NVMe and some SCSI drivers expose "serial"; SATA disks often only "wwid"
    const serial = try readTrim(arena, io, root, try std.fmt.allocPrint(arena, "sys/block/{s}/device/serial", .{base}));
    if (serial.len > 0) return serial;
    return readTrim(arena, io, root, try std.fmt.allocPrint(arena, "sys/block/{s}/device/wwid", .{base}));
}

fn trailingDigits(s: []const u8) usize {
    var n: usize = 0;
    while (n < s.len and std.ascii.isDigit(s[s.len - 1 - n])) n += 1;
    return n;
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

const writeTree = files.writeTree;

test "fingerprint of a fake machine" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTree(io, tmp.dir, &.{
        .{ "proc/cpuinfo", "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Atom(TM) x5\n\nprocessor\t: 1\nvendor_id\t: GenuineIntel\n" },
        .{ "sys/class/dmi/id/board_serial", "BSN-123\n" },
        .{ "sys/class/dmi/id/product_uuid", "4c4c4544-0042\n" },
        .{ "sys/class/net/lo/address", "00:00:00:00:00:00\n" },
        .{ "sys/class/net/eth1/address", "aa:bb:cc:00:00:02\n" },
        .{ "sys/class/net/eth0/address", "aa:bb:cc:00:00:01\n" },
        .{ "sys/class/net/usb0/address", "de:ad:be:ef:00:00\n" },
        .{ "sys/class/net/docker0/address", "02:42:00:00:00:00\n" },
        .{ "proc/mounts", "sysfs /sys sysfs rw 0 0\n/dev/nvme0n1p2 / ext4 rw 0 0\n" },
        .{ "sys/block/nvme0n1/device/serial", "  S5GXNF0R  \n" },
    });
    // Devices: eth0/eth1 on PCI, usb0 on USB, docker0 virtual (no device link)
    try tmp.dir.symLink(io, "../../../devices/pci0000:00/0000:00:1f.6", "sys/class/net/eth0/device", .{});
    try tmp.dir.symLink(io, "../../../devices/pci0000:00/0000:01:00.0", "sys/class/net/eth1/device", .{});
    try tmp.dir.symLink(io, "../../../devices/pci0000:00/0000:00:14.0/usb1/1-1", "sys/class/net/usb0/device", .{});

    const fp = try fingerprint(testing.allocator, io, tmp.dir);
    defer testing.allocator.free(fp);
    try testing.expectEqualStrings(
        "GenuineIntel/Intel(R) Atom(TM) x5|BSN-123|4c4c4544-0042|aa:bb:cc:00:00:01,aa:bb:cc:00:00:02|S5GXNF0R",
        fp,
    );
}

test "missing sources give empty fields" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTree(io, tmp.dir, &.{
        .{ "proc/mounts", "/dev/sda1 / ext4 rw 0 0\n" },
        .{ "sys/block/sda/device/wwid", "naa.5002538900000000\n" },
    });
    const fp = try fingerprint(testing.allocator, io, tmp.dir);
    defer testing.allocator.free(fp);
    try testing.expectEqualStrings("/||||naa.5002538900000000", fp);
}

test "same fingerprint, same key" {
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTree(io, tmp.dir, &.{.{ "sys/class/dmi/id/product_uuid", "u-1\n" }});
    const a = try keyPair(testing.allocator, io, tmp.dir);
    const b = try keyPair(testing.allocator, io, tmp.dir);
    try testing.expectEqualStrings(&a.publicKey().encode(), &b.publicKey().encode());
    try testing.expect(std.mem.startsWith(u8, &a.publicKey().encode(), "U"));
}
