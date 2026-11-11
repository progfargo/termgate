const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Binaries import this module via b.dependency("core", ...).module("core").
    const core = b.addModule("core", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{ .root_module = core });
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // Terminal screen state (libghostty-vt), a separate module so that only
    // the binaries that keep a screen (tgnode, termgate) build the library.
    const vt = b.addModule("vt", .{
        .root_source_file = b.path("src/vt.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Pictures in the terminal (Kitty graphics) are not shown anywhere, and
    // that part does not build for the browser (wasm32-wasi): left out
    if (b.lazyDependency("ghostty", .{ .target = target, .optimize = optimize, .@"vt-features" = @as([]const u8, "-kitty_graphics") })) |dep|
        vt.addImport("ghostty-vt", dep.module("ghostty-vt"));
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = vt })).step);

    // Tests against a running nats-server (see CLAUDE.md)
    if (b.option(bool, "nats-test", "Also run tests against a local nats-server") orelse false) {
        const it_module = b.createModule(.{
            .root_source_file = b.path("src/integration_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        it_module.addAnonymousImport("test_ca", .{ .root_source_file = b.path("testdata/ca.pem") });
        it_module.addAnonymousImport("test_other_ca", .{ .root_source_file = b.path("testdata/other-ca.pem") });
        const it = b.addTest(.{ .root_module = it_module });
        test_step.dependOn(&b.addRunArtifact(it).step);
    }
}
