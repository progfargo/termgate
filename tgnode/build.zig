const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core_dep = b.dependency("core", .{ .target = target, .optimize = optimize });

    // libc headers -> Zig (uname; PTY later). musl on the gateways.
    const c_mod = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const main_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "core", .module = core_dep.module("core") },
            .{ .name = "c", .module = c_mod.createModule() },
        },
    });

    main_module.addCSourceFile(.{ .file = b.path("src/sys_helpers.c") });

    const exe = b.addExecutable(.{ .name = "tgnode", .root_module = main_module });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests = b.addTest(.{ .root_module = main_module });
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    // End-to-end test against lib/core's operator-mode nats-server (CLAUDE.md)
    if (b.option(bool, "nats-test", "Also run tests against a local nats-server") orelse false) {
        const it_module = b.createModule(.{
            .root_source_file = b.path("src/integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "core", .module = core_dep.module("core") },
                .{ .name = "c", .module = c_mod.createModule() },
            },
        });
        it_module.addCSourceFile(.{ .file = b.path("src/sys_helpers.c") });
        it_module.addAnonymousImport("test_ca", .{ .root_source_file = b.path("../lib/core/testdata/ca.pem") });
        const it = b.addTest(.{ .root_module = it_module });
        test_step.dependOn(&b.addRunArtifact(it).step);
    }
}
