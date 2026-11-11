const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core_dep = b.dependency("core", .{ .target = target, .optimize = optimize });

    // SQLite (amalgamation), serialized mode: the panel's calls and the relay
    // service's tasks use the database from different threads
    const sqlite_dep = b.dependency("sqlite", .{});
    const sqlite_lib = b.addLibrary(.{
        .name = "sqlite3",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    sqlite_lib.root_module.addCSourceFile(.{
        .file = sqlite_dep.path("sqlite3.c"),
        .flags = &.{
            "-DSQLITE_DQS=0",
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_DEFAULT_FOREIGN_KEYS=1",
            "-Wno-gcc-install-dir-libstdcxx",
        },
    });
    sqlite_lib.root_module.addCSourceFile(.{ .file = b.path("src/sqlite_helpers.c"), .flags = &.{"-Wno-gcc-install-dir-libstdcxx"} });
    sqlite_lib.root_module.addIncludePath(sqlite_dep.path(""));

    const c_mod = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    });
    c_mod.addIncludePath(sqlite_dep.path(""));
    const c_module = c_mod.createModule();

    // Data layer
    const db_module = b.createModule(.{
        .root_source_file = b.path("src/db.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = c_module },
            .{ .name = "core", .module = core_dep.module("core") },
        },
    });
    db_module.linkLibrary(sqlite_lib);

    const db_tests = b.addTest(.{ .root_module = db_module });
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&b.addRunArtifact(db_tests).step);

    // Session recording: screens and command logs
    const recorder_module = b.createModule(.{
        .root_source_file = b.path("src/recorder.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "db", .module = db_module }},
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = recorder_module })).step);

    // termgate on the relay: auth callout, registration, invitations,
    // approvals, audit
    const service_module = b.createModule(.{
        .root_source_file = b.path("src/service.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_dep.module("core") },
            .{ .name = "recorder", .module = recorder_module },
            .{ .name = "db", .module = db_module },
        },
    });

    // First start: keys, CA, relay certificate, relay kit
    const setup_module = b.createModule(.{
        .root_source_file = b.path("src/setup.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "core", .module = core_dep.module("core") }},
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = setup_module })).step);

    // Tests against lib/core's relay setup (nats-callout-tls.conf, CLAUDE.md)
    if (b.option(bool, "nats-test", "Also run tests against a local nats-server") orelse false) {
        const it_module = b.createModule(.{
            .root_source_file = b.path("src/integration_test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "core", .module = core_dep.module("core") },
                .{ .name = "recorder", .module = recorder_module },
                .{ .name = "db", .module = db_module },
                .{ .name = "service", .module = service_module },
            },
        });
        it_module.addAnonymousImport("test_ca", .{ .root_source_file = b.path("../lib/core/testdata/ca.pem") });
        const it = b.addTest(.{ .root_module = it_module });
        test_step.dependOn(&b.addRunArtifact(it).step);
    }

    // Passwords, second step and session tokens of the panel's users
    const users_module = b.createModule(.{
        .root_source_file = b.path("src/users.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = users_module })).step);

    // termgate: the server program (the authority and the web panel's HTTP
    // side), without any UI library
    const server_module = b.createModule(.{
        .root_source_file = b.path("src/server/main.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "core", .module = core_dep.module("core") },
            .{ .name = "db", .module = db_module },
            .{ .name = "service", .module = service_module },
            .{ .name = "recorder", .module = recorder_module },
            .{ .name = "setup", .module = setup_module },
            .{ .name = "users", .module = users_module },
        },
    });
    // -Dsecond-step=false: signing in takes the password only, no code
    // from an authenticator app. For trying the panel quickly; termgate
    // says so when it starts. Without the option the second step is on.
    const server_options = b.addOptions();
    server_options.addOption(bool, "second_step", b.option(bool, "second-step", "Ask for the authenticator code at sign-in (default true; false only for trying the panel)") orelse true);
    server_module.addOptions("build_options", server_options);
    const server_exe = b.addExecutable(.{ .name = "termgate", .root_module = server_module });
    b.installArtifact(server_exe);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = server_module })).step);

    // The single-page panel (zig-out/web/spa), built like our earlier project's:
    // Zig compiled to WASM that builds the page in HTML through zig-js
    // (vendor/zig-js); its style sheet and fonts are web/asset
    {
        const spa_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
        const spa_optimize: std.builtin.OptimizeMode = if (b.option(bool, "spa-debug", "Build the single-page panel with safety checks") orelse false) .Debug else .ReleaseSmall;
        const zig_js = b.createModule(.{ .root_source_file = b.path("vendor/zig-js/src/main.zig"), .target = spa_target, .optimize = spa_optimize });
        const spa_module = b.createModule(.{
            .root_source_file = b.path("src/spa/main.zig"),
            .target = spa_target,
            .optimize = spa_optimize,
            .imports = &.{
                .{ .name = "zig-js", .module = zig_js },
                // libghostty-vt: drawing a watched session
                .{ .name = "vt", .module = b.dependency("core", .{ .target = spa_target, .optimize = spa_optimize }).module("vt") },
                // The rights a role can give, the same list as the server's
                .{ .name = "rights", .module = b.createModule(.{ .root_source_file = b.path("src/rights.zig"), .target = spa_target, .optimize = spa_optimize }) },
            },
        });
        const spa = b.addExecutable(.{ .name = "termgate", .root_module = spa_module });
        spa.entry = .disabled;
        spa.rdynamic = true;
        spa.export_memory = true;
        const spa_dir: std.Build.InstallDir = .{ .custom = "web/spa" };
        const spa_step = b.step("spa", "Build the panel into zig-out/web");
        b.getInstallStep().dependOn(spa_step);
        spa_step.dependOn(&b.addInstallArtifact(spa, .{ .dest_dir = .{ .override = spa_dir } }).step);
        inline for (.{ "index.html", "boot.js", "zigjs.js" }) |f|
            spa_step.dependOn(&b.addInstallFileWithDir(b.path("web/spa/" ++ f), spa_dir, f).step);
        // Installing the panel as an app (PWA)
        inline for (.{ "manifest.webmanifest", "icon-192.png", "icon-512.png" }) |f|
            spa_step.dependOn(&b.addInstallFileWithDir(b.path("web/" ++ f), .{ .custom = "web" }, f).step);
        spa_step.dependOn(&b.addInstallDirectory(.{ .source_dir = b.path("web/asset"), .install_dir = .{ .custom = "web" }, .install_subdir = "asset" }).step);
        // The parts that do not need a browser
        const spa_tests = b.createModule(.{ .root_source_file = b.path("src/spa/app.zig"), .target = target, .optimize = optimize });
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = spa_tests })).step);
    }
}
