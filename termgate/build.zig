const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // LVGL's sources; built for the browser below
    const lvgl_dep = b.dependency("lvgl", .{});

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

    // `zig build web-test`: the panel's self-tests in headless Chrome, against
    // a termgate started in a fresh folder (src/web/selftest.zig)
    {
        const selftest = b.addExecutable(.{
            .name = "web-test",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/web/selftest.zig"),
                .target = b.graph.host,
                .optimize = .Debug,
                .link_libc = true,
                .imports = &.{.{ .name = "db", .module = db_module }},
            }),
        });
        const run = b.addRunArtifact(selftest);
        run.addFileArg(b.graph.path(.install_bin, "termgate"));
        run.addArg(".zig-cache/web-test");
        run.setCwd(b.path(""));
        // The installed termgate and panel are what is tested
        run.step.dependOn(b.getInstallStep());
        run.has_side_effects = true;
        b.step("web-test", "Run the panel's self-tests in headless Chrome").dependOn(&run.step);
    }

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
            .imports = &.{.{ .name = "zig-js", .module = zig_js }},
        });
        const spa = b.addExecutable(.{ .name = "termgate", .root_module = spa_module });
        spa.entry = .disabled;
        spa.rdynamic = true;
        spa.export_memory = true;
        const spa_dir: std.Build.InstallDir = .{ .custom = "web/spa" };
        const spa_step = b.step("spa", "Build the single-page panel into zig-out/web/spa");
        b.getInstallStep().dependOn(spa_step);
        spa_step.dependOn(&b.addInstallArtifact(spa, .{ .dest_dir = .{ .override = spa_dir } }).step);
        inline for (.{ "index.html", "boot.js", "zigjs.js" }) |f|
            spa_step.dependOn(&b.addInstallFileWithDir(b.path("web/spa/" ++ f), spa_dir, f).step);
        spa_step.dependOn(&b.addInstallDirectory(.{ .source_dir = b.path("web/asset"), .install_dir = .{ .custom = "web" }, .install_subdir = "asset" }).step);
        // The parts that do not need a browser
        const spa_tests = b.createModule(.{ .root_source_file = b.path("src/spa/app.zig"), .target = target, .optimize = optimize });
        test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = spa_tests })).step);
    }

    // The panel (zig-out/web): the screens as WASM for the browser, with
    // SDL3 and Emscripten (src/web/main.zig, web/loader.js). Zig compiles
    // the panel and LVGL for wasm32-emscripten; emcc links them with
    // Emscripten's SDL3 into termgate.js and termgate.wasm.
    {
        const em = emscripten(b);
        const wasm = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .emscripten });
        const web_debug = b.option(bool, "web-debug", "Build the web UI with safety checks and panic messages") orelse false;
        const small: std.builtin.OptimizeMode = if (web_debug) .Debug else .ReleaseSmall;
        const sysroot_include: std.Build.LazyPath = .{ .cwd_relative = b.pathJoin(&.{ em.root, "cache", "sysroot", "include" }) };

        // Emscripten's SDL3, built into its cache once; its headers are
        // needed before the panel is compiled
        const sdl_port = b.addSystemCommand(&.{ b.pathJoin(&.{ em.root, "embuilder" }), "build", "sdl3" });
        sdl_port.setEnvironmentVariable("EMSDK", em.sdk);

        const flags: []const []const u8 = &.{ "-std=gnu11", "-DLV_CONF_INCLUDE_SIMPLE" };
        const web_lvgl = b.addLibrary(.{
            .name = "lvgl",
            .linkage = .static,
            .root_module = b.createModule(.{ .target = wasm, .optimize = small, .link_libc = true }),
        });
        web_lvgl.root_module.addSystemIncludePath(sysroot_include);
        web_lvgl.root_module.addIncludePath(b.path("lvconf"));
        web_lvgl.root_module.addIncludePath(lvgl_dep.path(""));
        web_lvgl.root_module.addCSourceFiles(.{
            .root = lvgl_dep.path(""),
            .files = findLvglSources(b, b.pathJoin(&.{
                lvgl_dep.builder.root.root_dir.path orelse ".",
                lvgl_dep.builder.root.sub_path,
                "src",
            })),
            .flags = flags,
        });
        web_lvgl.root_module.addCSourceFile(.{ .file = b.path("src/lv_helpers.c"), .flags = flags });
        const web_lvgl_c = b.addTranslateC(.{ .root_source_file = lvgl_dep.path("lvgl.h"), .target = wasm, .optimize = small, .link_libc = true });
        web_lvgl_c.addSystemIncludePath(sysroot_include);
        web_lvgl_c.addIncludePath(b.path("lvconf"));
        web_lvgl_c.addIncludePath(lvgl_dep.path(""));
        web_lvgl_c.defineCMacro("LV_CONF_INCLUDE_SIMPLE", null);
        const sdl_c = b.addTranslateC(.{ .root_source_file = b.path("src/web/sdl.h"), .target = wasm, .optimize = small, .link_libc = true });
        sdl_c.addSystemIncludePath(sysroot_include);
        sdl_c.step.dependOn(&sdl_port.step);

        // The screens (ui.zig) call the database and the relay service by the
        // names termgate's own modules have; in the browser these are
        // modules that call the server
        const web_core = b.dependency("core", .{ .target = wasm, .optimize = small });
        const web_lv = web_lvgl_c.createModule();
        const rpc_module = b.createModule(.{ .root_source_file = b.path("src/web/rpc.zig"), .target = wasm, .optimize = small });
        const types_module = b.createModule(.{
            .root_source_file = b.path("src/db_types.zig"),
            .target = wasm,
            .optimize = small,
            .imports = &.{.{ .name = "core", .module = web_core.module("core") }},
        });
        const web_db = b.createModule(.{
            .root_source_file = b.path("src/web/remote_db.zig"),
            .target = wasm,
            .optimize = small,
            .imports = &.{ .{ .name = "db_types", .module = types_module }, .{ .name = "rpc", .module = rpc_module } },
        });
        const web_service = b.createModule(.{
            .root_source_file = b.path("src/web/remote_service.zig"),
            .target = wasm,
            .optimize = small,
            .imports = &.{ .{ .name = "rpc", .module = rpc_module }, .{ .name = "vt", .module = web_core.module("vt") } },
        });
        const web_session = b.createModule(.{
            .root_source_file = b.path("src/web/session.zig"),
            .target = wasm,
            .optimize = small,
            .imports = &.{.{ .name = "rpc", .module = rpc_module }},
        });
        const web_ui = b.createModule(.{
            .root_source_file = b.path("src/ui.zig"),
            .target = wasm,
            .optimize = small,
            .imports = &.{
                .{ .name = "lvgl", .module = web_lv },
                .{ .name = "core", .module = web_core.module("core") },
                .{ .name = "vt", .module = web_core.module("vt") },
                .{ .name = "db", .module = web_db },
                .{ .name = "service", .module = web_service },
                .{ .name = "session", .module = web_session },
            },
        });
        web_ui.addAnonymousImport("font_regular", .{ .root_source_file = b.path("assets/Montserrat-Regular.ttf") });
        web_ui.addAnonymousImport("font_semibold", .{ .root_source_file = b.path("assets/Montserrat-SemiBold.ttf") });
        web_ui.addAnonymousImport("font_icons", .{ .root_source_file = b.path("assets/FontAwesome-Solid-900.ttf") });
        web_ui.addAnonymousImport("font_mono", .{ .root_source_file = b.path("assets/DejaVuSansMono.ttf") });

        const web_module = b.createModule(.{
            .root_source_file = b.path("src/web/main.zig"),
            .target = wasm,
            .optimize = small,
            .link_libc = true,
            .imports = &.{
                .{ .name = "sdl", .module = sdl_c.createModule() },
                .{ .name = "lvgl", .module = web_lv },
                .{ .name = "ui", .module = web_ui },
                .{ .name = "db", .module = web_db },
                .{ .name = "service", .module = web_service },
                .{ .name = "session", .module = web_session },
                .{ .name = "rpc", .module = rpc_module },
            },
        });
        const web_lib = b.addLibrary(.{ .name = "termgate", .linkage = .static, .root_module = web_module });

        // emcc: the panel, LVGL and SDL3 into termgate.js + termgate.wasm
        const link = b.addSystemCommand(&.{b.pathJoin(&.{ em.root, "emcc" })});
        link.setEnvironmentVariable("EMSDK", em.sdk);
        link.addArtifactArg(web_lib);
        link.addArtifactArg(web_lvgl);
        link.addArgs(&.{
            "--use-port=sdl3",
            if (web_debug) "-O0" else "-O2",
            "-sALLOW_MEMORY_GROWTH=1",
            "-sSTACK_SIZE=1048576",
            "-sENVIRONMENT=web",
            "-sEXPORTED_RUNTIME_METHODS=callMain,HEAPU8",
            // SDL's drawing without WebGL (a 2D canvas) needs it
            "-sDEFAULT_LIBRARY_FUNCS_TO_INCLUDE=$Browser",
            "-sEXPORTED_FUNCTIONS=_main," ++ web_exports,
        });
        link.addPrefixedFileArg("--js-library=", b.path("web/library.js"));
        const js = link.addPrefixedOutputFileArg("-o", "termgate.js");

        const web_dir: std.Build.InstallDir = .{ .custom = "web" };
        const web_step = b.step("web", "Build the web panel (WASM) into zig-out/web");
        // The panel belongs to termgate: a plain `zig build` builds both
        b.getInstallStep().dependOn(web_step);
        web_step.dependOn(&b.addInstallDirectory(.{
            .source_dir = js.dirname(),
            .install_dir = web_dir,
            .install_subdir = "",
            .include_extensions = &.{ ".js", ".wasm" },
        }).step);
        web_step.dependOn(&b.addInstallFileWithDir(b.path("web/index.html"), web_dir, "index.html").step);
        web_step.dependOn(&b.addInstallFileWithDir(b.path("web/loader.js"), web_dir, "loader.js").step);
        inline for (.{ "manifest.webmanifest", "icon-192.png", "icon-512.png" }) |f|
            web_step.dependOn(&b.addInstallFileWithDir(b.path("web/" ++ f), web_dir, f).step);
    }
}

/// The panel's functions the page calls (src/web/main.zig), for emcc.
const web_exports = "_tg_set_dark,_tg_resize,_tg_key,_tg_text_buf,_tg_text_cap,_tg_text,_tg_frame,_tg_edit," ++
    "_tg_test_dark,_tg_test_signed_in,_tg_test_acting,_tg_test_tap,_tg_test_text,_tg_test_value,_tg_test_goto,_tg_test_press,_tg_test_has_node";

const Emscripten = struct {
    /// The emsdk folder
    sdk: []const u8,
    /// Its upstream/emscripten (emcc, embuilder, the cache)
    root: []const u8,
};

/// Emscripten: -Demsdk=<folder>, else $EMSDK, else ~/emsdk (installed with
/// `./emsdk install latest && ./emsdk activate latest`).
fn emscripten(b: *std.Build) Emscripten {
    const sdk = b.option([]const u8, "emsdk", "The emsdk folder (default: $EMSDK, else ~/emsdk)") orelse
        b.graph.environ_map.get("EMSDK") orelse
        b.pathJoin(&.{ b.graph.environ_map.get("HOME") orelse "/", "emsdk" });
    return .{ .sdk = sdk, .root = b.pathJoin(&.{ sdk, "upstream", "emscripten" }) };
}

/// Finds all .c files under LVGL's src/.
fn findLvglSources(b: *std.Build, src_dir_path: []const u8) []const []const u8 {
    var dir = std.Io.Dir.cwd().openDir(b.graph.io, src_dir_path, .{ .iterate = true }) catch
        @panic("cannot open LVGL src directory");
    defer dir.close(b.graph.io);

    var walker = dir.walk(b.graph.arena) catch @panic("OOM");
    defer walker.deinit();

    var list: std.ArrayList([]const u8) = .empty;
    while (walker.next(b.graph.io) catch @panic("cannot scan LVGL src")) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.path, ".c")) {
            list.append(b.graph.arena, b.fmt("src/{s}", .{entry.path})) catch @panic("OOM");
        }
    }
    return list.items;
}
