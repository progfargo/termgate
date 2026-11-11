//! Screens (LVGL). Text is English. The look is a Linux terminal's: dark,
//! one accent color, DejaVu Sans Mono, thin frames, square corners.
//!
//! Layout: a top bar (menu button, page title, settings button), the page
//! content below it, a slide-in menu on the left and a slide-in settings panel
//! on the right. Both panels sit on the top layer over a dimmed backdrop;
//! tapping the backdrop closes them.
//!
//! Each page render starts from a cleaned content area and a reset arena; the
//! arena holds everything the page's LVGL objects point to.

const std = @import("std");
const lv = @import("lvgl");
const session = @import("session");
const core = @import("core");
const dbm = @import("db");
const Service = @import("service").Service;
const Watch = @import("service").Watch;
const vt = @import("vt");

const Allocator = std.mem.Allocator;
const Io = std.Io;

// src/lv_helpers.c
const panel_users = @import("panel/users.zig");
pub const panel_roles = @import("panel/roles.zig");
const panel_config = @import("panel/config.zig");
const panel_help = @import("panel/help.zig");
const panel_profile = @import("panel/profile.zig");

extern fn termgate_font_set_fallback(font: ?*lv.lv_font_t, fallback: ?*const lv.lv_font_t) void;
extern fn termgate_is_textarea(obj: ?*const lv.lv_obj_t) bool;
extern fn termgate_slide_w(obj: ?*lv.lv_obj_t, from: i32, to: i32, duration: u32) void;
extern fn termgate_slide_x(obj: ?*lv.lv_obj_t, from: i32, to: i32, duration: u32) void;
extern fn termgate_draw_fill(layer: ?*lv.lv_layer_t, x: i32, y: i32, w: i32, h: i32, rgb: u32, opa: u8) void;
extern fn termgate_draw_text(layer: ?*lv.lv_layer_t, font: ?*const lv.lv_font_t, x: i32, y: i32, w: i32, h: i32, rgb: u32, underline: bool, text: [*:0]const u8) void;

// ---------------------------------------------------------------------------
// Look

// LVGL's default theme, light or dark; the colors below are the ones the
// screens set themselves and follow the theme (setPalette).
pub var color_primary: u32 = 0;
pub var color_danger: u32 = 0;
pub var color_success: u32 = 0;
pub var color_warning: u32 = 0;
pub var color_text: u32 = 0;
/// The page behind the cards
pub var color_bg: u32 = 0;
/// Cards, bars, side panels, and the lines in them
pub var color_panel: u32 = 0;
pub var color_line: u32 = 0;
/// Text on the accent color
pub var color_on_primary: u32 = 0;
/// Faded text
pub var color_dim: u32 = 0;

var dark = false;
/// Called when the user changes the theme (the browser remembers it).
pub var on_theme: ?*const fn (bool) void = null;

fn setPalette() void {
    if (dark) {
        color_primary = 0x4C9BE0;
        color_danger = 0xEF5350;
        color_success = 0x66BB6A;
        color_warning = 0xFFA726;
        color_text = 0xE7E9EC;
        color_bg = 0x15171A;
        color_panel = 0x282B30;
        color_line = 0x3D4248;
        color_on_primary = 0xFFFFFF;
        color_dim = 0x9AA3AD;
    } else {
        color_primary = 0x1E5A8C;
        color_danger = 0xC62828;
        color_success = 0x2E7D32;
        color_warning = 0xBF5B04;
        color_text = 0x1F2933;
        color_bg = 0xF2F4F7;
        color_panel = 0xFFFFFF;
        color_line = 0xE2E6EB;
        color_on_primary = 0xFFFFFF;
        color_dim = 0x6B7785;
    }
}

pub fn isDark() bool {
    return dark;
}

/// Light or dark: everything is drawn again in the theme.
pub fn setDark(on: bool) !void {
    if (on == dark) return;
    dark = on;
    if (content == null) return; // before init: build() uses it
    try rebuild(scale);
}

const radius = 8;

// Sizes in 1x pixels; dp() scales them.
const pad = 14;
const gap = 12;
const icon_btn = 40;
const bar_h = 56;
const menu_w = 220;
/// Narrower than this (a phone), the menu is closed until its button is used
const wide_from = 760;
/// The sign-in card's width
const auth_w = 440;
const settings_w = 340;
const slide_ms = 180;

var scale: f32 = 1.0;

pub fn dp(v: i32) i32 {
    if (v == 0) return 0;
    return @max(1, @as(i32, @intFromFloat(@round(@as(f32, @floatFromInt(v)) * scale))));
}

pub var font_normal: ?*lv.lv_font_t = null;
pub var font_small: ?*lv.lv_font_t = null;
pub var font_bold: ?*lv.lv_font_t = null;
pub var font_title: ?*lv.lv_font_t = null;
/// Watched terminals
var font_mono: ?*lv.lv_font_t = null;
var icon_fonts: [4]?*lv.lv_font_t = @splat(null);

const font_regular_data = @embedFile("font_regular");
const font_semibold_data = @embedFile("font_semibold");
const font_icons_data = @embedFile("font_icons");
const font_mono_data = @embedFile("font_mono");

// ---------------------------------------------------------------------------
// State

/// The pages of the menu. From `users` on they are under the menu's
/// "Admin" heading (src/panel/). Profile is last, as in another earlier project.
pub const Page = enum(u8) { nodes, people, sessions, audit, users, roles, config, help, profile };
pub const page_count = 9;
const first_admin_page = @intFromEnum(Page.users);
const page_titles = [page_count][*:0]const u8{ "Nodes", "People", "Sessions", "Audit", "Users", "Roles", "Configuration", "Help", "Profile" };
/// Font Awesome code points (the whole Solid font is embedded, not only
/// LVGL's LV_SYMBOL_* subset): server, users, terminal, clipboard-list,
/// user, user-shield, cog, question-circle, user-circle
const page_icons = [page_count][*:0]const u8{ "\u{f233}", "\u{f0c0}", "\u{f120}", "\u{f46d}", "\u{f007}", "\u{f505}", "\u{f013}", "\u{f059}", "\u{f2bd}" };

/// May the signed-in user open the page (the right to browse it).
pub fn pageVisible(p: Page) bool {
    return switch (p) {
        .nodes => session.can("node", "browse"),
        .people => session.can("user", "browse"),
        .sessions => session.can("session", "browse"),
        .audit => session.can("audit", "browse"),
        .users => session.can("user", "browse"),
        .roles => session.can("role", "browse"),
        .config => session.can("config", "browse"),
        .help => true,
        .profile => session.can("profile", "browse"),
    };
}

/// The first page the user may open.
fn firstPage() Page {
    for (std.enums.values(Page)) |p| if (pageVisible(p)) return p;
    return .help;
}

pub var gpa: Allocator = undefined;
pub var io: Io = undefined;
pub var db: *dbm.Db = undefined;
pub var db_lock: *Io.Mutex = undefined;
/// Panels slide in real use; tests set them at once.
var animate = true;

/// Where nodes and users connect; needed to hand out node keys and
/// invitations. null until termgate is set up.
pub const Relay = struct {
    host: []const u8,
    port: u16,
    ca_fingerprint: [32]u8,
};
var relay: ?Relay = null;

pub fn setRelay(r: ?Relay) void {
    relay = r;
}

/// The running relay service (null when termgate is not connected); used to
/// end sessions.
var service: ?*Service = null;

/// Puts text on the clipboard; set by the platform layer.
pub var copy_text: ?*const fn ([*:0]const u8) void = null;
/// Asks the platform to type the clipboard's text into the focused field;
/// null where the clipboard cannot be read (then Paste is not offered).
pub var paste_text: ?*const fn () void = null;
/// Called once a user has signed in (web panel): the platform layer
/// fetches what the screens need.
pub var on_signed_in: ?*const fn () void = null;

pub fn setService(s: ?*Service) void {
    // A watch reads through the service's connection: end it first
    if (s == null and watch != null) {
        stopWatch();
        renderPage();
    }
    service = s;
}

var page: Page = .nodes;
var arena: std.heap.ArenaAllocator = undefined;

pub var content: ?*lv.lv_obj_t = null;
var page_title: ?*lv.lv_obj_t = null;
var backdrop: ?*lv.lv_obj_t = null;
var menu_panel: ?*lv.lv_obj_t = null;
var top_bar: ?*lv.lv_obj_t = null;
var main_column: ?*lv.lv_obj_t = null;
/// What the menu is in; its width is 0 while the menu is closed
var menu_slot: ?*lv.lv_obj_t = null;
var settings_panel: ?*lv.lv_obj_t = null;
var menu_open = false;
var settings_open = false;

/// Objects the panel's self-test taps and reads (web/main.zig).
pub const Refs = struct {
    menu_btn: ?*lv.lv_obj_t = null,
    settings_btn: ?*lv.lv_obj_t = null,
    signin_qr: ?*lv.lv_obj_t = null,
    backdrop: ?*lv.lv_obj_t = null,
    menu_items: [page_count]?*lv.lv_obj_t = @splat(null),
    // Nodes page
    new_node_btn: ?*lv.lv_obj_t = null,
    node_name_ta: ?*lv.lv_obj_t = null,
    node_desc_ta: ?*lv.lv_obj_t = null,
    node_create_btn: ?*lv.lv_obj_t = null,
    code_label: ?*lv.lv_obj_t = null,
    done_btn: ?*lv.lv_obj_t = null,
    first_approve_btn: ?*lv.lv_obj_t = null,
    first_reject_btn: ?*lv.lv_obj_t = null,
    msg_label: ?*lv.lv_obj_t = null,
    first_node_card: ?*lv.lv_obj_t = null,
    // Node info
    node_back_btn: ?*lv.lv_obj_t = null,
    node_refresh_btn: ?*lv.lv_obj_t = null,
    node_state_chip: ?*lv.lv_obj_t = null,
    node_hostname: ?*lv.lv_obj_t = null,
    node_sessions: usize = 0,
    // People page
    invite_btn: ?*lv.lv_obj_t = null,
    inv_name_ta: ?*lv.lv_obj_t = null,
    inv_bot_cb: ?*lv.lv_obj_t = null,
    inv_nodes_ta: ?*lv.lv_obj_t = null,
    inv_run_as_ta: ?*lv.lv_obj_t = null,
    inv_uses_ta: ?*lv.lv_obj_t = null,
    inv_days_ta: ?*lv.lv_obj_t = null,
    inv_create_btn: ?*lv.lv_obj_t = null,
    first_revoke_btn: ?*lv.lv_obj_t = null,
    // Sessions and audit
    first_end_btn: ?*lv.lv_obj_t = null,
    first_watch_btn: ?*lv.lv_obj_t = null,
    audit_rows: usize = 0,
    action_rows: usize = 0,
    // Watching a session
    watch_back_btn: ?*lv.lv_obj_t = null,
    watch_history_btn: ?*lv.lv_obj_t = null,
    // Session history (log)
    history_back_btn: ?*lv.lv_obj_t = null,
    history_mode_btn: ?*lv.lv_obj_t = null,
    history_commands: usize = 0,
    history_rows: usize = 0,
    history_grid: ?*const vt.Screen.Grid = null,
    first_audit_row: ?*lv.lv_obj_t = null,
    // Users (web panel)
    new_user_btn: ?*lv.lv_obj_t = null,
    user_name_ta: ?*lv.lv_obj_t = null,
    user_create_btn: ?*lv.lv_obj_t = null,
    user_rows: usize = 0,
    first_user_edit_btn: ?*lv.lv_obj_t = null,
    last_user_edit_btn: ?*lv.lv_obj_t = null,
    last_user_delete_btn: ?*lv.lv_obj_t = null,
    user_role_dd: ?*lv.lv_obj_t = null,
    user_grant_btn: ?*lv.lv_obj_t = null,
    user_roles: usize = 0,
    // Roles
    new_role_btn: ?*lv.lv_obj_t = null,
    role_name_ta: ?*lv.lv_obj_t = null,
    role_description_ta: ?*lv.lv_obj_t = null,
    role_save_btn: ?*lv.lv_obj_t = null,
    role_rows: usize = 0,
    last_role_edit_btn: ?*lv.lv_obj_t = null,
    last_role_delete_btn: ?*lv.lv_obj_t = null,
    confirm_yes_btn: ?*lv.lv_obj_t = null,
    edit_select_all_btn: ?*lv.lv_obj_t = null,
    edit_cut_btn: ?*lv.lv_obj_t = null,
    edit_copy_btn: ?*lv.lv_obj_t = null,
    edit_paste_btn: ?*lv.lv_obj_t = null,
    // Signing in (web panel)
    signin_name_ta: ?*lv.lv_obj_t = null,
    signin_password_ta: ?*lv.lv_obj_t = null,
    signin_code_ta: ?*lv.lv_obj_t = null,
    signin_btn: ?*lv.lv_obj_t = null,
    sign_out_btn: ?*lv.lv_obj_t = null,
    theme_cb: ?*lv.lv_obj_t = null,
    // Acting as another user (top bar): who, and back to oneself
    acting_label: ?*lv.lv_obj_t = null,
    acting_btn: ?*lv.lv_obj_t = null,
    last_user_select_btn: ?*lv.lv_obj_t = null,
    // Profile page
    profile_current_ta: ?*lv.lv_obj_t = null,
    profile_new_ta: ?*lv.lv_obj_t = null,
    profile_new2_ta: ?*lv.lv_obj_t = null,
    profile_password_btn: ?*lv.lv_obj_t = null,
    // Configuration page
    set_output_ta: ?*lv.lv_obj_t = null,
    set_minutes_ta: ?*lv.lv_obj_t = null,
    set_days_ta: ?*lv.lv_obj_t = null,
    set_save_btn: ?*lv.lv_obj_t = null,
    set_msg: ?*lv.lv_obj_t = null,
    watch_screen: ?*lv.lv_obj_t = null,
    watch_status: ?*lv.lv_obj_t = null,
};
pub var refs: Refs = .{};

fn clearPageRefs() void {
    const keep = refs;
    refs = .{};
    refs.menu_btn = keep.menu_btn;
    refs.settings_btn = keep.settings_btn;
    refs.backdrop = keep.backdrop;
    refs.menu_items = keep.menu_items;
    refs.sign_out_btn = keep.sign_out_btn;
    refs.acting_label = keep.acting_label;
    refs.acting_btn = keep.acting_btn;
    refs.confirm_yes_btn = keep.confirm_yes_btn;
    msg_box = null;
}

// ---------------------------------------------------------------------------
// Setup

/// TTF font at the current scale, with Font Awesome as fallback for icons.
fn makeFont(data: []const u8, size: i32, icon_slot: usize) ?*lv.lv_font_t {
    const px = dp(size);
    const f = lv.lv_tiny_ttf_create_data(data.ptr, data.len, px);
    const icons = lv.lv_tiny_ttf_create_data(font_icons_data.ptr, font_icons_data.len, px);
    icon_fonts[icon_slot] = icons;
    termgate_font_set_fallback(f, icons);
    return f;
}

fn destroyFonts() void {
    for ([_]*?*lv.lv_font_t{ &font_normal, &font_small, &font_bold, &font_title, &font_mono }) |f| {
        if (f.*) |ff| lv.lv_tiny_ttf_destroy(ff);
        f.* = null;
    }
    for (&icon_fonts) |*f| {
        if (f.*) |ff| lv.lv_tiny_ttf_destroy(ff);
        f.* = null;
    }
}

pub fn init(allocator: Allocator, io_: Io, database: *dbm.Db, lock: *Io.Mutex, ui_scale: f32, animated: bool) !void {
    gpa = allocator;
    io = io_;
    db = database;
    db_lock = lock;
    animate = animated;
    arena = .init(gpa);
    try build(ui_scale);
}

/// Rebuilds everything at a new scale (window moved to another display).
pub fn setScale(ui_scale: f32) !void {
    if (@abs(ui_scale - scale) < 0.01) return;
    try rebuild(ui_scale);
}

fn rebuild(ui_scale: f32) !void {
    stopWatch();
    lv.lv_obj_clean(lv.lv_screen_active());
    lv.lv_obj_clean(lv.lv_layer_top());
    refs = .{};
    menu_open = false;
    settings_open = false;
    destroyFonts();
    try build(ui_scale);
}

/// Deletes the UI's objects before its fonts: objects still on the screen
/// would use the destroyed fonts when LVGL deletes them later.
pub fn deinit() void {
    stopWatch();
    if (refresh_timer) |t| lv.lv_timer_delete(t);
    refresh_timer = null;
    lv.lv_obj_clean(lv.lv_layer_top());
    lv.lv_obj_clean(lv.lv_screen_active());
    arena.deinit();
    destroyFonts();
}

fn build(ui_scale: f32) !void {
    scale = ui_scale;
    setPalette();
    font_normal = makeFont(font_regular_data, 15, 0);
    font_small = makeFont(font_regular_data, 13, 1);
    font_bold = makeFont(font_semibold_data, 15, 2);
    font_title = makeFont(font_semibold_data, 20, 3);
    font_mono = lv.lv_tiny_ttf_create_data(font_mono_data.ptr, font_mono_data.len, dp(13));
    if (font_normal == null or font_small == null or font_bold == null or font_title == null or font_mono == null)
        return error.FontLoadFailed;

    // The theme gets the font, so every widget uses it
    const disp = lv.lv_display_get_default();
    const theme = lv.lv_theme_default_init(disp, lv.lv_color_hex(color_primary), lv.lv_color_hex(color_danger), dark, font_normal);
    lv.lv_display_set_theme(disp, theme);

    const scr = lv.lv_screen_active();
    lv.lv_obj_set_style_text_font(scr, font_normal, 0);
    lv.lv_obj_set_style_text_color(scr, lv.lv_color_hex(color_text), 0);
    lv.lv_obj_set_style_bg_color(scr, lv.lv_color_hex(color_bg), 0);
    // The menu beside the page: when it slides in, the page gets narrower
    lv.lv_obj_set_flex_flow(scr, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_column(scr, 0, 0);
    lv.lv_obj_set_style_pad_all(scr, 0, 0);
    lv.lv_obj_set_style_pad_row(scr, 0, 0);
    lv.lv_obj_set_scrollable(scr, false);
    lv.lv_obj_set_style_text_font(lv.lv_layer_top(), font_normal, 0);
    lv.lv_obj_set_style_text_color(lv.lv_layer_top(), lv.lv_color_hex(color_text), 0);

    menu_slot = lv.lv_obj_create(scr);
    lv.lv_obj_remove_style_all(menu_slot);
    lv.lv_obj_set_size(menu_slot, 0, lv.lv_pct(100));
    lv.lv_obj_set_scrollable(menu_slot, false);

    const main_col = lv.lv_obj_create(scr);
    lv.lv_obj_remove_style_all(main_col);
    lv.lv_obj_set_size(main_col, 1, lv.lv_pct(100));
    lv.lv_obj_set_flex_grow(main_col, 1);
    lv.lv_obj_set_flex_flow(main_col, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_scrollable(main_col, false);
    main_column = main_col;
    buildTopBar(main_col);

    content = lv.lv_obj_create(main_col);
    lv.lv_obj_remove_style_all(content);
    lv.lv_obj_set_width(content, lv.lv_pct(100));
    lv.lv_obj_set_flex_grow(content, 1);
    lv.lv_obj_set_flex_flow(content, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_style_pad_all(content, dp(pad), 0);
    lv.lv_obj_set_style_pad_row(content, dp(gap), 0);
    lv.lv_obj_set_scroll_dir(content, lv.LV_DIR_VER);

    buildPanels();
    renderPage();
    if (refresh_timer == null) refresh_timer = lv.lv_timer_create(onRefreshTimer, 2000, null);
}

/// Live pages (nodes, sessions) are re-rendered when what they show changes.
var refresh_timer: ?*lv.lv_timer_t = null;
var last_signature: u64 = 0;

fn onRefreshTimer(_: ?*lv.lv_timer_t) callconv(.c) void {
    refresh();
}

/// Re-renders the page if its data changed (and no form is open).
pub fn refresh() void {
    // The sign-in screen shows no data: nothing to ask the server for
    if (!session.signedIn() or settings_open) return;
    switch (page) {
        .nodes => switch (nodes_mode) {
            .list => if (nodesSignature() != last_signature) renderPage(),
            .info => if (nodeInfoSignature() != last_signature) renderPage(),
            else => {},
        },
        // The watch view updates itself (onWatchTimer)
        .sessions => if (watch == null and sessionsSignature() != last_signature) renderPage(),
        else => {},
    }
}

fn buildTopBar(scr: ?*lv.lv_obj_t) void {
    const bar = lv.lv_obj_create(scr);
    top_bar = bar;
    lv.lv_obj_set_size(bar, lv.lv_pct(100), dp(bar_h));
    lv.lv_obj_set_style_radius(bar, 0, 0);
    lv.lv_obj_set_style_bg_color(bar, lv.lv_color_hex(color_panel), 0);
    lv.lv_obj_set_style_border_side(bar, lv.LV_BORDER_SIDE_BOTTOM, 0);
    lv.lv_obj_set_style_border_width(bar, 1, 0);
    lv.lv_obj_set_style_border_color(bar, lv.lv_color_hex(color_line), 0);
    lv.lv_obj_set_style_shadow_width(bar, 0, 0);
    lv.lv_obj_set_style_pad_hor(bar, dp(10), 0);
    lv.lv_obj_set_style_pad_ver(bar, 0, 0);
    lv.lv_obj_set_flex_flow(bar, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_flex_align(bar, lv.LV_FLEX_ALIGN_START, lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER);
    lv.lv_obj_set_style_pad_column(bar, dp(10), 0);
    lv.lv_obj_set_scrollable(bar, false);

    refs.menu_btn = flatIconButton(bar, lv.LV_SYMBOL_BARS, onMenuButton);
    page_title = lv.lv_label_create(bar);
    lv.lv_obj_set_style_text_font(page_title, font_title, 0);
    lv.lv_obj_set_style_text_color(page_title, lv.lv_color_hex(color_primary), 0);
    lv.lv_obj_set_flex_grow(page_title, 1);
    // While acting as another user: "erdem as veli", and back to oneself
    refs.acting_label = lv.lv_label_create(bar);
    lv.lv_obj_set_style_text_color(refs.acting_label, lv.lv_color_hex(color_warning), 0);
    refs.acting_btn = outlineButton(bar, "Back to myself", onStopActing, null, false);
    refs.settings_btn = flatIconButton(bar, "\u{f007}", onSettingsButton);
}

/// The left menu and the right settings panel, closed (outside the screen).
fn buildPanels() void {
    const top = lv.lv_layer_top();

    backdrop = lv.lv_obj_create(top);
    lv.lv_obj_remove_style_all(backdrop);
    lv.lv_obj_set_size(backdrop, lv.lv_pct(100), lv.lv_pct(100));
    lv.lv_obj_set_style_bg_color(backdrop, lv.lv_color_hex(0x000000), 0);
    lv.lv_obj_set_style_bg_opa(backdrop, lv.LV_OPA_60, 0);
    lv.lv_obj_set_clickable(backdrop, true);
    lv.lv_obj_set_hidden(backdrop, true);
    _ = lv.lv_obj_add_event_cb(backdrop, onBackdrop, lv.LV_EVENT_CLICKED, null);
    refs.backdrop = backdrop;

    // The menu is in its slot beside the page (see build), at its full
    // width; the slot's width is what opens and closes it
    const side = lv.lv_obj_create(menu_slot);
    lv.lv_obj_remove_style_all(side);
    lv.lv_obj_set_size(side, dp(menu_w), lv.lv_pct(100));
    lv.lv_obj_set_style_bg_color(side, lv.lv_color_hex(colorSidebar()), 0);
    lv.lv_obj_set_style_bg_opa(side, lv.LV_OPA_COVER, 0);
    lv.lv_obj_set_flex_flow(side, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_style_pad_all(side, dp(12), 0);
    lv.lv_obj_set_style_pad_row(side, dp(4), 0);
    menu_panel = side;
    const brand = label(side, "termgate");
    lv.lv_obj_set_style_text_font(brand, font_title, 0);
    lv.lv_obj_set_style_text_color(brand, lv.lv_color_hex(0xFFFFFF), 0);
    lv.lv_obj_set_style_pad_bottom(brand, dp(16), 0);
    lv.lv_obj_set_style_pad_left(brand, dp(8), 0);
    for (0..page_count) |i| {
        if (i == first_admin_page) {
            const heading = muted(side, "Admin");
            lv.lv_obj_set_style_text_color(heading, lv.lv_color_hex(color_sidebar_text), 0);
            lv.lv_obj_set_style_text_opa(heading, lv.LV_OPA_60, 0);
            lv.lv_obj_set_style_pad_top(heading, dp(14), 0);
            lv.lv_obj_set_style_pad_left(heading, dp(8), 0);
        }
        refs.menu_items[i] = menuItem(side, page_icons[i], page_titles[i], onMenuItem, @ptrFromInt(i + 1));
    }
    const spacer = lv.lv_obj_create(side);
    lv.lv_obj_remove_style_all(spacer);
    lv.lv_obj_set_width(spacer, lv.lv_pct(100));
    lv.lv_obj_set_flex_grow(spacer, 1);
    refs.sign_out_btn = menuItem(side, lv.LV_SYMBOL_POWER, "Sign out", onSignOut, null);
    styleMenuItems();

    // A focused text area in a closed panel must not scroll the layer
    // (that would pull the panel into view)
    lv.lv_obj_set_scrollable(top, false);
    settings_panel = panel(top, dp(settings_w));
    lv.lv_obj_set_align(settings_panel, lv.LV_ALIGN_TOP_RIGHT);
    lv.lv_obj_set_x(settings_panel, dp(settings_w));
    renderSettings();
}

fn panel(parent: ?*lv.lv_obj_t, width: i32) ?*lv.lv_obj_t {
    const p = lv.lv_obj_create(parent);
    lv.lv_obj_set_size(p, width, lv.lv_pct(100));
    lv.lv_obj_set_style_radius(p, 0, 0);
    lv.lv_obj_set_style_bg_color(p, lv.lv_color_hex(color_panel), 0);
    lv.lv_obj_set_style_border_width(p, 1, 0);
    lv.lv_obj_set_style_border_color(p, lv.lv_color_hex(color_line), 0);
    lv.lv_obj_set_style_shadow_width(p, 0, 0);
    lv.lv_obj_set_style_pad_all(p, dp(16), 0);
    lv.lv_obj_set_style_pad_row(p, dp(6), 0);
    lv.lv_obj_set_flex_flow(p, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_hidden(p, true);
    return p;
}

const color_sidebar_text = 0xDDE6EE;
const color_sidebar_active = 0x1E5A8C;

fn colorSidebar() u32 {
    return if (dark) 0x1B1E22 else 0x13293D;
}

/// A row of the menu: icon and name.
fn menuItem(parent: ?*lv.lv_obj_t, icon: [*:0]const u8, text: [*:0]const u8, cb: lv.lv_event_cb_t, user_data: ?*anyopaque) ?*lv.lv_obj_t {
    const b = lv.lv_obj_create(parent);
    lv.lv_obj_remove_style_all(b);
    lv.lv_obj_set_size(b, lv.lv_pct(100), lv.LV_SIZE_CONTENT);
    lv.lv_obj_set_style_pad_ver(b, dp(10), 0);
    lv.lv_obj_set_style_pad_hor(b, dp(10), 0);
    lv.lv_obj_set_style_radius(b, dp(8), 0);
    lv.lv_obj_set_style_bg_color(b, lv.lv_color_hex(color_sidebar_active), 0);
    lv.lv_obj_set_style_bg_opa(b, lv.LV_OPA_TRANSP, 0);
    lv.lv_obj_set_style_bg_opa(b, lv.LV_OPA_50, lv.LV_STATE_PRESSED);
    lv.lv_obj_add_flag(b, lv.LV_OBJ_FLAG_CLICKABLE);
    lv.lv_obj_remove_flag(b, lv.LV_OBJ_FLAG_SCROLLABLE);
    lv.lv_obj_set_flex_flow(b, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_column(b, dp(10), 0);
    lv.lv_obj_set_style_text_color(b, lv.lv_color_hex(color_sidebar_text), 0);
    const ic = lv.lv_label_create(b);
    lv.lv_label_set_text(ic, icon);
    // Icons differ in width; a fixed column keeps the names aligned
    lv.lv_obj_set_width(ic, dp(22));
    lv.lv_obj_set_style_text_align(ic, lv.LV_TEXT_ALIGN_CENTER, 0);
    const l = lv.lv_label_create(b);
    lv.lv_label_set_text(l, text);
    _ = lv.lv_obj_add_event_cb(b, cb, lv.LV_EVENT_CLICKED, user_data);
    return b;
}

/// The current page's menu item is highlighted; pages the user may not
/// browse are not in the menu.
fn styleMenuItems() void {
    for (refs.menu_items, 0..) |item, i| {
        lv.lv_obj_set_hidden(item, !pageVisible(@enumFromInt(i)));
        const active = i == @intFromEnum(page);
        lv.lv_obj_set_style_bg_opa(item, if (active) lv.LV_OPA_COVER else lv.LV_OPA_TRANSP, 0);
        lv.lv_obj_set_style_text_color(item, lv.lv_color_hex(if (active) 0xFFFFFF else color_sidebar_text), 0);
        lv.lv_obj_set_style_text_font(item, if (active) font_bold else font_normal, 0);
    }
}

/// A window wide enough for the menu to stay beside the page.
fn wide() bool {
    return lv.lv_display_get_horizontal_resolution(null) >= dp(wide_from);
}

/// Lays the page out for who is looking at it. Signed in: the menu on the
/// left (always there in a wide window; behind its button on a phone),
/// the bar on top. Not signed in: only the sign-in card, in the middle.
fn applyShell() void {
    const signed_in = session.signedIn();
    const fixed = signed_in and wide();
    if (!signed_in or !fixed) {
        if (!signed_in) menu_open = false;
    }
    _ = lv.lv_anim_delete(menu_slot, null);
    lv.lv_obj_set_width(menu_slot, if (fixed or (signed_in and menu_open)) dp(menu_w) else 0);
    lv.lv_obj_set_hidden(top_bar, !signed_in);
    lv.lv_obj_set_hidden(refs.menu_btn, fixed);
    lv.lv_obj_set_hidden(refs.settings_btn, !signed_in);
    const acting = session.actingFor();
    lv.lv_obj_set_hidden(refs.acting_label, acting == null);
    lv.lv_obj_set_hidden(refs.acting_btn, acting == null or !session.canUnselect());
    if (acting) |real| {
        var buf: [160]u8 = undefined;
        const text: [:0]const u8 = std.fmt.bufPrintSentinel(&buf, "{s} as {s}", .{ real, session.name() }, 0) catch "";
        lv.lv_label_set_text(refs.acting_label, text.ptr);
    }
    lv.lv_obj_set_flex_align(main_column, if (signed_in) lv.LV_FLEX_ALIGN_START else lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER);
    if (signed_in) {
        lv.lv_obj_set_width(content, lv.lv_pct(100));
        lv.lv_obj_set_flex_grow(content, 1);
    } else {
        lv.lv_obj_set_flex_grow(content, 0);
        lv.lv_obj_set_size(content, @min(dp(auth_w), lv.lv_display_get_horizontal_resolution(null)), lv.LV_SIZE_CONTENT);
    }
}

/// The window's size changed.
pub fn resized() void {
    if (content == null) return;
    applyShell();
}

// ---------------------------------------------------------------------------
// Panels

pub fn menuOpen() bool {
    return menu_open;
}

pub fn settingsOpen() bool {
    return settings_open;
}

fn slide(p: ?*lv.lv_obj_t, from: i32, to: i32) void {
    termgate_slide_x(p, from, to, if (animate) slide_ms else 0);
}

fn openMenu() void {
    if (wide()) return; // always there
    closeSettings();
    termgate_slide_w(menu_slot, 0, dp(menu_w), if (animate) slide_ms else 0);
    menu_open = true;
}

fn closeMenu() void {
    if (!menu_open) return;
    menu_open = false;
    if (wide()) return; // always there
    termgate_slide_w(menu_slot, dp(menu_w), 0, if (animate) slide_ms else 0);
    menu_open = false;
}

fn openSettings() void {
    renderSettings();
    lv.lv_obj_set_hidden(backdrop, false);
    lv.lv_obj_set_hidden(settings_panel, false);
    lv.lv_obj_move_foreground(settings_panel);
    slide(settings_panel, dp(settings_w), 0);
    settings_open = true;
}

fn closeSettings() void {
    if (!settings_open) return;
    slide(settings_panel, 0, dp(settings_w));
    lv.lv_obj_set_hidden(backdrop, true);
    settings_open = false;
}

fn onMenuButton(_: ?*lv.lv_event_t) callconv(.c) void {
    if (!session.signedIn()) return;
    if (menu_open) closeMenu() else openMenu();
}

fn onSettingsButton(_: ?*lv.lv_event_t) callconv(.c) void {
    if (!session.signedIn()) return;
    if (settings_open) closeSettings() else openSettings();
}

fn onBackdrop(_: ?*lv.lv_event_t) callconv(.c) void {
    closeMenu();
    closeSettings();
}

fn onMenuItem(e: ?*lv.lv_event_t) callconv(.c) void {
    const i = @intFromPtr(lv.lv_event_get_user_data(e)) - 1;
    page = @enumFromInt(i);
    stopWatch();
    history_on = false;
    panel_users.reset();
    panel_roles.reset();
    // Fresh system info from the online nodes (they answer on status.<node>)
    if (page == .nodes) if (service) |s| s.requestStatus();
    closeMenu();
    styleMenuItems();
    renderPage();
}

/// Shows a page (the web panel's self-test; people use the menu).
pub fn showPage(p: Page) void {
    page = p;
    stopWatch();
    history_on = false;
    panel_users.reset();
    panel_roles.reset();
    styleMenuItems();
    renderPage();
}

pub fn currentPage() Page {
    return page;
}

/// The panel on the right: who is signed in, and signing out.
fn renderSettings() void {
    lv.lv_obj_clean(settings_panel);
    const t = lv.lv_label_create(settings_panel);
    lv.lv_label_set_text(t, "User");
    lv.lv_obj_set_style_text_font(t, font_title, 0);
    lv.lv_obj_set_style_pad_bottom(t, dp(12), 0);
    if (!session.signedIn()) return;
    var buf: [96]u8 = undefined;
    _ = bold(settings_panel, std.fmt.bufPrintSentinel(&buf, "{s}", .{session.name()}, 0) catch "");
    if (session.isSuperuser()) _ = muted(settings_panel, "Superuser: has every right.");
    if (session.actingFor()) |real| _ = muted(settings_panel, std.fmt.bufPrintSentinel(&buf, "Signed in as {s}, acting as this user.", .{real}, 0) catch "");
    const theme_cb = checkbox(settings_panel, "Dark theme", dark);
    lv.lv_obj_set_style_pad_top(theme_cb, dp(16), 0);
    _ = lv.lv_obj_add_event_cb(theme_cb, onThemeBox, lv.LV_EVENT_VALUE_CHANGED, null);
    refs.theme_cb = theme_cb;
}

fn onThemeBox(_: ?*lv.lv_event_t) callconv(.c) void {
    // Everything is drawn again, the checkbox too: not inside its own event
    _ = lv.lv_async_call(switchTheme, null);
}

fn switchTheme(_: ?*anyopaque) callconv(.c) void {
    setDark(!dark) catch return;
    if (on_theme) |f| f(dark);
}

// ---------------------------------------------------------------------------
// Pages

/// Cleans the content, resets the page arena and returns it.
pub fn beginPage() Allocator {
    lv.lv_obj_clean(content);
    _ = arena.reset(.retain_capacity);
    lv.lv_obj_scroll_to_y(content, 0, false);
    lv.lv_label_set_text(page_title, page_titles[@intFromEnum(page)]);
    return arena.allocator();
}

fn renderPage() void {
    renderPageContent();
    // A form: the cursor is in its first field
    if (firstField(content)) |f| lv.lv_group_focus_obj(f);
}

/// The first text field under `parent`, in the order shown.
fn firstField(parent: ?*lv.lv_obj_t) ?*lv.lv_obj_t {
    var i: u32 = 0;
    while (i < lv.lv_obj_get_child_count(parent)) : (i += 1) {
        const child = lv.lv_obj_get_child(parent, @intCast(i));
        if (termgate_is_textarea(child)) return child;
        if (firstField(child)) |f| return f;
    }
    return null;
}

fn renderPageContent() void {
    clearPageRefs();
    // The menu and the settings are for signed-in users: before that the
    // top bar has no buttons, and an open panel is closed
    const signed_in = session.signedIn();
    applyShell();
    if (!signed_in) {
        closeSettings();
        return renderSignIn();
    }
    if (history_on) return renderHistory();
    // A page the user has no right to browse (any more) is not shown
    if (!pageVisible(page)) {
        page = firstPage();
        styleMenuItems();
    }
    switch (page) {
        .nodes => renderNodes(),
        .people => renderPeople(),
        .sessions => renderSessions(),
        .audit => renderAudit(),
        .users => panel_users.render(),
        .roles => panel_roles.render(),
        .config => panel_config.render(),
        .help => panel_help.render(),
        .profile => panel_profile.render(),
    }
}

fn now() i64 {
    return @intCast(@divFloor(Io.Timestamp.now(io, .real).nanoseconds, std.time.ns_per_s));
}

/// "just now", "12 s ago", "5 min ago", "3 h ago", "2 days ago"
fn ago(a: Allocator, t: ?i64) [*:0]const u8 {
    const v = t orelse return "never";
    const d = @max(now() - v, 0);
    if (d < 10) return "just now";
    if (d < 60) return zfmt(a, "{d} s ago", .{d});
    if (d < 3600) return zfmt(a, "{d} min ago", .{@divTrunc(d, 60)});
    if (d < 86400) return zfmt(a, "{d} h ago", .{@divTrunc(d, 3600)});
    return zfmt(a, "{d} days ago", .{@divTrunc(d, 86400)});
}

fn gb(kb: u64) f64 {
    return @as(f64, @floatFromInt(kb)) / (1024.0 * 1024.0);
}

/// What tgnode reports (sysinfo.Status); fields are optional so older or
/// partial reports still show.
const NodeStatus = struct {
    version: []const u8 = "",
    hostname: []const u8 = "",
    os: []const u8 = "",
    kernel: []const u8 = "",
    arch: []const u8 = "",
    cpus: u32 = 0,
    uptime_s: u64 = 0,
    load: [3]f64 = .{ 0, 0, 0 },
    mem_total_kb: u64 = 0,
    mem_available_kb: u64 = 0,
    disk_total_bytes: u64 = 0,
    disk_free_bytes: u64 = 0,
};

fn parseStatus(a: Allocator, json: ?[]const u8) ?NodeStatus {
    return std.json.parseFromSliceLeaky(NodeStatus, a, json orelse return null, .{ .ignore_unknown_fields = true }) catch null;
}

/// System info lines of a node card.
fn statusLines(parent: ?*lv.lv_obj_t, a: Allocator, st: NodeStatus) void {
    _ = muted(parent, zfmt(a, "{s} · {s} · {s} · {d} CPUs · tgnode {s}", .{ st.hostname, st.os, st.arch, st.cpus, st.version }));
    const mem_used = st.mem_total_kb -| st.mem_available_kb;
    _ = muted(parent, zfmt(a, "Memory {d:.1} / {d:.1} GB used · Disk {d:.0} GB free of {d:.0} GB", .{
        gb(mem_used),
        gb(st.mem_total_kb),
        @as(f64, @floatFromInt(st.disk_free_bytes)) / 1e9,
        @as(f64, @floatFromInt(st.disk_total_bytes)) / 1e9,
    }));
}

// ---------------------------------------------------------------------------
// Signing in (web panel): name and password, then a code from the
// authenticator app; at the first sign-in the app is set up with a secret.

const SignInStep = enum { password, code, setup };
var signin_step: SignInStep = .password;
var signin_msg: ?[]const u8 = null;
var signin_secret: [64]u8 = undefined;
var signin_secret_len: usize = 0;
/// The same key as an otpauth:// address, for the QR code
var signin_uri: [256]u8 = undefined;
var signin_uri_len: usize = 0;

fn renderSignIn() void {
    const a = beginPage();
    lv.lv_label_set_text(page_title, "termgate");
    // The application's name and what it is, over the card
    const brand = box(content, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_flex_align(brand, lv.LV_FLEX_ALIGN_START, lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER);
    const name = title(brand, "termgate");
    lv.lv_obj_set_style_text_align(name, lv.LV_TEXT_ALIGN_CENTER, 0);
    lv.lv_obj_set_style_text_color(name, lv.lv_color_hex(color_primary), 0);
    const sub = muted(brand, "Terminal access to gateways");
    lv.lv_obj_set_style_text_align(sub, lv.LV_TEXT_ALIGN_CENTER, 0);

    // One card: the title and the fields
    const c = header(content, "Sign in", "").card;
    defer if (signin_msg) |m| {
        signin_msg = null;
        showMsg(.warning, m);
        // Under the card (the name above is the first child here)
        lv.lv_obj_move_to_index(msg_box, 2);
    };
    switch (signin_step) {
        .password => {
            refs.signin_name_ta = field(c, a, "Name", 32, "", null);
            refs.signin_password_ta = field(c, a, "Password", 128, "", null);
            lv.lv_textarea_set_password_mode(refs.signin_password_ta, true);
            const row = box(c, lv.LV_FLEX_FLOW_ROW);
            refs.signin_btn = button(row, "Sign in", onSignIn, null);
        },
        .code, .setup => {
            _ = muted(c, if (signin_step == .setup) "First sign-in: set up the second step." else "Enter the 6-digit code from your authenticator app.");
            if (signin_step == .setup) {
                _ = label(c, "1. Open your authenticator app (Google Authenticator or another) and scan this code:");
                if (signin_uri_len > 0) {
                    // Dark on white with a white edge: what scanners expect
                    const qr = lv.lv_qrcode_create(c);
                    lv.lv_qrcode_set_size(qr, dp(200));
                    lv.lv_qrcode_set_dark_color(qr, lv.lv_color_hex(0x000000));
                    lv.lv_qrcode_set_light_color(qr, lv.lv_color_hex(0xFFFFFF));
                    _ = lv.lv_qrcode_update(qr, &signin_uri, @intCast(signin_uri_len));
                    lv.lv_obj_set_style_border_color(qr, lv.lv_color_hex(0xFFFFFF), 0);
                    lv.lv_obj_set_style_border_width(qr, dp(8), 0);
                    refs.signin_qr = qr;
                }
                _ = label(c, "2. Or add an entry by setup key, named termgate. Key:");
                const key = label(c, zfmt(a, "{s}", .{signin_secret[0..signin_secret_len]}));
                lv.lv_obj_set_style_text_color(key, lv.lv_color_hex(color_primary), 0);
                lv.lv_obj_set_style_text_font(key, font_title, 0);
                _ = label(c, "3. Enter the code the app shows.");
            }
            refs.signin_code_ta = field(c, a, "Code", 6, "", null);
            const row = box(c, lv.LV_FLEX_FLOW_ROW);
            refs.signin_btn = button(row, "Confirm", onSignInCode, null);
            _ = outlineButton(row, "Back", onSignInBack, null, false);
        },
    }
}

fn onSignIn(_: ?*lv.lv_event_t) callconv(.c) void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    const name = std.mem.trim(u8, taText(refs.signin_name_ta), " ");
    switch (session.login(tmp.allocator(), name, taText(refs.signin_password_ta))) {
        .signed_in => return signedIn(),
        .code => signin_step = .code,
        .setup => |s| {
            signin_secret_len = @min(s.secret.len, signin_secret.len);
            @memcpy(signin_secret[0..signin_secret_len], s.secret[0..signin_secret_len]);
            // Too long for the buffer: no QR code, the key is still shown
            signin_uri_len = if (s.uri.len <= signin_uri.len) s.uri.len else 0;
            @memcpy(signin_uri[0..signin_uri_len], s.uri[0..signin_uri_len]);
            signin_step = .setup;
        },
        .failed => |m| {
            // The message outlives the arena: copy it
            const n = @min(m.len, signin_msg_buf.len);
            @memcpy(signin_msg_buf[0..n], m[0..n]);
            signin_msg = signin_msg_buf[0..n];
        },
    }
    renderPage();
}

var signin_msg_buf: [128]u8 = undefined;

fn onSignInCode(_: ?*lv.lv_event_t) callconv(.c) void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    if (session.code(tmp.allocator(), taText(refs.signin_code_ta))) |m| {
        const n = @min(m.len, signin_msg_buf.len);
        @memcpy(signin_msg_buf[0..n], m[0..n]);
        signin_msg = signin_msg_buf[0..n];
        return renderPage();
    }
    signedIn();
}

/// Signed in (with the code, or with the password alone): the panel.
fn signedIn() void {
    signin_step = .password;
    signin_secret_len = 0;
    signin_uri_len = 0;
    if (on_signed_in) |f| f();
    page = firstPage();
    styleMenuItems();
    renderSettings();
    renderPage();
}

fn onSignInBack(_: ?*lv.lv_event_t) callconv(.c) void {
    signin_step = .password;
    renderPage();
}

fn onStopActing(_: ?*lv.lv_event_t) callconv(.c) void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    if (session.userUnselect(tmp.allocator())) |why| return showMsg(.warning, why);
    actingChanged();
}

/// The user started or stopped acting as another: the panel is drawn for
/// whose rights now apply, from its first page.
pub fn actingChanged() void {
    stopWatch();
    history_on = false;
    reloadRights();
    page = firstPage();
    panel_users.reset();
    panel_roles.reset();
    styleMenuItems();
    closeSettings();
    renderSettings();
    renderPage();
}

fn onSignOut(_: ?*lv.lv_event_t) callconv(.c) void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    stopWatch();
    history_on = false;
    session.logout(tmp.allocator());
    page = .nodes;
    panel_users.reset();
    panel_roles.reset();
    styleMenuItems();
    closeSettings();
    renderSettings();
    renderPage();
}

// ---------------------------------------------------------------------------
// Sessions and audit pages

var sessions_msg: ?[]const u8 = null;

fn sessionsSignature() u64 {
    var h = std.hash.Wyhash.init(1);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    defer db_lock.unlock(io);
    const list = db.sessionsActive(tmp.allocator()) catch return 0;
    for (list) |x| h.update(x.sid);
    // Durations shown in minutes
    const minute = @divTrunc(now(), 60);
    h.update(std.mem.asBytes(&minute));
    return h.final();
}

/// "45 s", "12 min", "3 h 5 min"
fn duration(a: Allocator, secs: i64) [*:0]const u8 {
    const d = @max(secs, 0);
    if (d < 60) return zfmt(a, "{d} s", .{d});
    if (d < 3600) return zfmt(a, "{d} min", .{@divTrunc(d, 60)});
    return zfmt(a, "{d} h {d} min", .{ @divTrunc(d, 3600), @divTrunc(@mod(d, 3600), 60) });
}

fn renderSessions() void {
    if (watch != null) return renderWatch();
    const a = beginPage();
    last_signature = sessionsSignature();
    db_lock.lockUncancelable(io);
    const list = db.sessionsActive(a) catch &.{};
    db_lock.unlock(io);

    _ = header(content, "Sessions", zfmt(a, "{d} open now. Sessions end when the user leaves or when you end them.", .{list.len}));
    if (sessions_msg) |m| {
        sessions_msg = null;
        const c = card(content);
        messageLook(c);
        refs.msg_label = label(c, zfmt(a, "{s}", .{m}));
    }
    if (list.len == 0) {
        const c = card(content);
        _ = muted(c, "No open sessions.");
    }
    const t = now();
    for (list, 0..) |x, i| {
        const c = card(content);
        _ = bold(c, zfmt(a, "{s} on {s}", .{ x.person, x.node }));
        _ = muted(c, zfmt(a, "Open for {s}, since {s} · session {s}", .{ duration(a, t - x.started), dateTime(a, x.started), x.sid }));
        const row = box(c, lv.LV_FLEX_FLOW_ROW);
        const w = button(row, "\u{f06e} Watch", onWatch, @ptrFromInt(i + 1));
        const b = outlineButton(row, "End session", onEndSession, @ptrFromInt(i + 1), true);
        if (refs.first_end_btn == null) {
            refs.first_end_btn = b;
            refs.first_watch_btn = w;
        }
    }
}

fn onEndSession(e: ?*lv.lv_event_t) callconv(.c) void {
    const i = @intFromPtr(lv.lv_event_get_user_data(e)) - 1;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const list = db.sessionsActive(tmp.allocator()) catch &.{};
    db_lock.unlock(io);
    if (i >= list.len) return renderPage();
    const x = list[i];
    const svc = service orelse {
        sessions_msg = "termgate is not connected to the relay.";
        return renderPage();
    };
    svc.endSession(x.node, x.user_key, x.sid) catch {
        sessions_msg = "Could not reach the node.";
    };
    renderPage();
}

// --- watching a session (read-only) ----------------------------------------

/// The session being watched; while set, the Sessions page shows it.
var watch: ?*Watch = null;
var watch_title: [160]u8 = undefined;
var watch_title_len: usize = 0;
var watch_timer: ?*lv.lv_timer_t = null;
var watch_seen: u64 = std.math.maxInt(u64);
/// The watched screen as last copied, drawn by onTermDraw
var watch_arena: ?std.heap.ArenaAllocator = null;
var watch_grid: ?vt.Screen.Grid = null;
var watch_state: Watch.State = .connecting;

fn onWatch(e: ?*lv.lv_event_t) callconv(.c) void {
    const i = @intFromPtr(lv.lv_event_get_user_data(e)) - 1;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const list = db.sessionsActive(tmp.allocator()) catch &.{};
    db_lock.unlock(io);
    if (i >= list.len) return renderPage();
    const x = list[i];
    const svc = service orelse {
        sessions_msg = "termgate is not connected to the relay.";
        page = .sessions;
        return renderPage();
    };
    const w = svc.watch(x.node, x.user_key, x.sid) catch {
        sessions_msg = "Could not start watching.";
        page = .sessions;
        return renderPage();
    };
    const t = std.fmt.bufPrint(&watch_title, "{s} on {s}", .{ x.person, x.node }) catch watch_title[0..0];
    openWatch(w, x.sid, t);
}

/// Shows `w` on the Sessions page; the UI owns it from now on.
pub fn openWatch(w: *Watch, sid: []const u8, title_text: []const u8) void {
    stopWatch();
    watch = w;
    setWatchSid(sid);
    const n = @min(title_text.len, watch_title.len);
    std.mem.copyForwards(u8, watch_title[0..n], title_text[0..n]);
    watch_title_len = n;
    watch_seen = std.math.maxInt(u64);
    watch_timer = lv.lv_timer_create(onWatchTimer, 100, null);
    page = .sessions;
    styleMenuItems();
    renderPage();
}

fn stopWatch() void {
    if (watch_timer) |t| lv.lv_timer_delete(t);
    watch_timer = null;
    watch_grid = null;
    if (watch_arena) |*ar| ar.deinit();
    watch_arena = null;
    if (watch) |w| w.stop();
    watch = null;
}

fn onWatchBack(_: ?*lv.lv_event_t) callconv(.c) void {
    stopWatch();
    renderPage();
}

fn onWatchTimer(_: ?*lv.lv_timer_t) callconv(.c) void {
    updateWatch();
}

/// Copies the watched screen into the view when it changed.
pub fn updateWatch() void {
    const w = watch orelse return;
    const term = refs.watch_screen orelse return;
    w.poll();
    const v = w.version.load(.acquire);
    if (v == watch_seen) return;
    watch_seen = v;

    if (watch_arena == null) watch_arena = .init(gpa);
    const ar = &watch_arena.?;
    _ = ar.reset(.retain_capacity);
    w.lock.lockUncancelable(io);
    watch_grid = w.screen.grid(ar.allocator()) catch null;
    w.lock.unlock(io);
    watch_state = w.state.load(.acquire);
    const g = watch_grid orelse return;

    const cw: i32 = @intCast(lv.lv_font_get_glyph_width(font_mono, 'M', 0));
    const ch: i32 = lv.lv_font_get_line_height(font_mono);
    lv.lv_obj_set_size(term, @as(i32, g.cols) * cw, @as(i32, g.rows) * ch);
    if (lv.lv_obj_get_parent(term)) |c| lv.lv_obj_set_style_bg_color(c, lv.lv_color_hex(g.background.hex()), 0);
    _ = lv.lv_obj_invalidate(term);

    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    const a = tmp.allocator();
    const status: [*:0]const u8 = switch (watch_state) {
        .connecting => "Connecting…",
        .live => zfmt(a, "Live from when you started watching · {d}×{d} · read-only: nothing you type is sent", .{ g.cols, g.rows }),
        .ended => "The session has ended.",
        .failed => "The relay connection was lost.",
        .unreadable => "termgate has no keys for this session (it was opened before end-to-end encryption).",
    };
    if (refs.watch_status) |l| lv.lv_label_set_text(l, status);
}

/// Draws the watched screen: per row, runs of cells with the same colors
/// (background, then text), then the cursor.
fn onTermDraw(e: ?*lv.lv_event_t) callconv(.c) void {
    const g = watch_grid orelse return;
    drawGrid(e, g, watch_state == .live);
}

/// A played-back log (the grid is in the page arena, passed as user data).
fn onGridDraw(e: ?*lv.lv_event_t) callconv(.c) void {
    const g: *const vt.Screen.Grid = @ptrCast(@alignCast(lv.lv_event_get_user_data(e) orelse return));
    drawGrid(e, g.*, false);
}

fn drawGrid(e: ?*lv.lv_event_t, g: vt.Screen.Grid, show_cursor: bool) void {
    const obj: ?*lv.lv_obj_t = @ptrCast(lv.lv_event_get_current_target(e));
    const layer = lv.lv_event_get_layer(e);
    var area: lv.lv_area_t = undefined;
    lv.lv_obj_get_coords(obj, &area);
    const cw: i32 = @intCast(lv.lv_font_get_glyph_width(font_mono, 'M', 0));
    const ch: i32 = lv.lv_font_get_line_height(font_mono);
    var buf: [4096]u8 = undefined;

    const screen_h = lv.lv_display_get_vertical_resolution(lv.lv_display_get_default());
    for (0..g.rows) |y| {
        const row = g.cells[y * g.cols ..][0..g.cols];
        const py = area.y1 + @as(i32, @intCast(y)) * ch;
        if (py + ch < 0 or py > screen_h) continue;
        var x: usize = 0;
        while (x < row.len) {
            const first = row[x];
            var end = x;
            var n: usize = 0;
            while (end < row.len and row[end].fg.hex() == first.fg.hex() and row[end].bg.hex() == first.bg.hex() and row[end].underline == first.underline) : (end += 1) {
                const cp = row[end].cp;
                if (cp == 0) continue;
                const len = std.unicode.utf8CodepointSequenceLength(cp) catch continue;
                if (n + len >= buf.len) break;
                _ = std.unicode.utf8Encode(cp, buf[n..][0..len]) catch continue;
                n += len;
            }
            buf[n] = 0;
            const px = area.x1 + @as(i32, @intCast(x)) * cw;
            const w = @as(i32, @intCast(end - x)) * cw;
            if (first.bg.hex() != g.background.hex()) termgate_draw_fill(layer, px, py, w, ch, first.bg.hex(), lv.LV_OPA_COVER);
            if (std.mem.trim(u8, buf[0..n], " ").len > 0 or first.underline)
                termgate_draw_text(layer, font_mono, px, py, w + cw, ch, first.fg.hex(), first.underline, buf[0..n :0].ptr);
            x = end;
        }
    }
    // Rows outside the window are skipped (a played-back log is long)
    if (g.cursor) |c| if (show_cursor) {
        const fg = if (c.y < g.rows and c.x < g.cols) g.cells[@as(usize, c.y) * g.cols + c.x].fg.hex() else 0xE0E0E0;
        termgate_draw_fill(layer, area.x1 + @as(i32, c.x) * cw, area.y1 + @as(i32, c.y) * ch, cw, ch, fg, lv.LV_OPA_50);
    };
}

fn renderWatch() void {
    const a = beginPage();
    const h = header(content, zfmt(a, "{s}", .{watch_title[0..watch_title_len]}), "Watching read-only");
    refs.watch_history_btn = outlineButton(h.actions, "\u{f1da} History", onWatchHistory, null, false);
    refs.watch_back_btn = outlineButton(h.actions, lv.LV_SYMBOL_LEFT ++ " Sessions", onWatchBack, null, false);
    refs.watch_status = muted(h.card, "");

    // A card in the terminal's background color; wide screens scroll
    // sideways inside it
    const c = card(content);
    lv.lv_obj_set_style_bg_color(c, lv.lv_color_hex(0x000000), 0);
    lv.lv_obj_set_scrollable(c, true);
    lv.lv_obj_set_scroll_dir(c, lv.LV_DIR_HOR);
    const term = lv.lv_obj_create(c);
    lv.lv_obj_remove_style_all(term);
    lv.lv_obj_set_scrollable(term, false);
    _ = lv.lv_obj_add_event_cb(term, onTermDraw, lv.LV_EVENT_DRAW_MAIN, null);
    refs.watch_screen = term;
    watch_seen = std.math.maxInt(u64);
    updateWatch();
}

// --- session history (the log) -------------------------------------------

var watch_sid: [64]u8 = undefined;
var watch_sid_len: usize = 0;

fn setWatchSid(sid: []const u8) void {
    watch_sid_len = @min(sid.len, watch_sid.len);
    @memcpy(watch_sid[0..watch_sid_len], sid[0..watch_sid_len]);
}

/// The session whose log is shown; while set, the page shows it.
var history_on = false;
var history_sid: [64]u8 = undefined;
var history_sid_len: usize = 0;
var history_title: [160]u8 = undefined;
var history_title_len: usize = 0;

/// Shows session `sid`'s log over the current page; Back returns to it.
pub fn openHistory(sid: []const u8, title_text: []const u8) void {
    history_sid_len = @min(sid.len, history_sid.len);
    @memcpy(history_sid[0..history_sid_len], sid[0..history_sid_len]);
    history_title_len = @min(title_text.len, history_title.len);
    @memcpy(history_title[0..history_title_len], title_text[0..history_title_len]);
    history_on = true;
    renderPage();
}

fn onWatchHistory(_: ?*lv.lv_event_t) callconv(.c) void {
    openHistory(watch_sid[0..watch_sid_len], watch_title[0..watch_title_len]);
}

fn onHistoryBack(_: ?*lv.lv_event_t) callconv(.c) void {
    history_on = false;
    renderPage();
}

/// History is shown played back in a terminal, or raw: every byte, escape
/// sequences and control characters made visible. A program can hide text
/// from a terminal (write it, then erase it); the raw view shows it all.
var history_raw = false;

fn onHistoryMode(_: ?*lv.lv_event_t) callconv(.c) void {
    history_raw = !history_raw;
    renderPage();
}

fn renderHistory() void {
    const a = beginPage();
    const sid = history_sid[0..history_sid_len];
    db_lock.lockUncancelable(io);
    const cmds = db.commandsOf(a, sid) catch &.{};
    const st = db.settingsGet() catch dbm.Settings{};
    db_lock.unlock(io);
    const h = header(content, zfmt(a, "{s}", .{history_title[0..history_title_len]}), zfmt(a, "Session log · {d} commands · session {s}", .{ cmds.len, sid }));
    refs.history_mode_btn = outlineButton(h.actions, if (history_raw) "Terminal" else "Raw", onHistoryMode, null, false);
    refs.history_back_btn = outlineButton(h.actions, lv.LV_SYMBOL_LEFT ++ " Back", onHistoryBack, null, false);
    refs.history_commands = cmds.len;
    if (cmds.len == 0) {
        const c = card(content);
        _ = muted(c, if (st.log_days > 0) zfmt(a, "Nothing logged (logs are kept {d} days).", .{st.log_days}) else "Nothing logged.");
        return;
    }
    if (history_raw) return renderHistoryRaw(a, cmds);

    // Played back: the outputs in order into a terminal tall enough for
    // all of it; prompts and echoed commands come with them
    var lines: usize = 2;
    for (cmds) |cmd| lines += std.mem.count(u8, cmd.output, "\n") + 2;
    const rows: u16 = @intCast(@min(@max(lines, 24), 5000));
    const scr = vt.Screen.create(gpa, io, 120, rows) catch return;
    defer scr.destroy();
    for (cmds) |cmd| {
        if (!cmd.intact) scr.feed("\r\n\x1b[0;31m[termgate: this part does not decrypt]\x1b[0m\r\n");
        scr.feed(cmd.output);
        const shown: i64 = @intCast(std.unicode.utf8CountCodepoints(cmd.output) catch cmd.output.len);
        if (cmd.output_chars > shown)
            scr.feed(std.mem.span(zfmt(a, "\r\n\x1b[0;33m[termgate: output cut, {d} of {d} characters kept]\x1b[0m\r\n", .{ shown, cmd.output_chars })));
    }
    const g = a.create(vt.Screen.Grid) catch return;
    g.* = scr.grid(a) catch return;
    // Up to the last row with text
    var used: usize = 0;
    for (0..g.rows) |y| {
        for (g.cells[y * g.cols ..][0..g.cols]) |cell| if (cell.cp != ' ' and cell.cp != 0) {
            used = y + 1;
            break;
        };
    }
    refs.history_rows = used;
    const c = card(content);
    lv.lv_obj_set_style_bg_color(c, lv.lv_color_hex(g.background.hex()), 0);
    lv.lv_obj_set_scrollable(c, true);
    lv.lv_obj_set_scroll_dir(c, lv.LV_DIR_HOR);
    const term = lv.lv_obj_create(c);
    lv.lv_obj_remove_style_all(term);
    lv.lv_obj_set_scrollable(term, false);
    const cw: i32 = @intCast(lv.lv_font_get_glyph_width(font_mono, 'M', 0));
    const chh: i32 = lv.lv_font_get_line_height(font_mono);
    lv.lv_obj_set_size(term, @as(i32, g.cols) * cw, @as(i32, @intCast(@max(used, 1))) * chh);
    _ = lv.lv_obj_add_event_cb(term, onGridDraw, lv.LV_EVENT_DRAW_MAIN, g);
    refs.history_grid = g;
}

/// Every byte as it was logged; ESC, CR and other control characters shown
/// as \e, \r, \xNN (a newline is shown and also breaks the line).
fn renderHistoryRaw(a: Allocator, cmds: []const dbm.Command) void {
    const c = card(content);
    // Terminal output: dark in both themes
    lv.lv_obj_set_style_bg_color(c, lv.lv_color_hex(0x000000), 0);
    lv.lv_obj_set_style_pad_row(c, dp(2), 0);
    for (cmds) |cmd| {
        const top = box(c, lv.LV_FLEX_FLOW_ROW);
        lv.lv_obj_set_style_pad_top(top, dp(6), 0);
        const typed = mono(top, if (cmd.line.len > 0) zfmt(a, "typed: {s}", .{escaped(a, cmd.line)}) else "(session start)", 0x8BE9FD);
        lv.lv_obj_set_flex_grow(typed, 1);
        const at = mono(top, dateTime(a, cmd.at), 0x808080);
        lv.lv_obj_set_width(at, lv.LV_SIZE_CONTENT);
        if (!cmd.intact) _ = mono(c, "[does not decrypt: changed in the database, or another key]", 0xFF5555);
        if (cmd.output.len > 0) _ = mono(c, zfmt(a, "{s}", .{escaped(a, cmd.output)}), 0xE0E0E0);
        const shown: i64 = @intCast(std.unicode.utf8CountCodepoints(cmd.output) catch cmd.output.len);
        if (cmd.output_chars > shown)
            _ = mono(c, zfmt(a, "[output cut: {d} of {d} characters kept]", .{ shown, cmd.output_chars }), 0xFFB86C);
    }
}

fn escaped(a: Allocator, bytes: []const u8) []const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (bytes) |b| {
        const r = switch (b) {
            0x1b => out.appendSlice(a, "\\e"),
            '\r' => out.appendSlice(a, "\\r"),
            '\n' => out.appendSlice(a, "\\n\n"),
            '\t' => out.appendSlice(a, "\\t"),
            '\\' => out.appendSlice(a, "\\\\"),
            0...0x08, 0x0b...0x0c, 0x0e...0x1a, 0x1c...0x1f, 0x7f => out.print(a, "\\x{x:0>2}", .{b}),
            else => out.append(a, b),
        };
        r catch break;
    }
    return out.items;
}

/// Monospaced text in a color, wrapping at the card's width.
fn mono(parent: ?*lv.lv_obj_t, s: [*:0]const u8, color: u32) ?*lv.lv_obj_t {
    const l = lv.lv_label_create(parent);
    lv.lv_label_set_text(l, s);
    lv.lv_obj_set_width(l, lv.lv_pct(100));
    lv.lv_obj_set_style_text_font(l, font_mono, 0);
    lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color), 0);
    return l;
}

fn onAuditRow(e: ?*lv.lv_event_t) callconv(.c) void {
    const i = @intFromPtr(lv.lv_event_get_user_data(e)) - 1;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const list = db.sessionsRecent(tmp.allocator(), 200) catch &.{};
    db_lock.unlock(io);
    if (i >= list.len) return;
    const x = list[i];
    var buf: [160]u8 = undefined;
    openHistory(x.sid, std.fmt.bufPrint(&buf, "{s} on {s}", .{ x.person, x.node }) catch "");
}

fn renderAudit() void {
    const a = beginPage();
    db_lock.lockUncancelable(io);
    const list = db.sessionsRecent(a, 200) catch &.{};
    db_lock.unlock(io);
    _ = header(content, "Audit", "Every session termgate approved, newest first (last 200). Select one for its log.");
    refs.audit_rows = list.len;
    if (list.len == 0) {
        const c = card(content);
        _ = muted(c, "No sessions yet.");
        return renderActions(a);
    }
    const c = card(content);
    lv.lv_obj_set_style_pad_row(c, dp(2), 0);
    _ = auditRow(c, a, "Started", "Who", "Node", "Duration", "Result", true);
    const t = now();
    for (list, 0..) |x, i| {
        const dur: [*:0]const u8 = if (x.ended) |e| duration(a, e - x.started) else zfmt(a, "{s} so far", .{duration(a, t - x.started)});
        const result: [*:0]const u8 = if (x.ended == null) "open" else if (x.exit_status) |st| (if (st == 0) "ended" else zfmt(a, "ended (status {d})", .{st})) else "ended";
        // A row opens the session's log
        const row = auditRow(c, a, dateTime(a, x.started), zfmt(a, "{s}", .{x.person}), zfmt(a, "{s}", .{x.node}), dur, result, false);
        lv.lv_obj_set_clickable(row, true);
        _ = lv.lv_obj_add_event_cb(row, onAuditRow, lv.LV_EVENT_CLICKED, @ptrFromInt(i + 1));
        if (refs.first_audit_row == null) refs.first_audit_row = row;
    }
    renderActions(a);
}

/// What an API call is in words.
fn actionText(call: []const u8) []const u8 {
    const names = [_][2][]const u8{
        .{ "login", "sign-in" },
        .{ "db.nodeCreate", "created node" },
        .{ "db.nodeNewToken", "new node key for" },
        .{ "db.nodeApprove", "approved node" },
        .{ "db.nodeReject", "rejected node" },
        .{ "db.nodeSetDisabled", "disabled/enabled node" },
        .{ "db.nodeDelete", "deleted node" },
        .{ "db.personInvite", "invited" },
        .{ "db.personRevoke", "revoked access of" },
        .{ "db.settingsSet", "changed settings" },
        .{ "svc.endSession", "ended" },
        .{ "svc.kickNode", "closed connection of node" },
        .{ "svc.kickUser", "closed connection of key" },
        .{ "users.create", "added user" },
        .{ "users.update", "changed user" },
        .{ "users.reset", "new password for user" },
        .{ "users.delete", "deleted user" },
        .{ "users.grant", "gave a role to" },
        .{ "users.revoke", "took a role from" },
        .{ "roles.insert", "added role" },
        .{ "roles.update", "changed role" },
        .{ "roles.delete", "deleted role" },
    };
    for (names) |n| if (std.mem.eql(u8, n[0], call)) return n[1];
    return call;
}

/// What panel users did (web panel): every change and every sign-in.
fn renderActions(a: Allocator) void {
    db_lock.lockUncancelable(io);
    const list = db.actionsRecent(a, 100) catch &.{};
    db_lock.unlock(io);
    refs.action_rows = list.len;
    if (list.len == 0) return;
    const c = card(content);
    lv.lv_obj_set_style_pad_row(c, dp(2), 0);
    _ = bold(c, "Panel activity (last 100): who did what");
    for (list) |x| {
        const row = box(c, lv.LV_FLEX_FLOW_ROW);
        lv.lv_obj_set_style_pad_ver(row, dp(3), 0);
        const texts = [_][*:0]const u8{
            dateTime(a, x.at),
            zfmt(a, "{s}", .{if (x.user.len > 0) x.user else "-"}),
            if (std.mem.eql(u8, x.call, "login"))
                (if (x.ok) "signed in" else zfmt(a, "sign-in failed ({s})", .{x.detail}))
            else
                zfmt(a, "{s} {s}", .{ actionText(x.call), x.detail }),
            if (x.ok) "ok" else "denied",
        };
        // Narrow enough for a phone
        const widths = [_]i32{ 24, 13, 47, 14 };
        for (texts, widths, 0..) |txt, w, i| {
            const l = lv.lv_label_create(row);
            lv.lv_label_set_text(l, txt);
            lv.lv_label_set_long_mode(l, lv.LV_LABEL_LONG_MODE_DOTS);
            lv.lv_obj_set_width(l, lv.lv_pct(w));
            lv.lv_obj_set_style_text_font(l, font_small, 0);
            if (i == 3 and !x.ok) lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color_danger), 0);
        }
    }
}

fn auditRow(parent: ?*lv.lv_obj_t, a: Allocator, started: [*:0]const u8, who: [*:0]const u8, node: [*:0]const u8, dur: [*:0]const u8, result: [*:0]const u8, head: bool) ?*lv.lv_obj_t {
    _ = a;
    const row = box(parent, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_ver(row, dp(4), 0);
    const widths = [_]i32{ 26, 22, 22, 14, 16 };
    const texts = [_][*:0]const u8{ started, who, node, dur, result };
    for (texts, widths) |txt, w| {
        const l = lv.lv_label_create(row);
        lv.lv_label_set_text(l, txt);
        lv.lv_label_set_long_mode(l, lv.LV_LABEL_LONG_MODE_DOTS);
        lv.lv_obj_set_width(l, lv.lv_pct(w));
        if (head) lv.lv_obj_set_style_text_font(l, font_bold, 0) else lv.lv_obj_set_style_text_font(l, font_small, 0);
    }
    return row;
}

// ---------------------------------------------------------------------------
// People page

const PeopleMode = enum { list, form, created };
var people_mode: PeopleMode = .list;
var people_msg: ?[]const u8 = null;
var confirm_revoke: i64 = 0;
const invitation_lifetime_s = 7 * 86400;

fn renderPeople() void {
    const a = beginPage();
    switch (people_mode) {
        .list => renderPeopleList(a),
        .form => renderInviteForm(a),
        .created => renderInviteCreated(a),
    }
}

fn showPeopleMsg(a: Allocator) void {
    const m = people_msg orelse return;
    people_msg = null;
    const c = card(content);
    messageLook(c);
    refs.msg_label = label(c, zfmt(a, "{s}", .{m}));
}

fn renderPeopleList(a: Allocator) void {
    db_lock.lockUncancelable(io);
    const people = db.personList(a) catch {
        db_lock.unlock(io);
        _ = header(content, "People", "Database error.");
        return;
    };
    db_lock.unlock(io);

    var active: usize = 0;
    var open: usize = 0;
    for (people) |p| {
        if (p.revoked) continue;
        if (p.user_key != null) active += 1 else open += 1;
    }
    const h = header(content, "People", zfmt(a, "{d} people · {d} active · {d} invitations not used yet", .{ people.len, active, open }));
    refs.invite_btn = button(h.actions, lv.LV_SYMBOL_PLUS ++ " Invite", onInvite, null);
    showPeopleMsg(a);

    const t = now();
    for (people) |p| {
        const c = card(content);
        const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
        const name = bold(top_row, zfmt(a, "{s}", .{p.name}));
        lv.lv_obj_set_width(name, lv.LV_SIZE_CONTENT);
        if (p.kind == .bot) _ = chip(top_row, "bot", 0x6A1B9A);
        if (p.revoked) {
            _ = chip(top_row, "revoked", color_danger);
        } else if (p.user_key == null) {
            const expired = if (p.token_expires) |e| t >= e else true;
            _ = chip(top_row, if (expired) "invitation expired" else "invited", if (expired) color_dim else color_primary);
        } else {
            _ = chip(top_row, "active", color_success);
        }
        const shown = std.mem.replaceOwned(u8, a, p.nodes, ",", ", ") catch p.nodes;
        _ = label(c, zfmt(a, "Nodes {s} · runs as {s}", .{ shown, p.run_as }));
        _ = muted(c, limitsText(a, p));
        if (p.user_key == null and !p.revoked) {
            _ = muted(c, zfmt(a, "Invitation valid until {s}", .{dateTime(a, p.token_expires)}));
        } else if (p.user_key) |k| {
            _ = muted(c, zfmt(a, "Key {s}", .{k}));
        }
        if (!p.revoked) {
            const row = box(c, lv.LV_FLEX_FLOW_ROW);
            const text: [*:0]const u8 = if (confirm_revoke == p.id) "Tap again to revoke" else if (p.user_key == null) "Cancel invitation" else "Revoke access";
            const b = outlineButton(row, text, onRevoke, idPtr(p.id), true);
            if (refs.first_revoke_btn == null) refs.first_revoke_btn = b;
        }
    }
}

/// "3 of 5 sessions used · until 2026-12-01 10:00 UTC"
fn limitsText(a: Allocator, p: dbm.Person) [*:0]const u8 {
    const uses = p.uses orelse 0;
    const sessions: []const u8 = if (p.max_uses) |m|
        std.fmt.allocPrint(a, "{d} of {d} sessions used", .{ uses, m }) catch ""
    else
        std.fmt.allocPrint(a, "{d} sessions used, no limit on the number", .{uses}) catch "";
    if (p.grant_exp) |e| return zfmt(a, "{s} · until {s}", .{ sessions, dateTime(a, e) });
    return zfmt(a, "{s} · no end date", .{sessions});
}

fn renderInviteForm(a: Allocator) void {
    _ = header(content, "Invite", "One invitation is for one person or bot. Choose which nodes, as which user, and how often or until when.");
    showPeopleMsg(a);
    const c = card(content);
    refs.inv_name_ta = field(c, a, "Name", 100, "", "Who this is for, e.g. Ali Yilmaz or backup-bot");
    refs.inv_bot_cb = lv.lv_checkbox_create(c);
    lv.lv_checkbox_set_text(refs.inv_bot_cb, "This is a bot (AI agent or script)");
    refs.inv_nodes_ta = field(c, a, "Nodes", 200, "", "Node names or patterns, comma separated: ist_*, pump?? (* any run, ? one character)");
    refs.inv_run_as_ta = field(c, a, "Run as", 32, "root", "Unix user the shell runs as on the node");
    refs.inv_uses_ta = field(c, a, "Sessions", 6, "", "How many sessions in total (empty: no limit on the number)");
    refs.inv_days_ta = field(c, a, "Valid for days", 6, "", "Access ends after this many days (empty: no end date). At least one of the two is needed.");
    const row = box(c, lv.LV_FLEX_FLOW_ROW);
    refs.inv_create_btn = button(row, "Create invitation", onCreateInvitation, null);
    _ = outlineButton(row, "Cancel", onPeopleBack, null, false);
}

fn renderInviteCreated(a: Allocator) void {
    const name = created_name[0..created_name_len];
    const code = created_code[0..created_code_len];
    _ = header(content, zfmt(a, "Invitation for {s}", .{name}), "Shown once. Valid for 7 days, for one use.");
    const c = card(content);
    _ = bold(c, "Send this to them; they run it once (add a node name to open a terminal right away):");
    const cmd = label(c, zfmt(a, "tgterm --invite {s}", .{code}));
    lv.lv_obj_set_style_text_font(cmd, font_small, 0);
    refs.code_label = cmd;
    _ = muted(c, "tgterm creates their key on their machine; the invitation ties it to them. After that \"tgterm <node>\" is enough.");
    const row = box(c, lv.LV_FLEX_FLOW_ROW);
    _ = button(row, lv.LV_SYMBOL_COPY ++ " Copy command", onCopyInvite, null);
    refs.done_btn = outlineButton(row, "Done", onPeopleBack, null, false);
}

fn setPeopleMode(m: PeopleMode) void {
    people_mode = m;
    renderPage();
}

fn onInvite(_: ?*lv.lv_event_t) callconv(.c) void {
    setPeopleMode(.form);
}

fn onPeopleBack(_: ?*lv.lv_event_t) callconv(.c) void {
    setPeopleMode(.list);
}

fn parseOptionalNumber(text: []const u8) error{Invalid}!?u32 {
    const t = std.mem.trim(u8, text, " ");
    if (t.len == 0) return null;
    const n = std.fmt.parseInt(u32, t, 10) catch return error.Invalid;
    if (n == 0) return error.Invalid;
    return n;
}

fn onCreateInvitation(_: ?*lv.lv_event_t) callconv(.c) void {
    const a = arena.allocator();
    const name = std.mem.trim(u8, taText(refs.inv_name_ta), " ");
    const run_as = std.mem.trim(u8, taText(refs.inv_run_as_ta), " ");
    // "ist_*, pump??" -> "ist_*,pump??"
    var nodes: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, taText(refs.inv_nodes_ta), ',');
    while (it.next()) |raw| {
        const pat = std.mem.trim(u8, raw, " ");
        if (pat.len == 0) continue;
        if (nodes.items.len > 0) nodes.append(a, ',') catch return;
        nodes.appendSlice(a, pat) catch return;
    }
    const uses = parseOptionalNumber(taText(refs.inv_uses_ta)) catch {
        people_msg = "Sessions must be a positive number or empty.";
        return renderPage();
    };
    const days = parseOptionalNumber(taText(refs.inv_days_ta)) catch {
        people_msg = "Valid for days must be a positive number or empty.";
        return renderPage();
    };
    if (name.len == 0 or nodes.items.len == 0 or run_as.len == 0) {
        people_msg = "Name, nodes and run as are needed.";
        return renderPage();
    }
    if (uses == null and days == null) {
        people_msg = "Give a number of sessions, a number of days, or both.";
        return renderPage();
    }
    const is_bot = lv.lv_obj_has_state(refs.inv_bot_cb, lv.LV_STATE_CHECKED);
    const text = makeCode(name) catch |e| {
        people_msg = if (e == error.NoRelay) "The relay is not configured yet (see Settings)." else "Could not create the invitation.";
        return renderPage();
    };
    const parsed = core.code.parse(text) catch return;
    const th = dbm.tokenHash(parsed.token);
    db_lock.lockUncancelable(io);
    const res = db.personInvite(.{
        .name = name,
        .kind = if (is_bot) .bot else .human,
        .nodes = nodes.items,
        .run_as = run_as,
        .max_uses = uses,
        .grant_exp = if (days) |d| now() + @as(i64, d) * 86400 else null,
    }, &th, now() + invitation_lifetime_s, now());
    db_lock.unlock(io);
    _ = res catch |e| {
        people_msg = if (e == error.InvalidSpec) "Check the node patterns: lowercase letters, digits, _, * and ?." else "Database error.";
        return renderPage();
    };
    setPeopleMode(.created);
}

fn onRevoke(e: ?*lv.lv_event_t) callconv(.c) void {
    const id = eventId(e);
    if (confirm_revoke != id) {
        confirm_revoke = id;
        return renderPage();
    }
    confirm_revoke = 0;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const key = if (db.personGet(tmp.allocator(), id) catch null) |p| p.user_key else null;
    db.personRevoke(id) catch {};
    db_lock.unlock(io);
    // The callout refuses them from now on; close what is open
    if (key) |k| if (service) |s| s.kickUser(k);
    renderPage();
}

fn onCopyInvite(_: ?*lv.lv_event_t) callconv(.c) void {
    var buf: [400]u8 = undefined;
    const cmd = std.fmt.bufPrintSentinel(&buf, "tgterm --invite {s}", .{created_code[0..created_code_len]}, 0) catch return;
    if (copy_text) |f| f(cmd.ptr);
}

// ---------------------------------------------------------------------------
// Nodes page

const NodesMode = enum { list, form, created, info };
/// The node the info view shows
var info_id: i64 = 0;
var nodes_mode: NodesMode = .list;
/// The node key just created (shown once)
var created_code: [256]u8 = undefined;
var created_code_len: usize = 0;
var created_name: [64]u8 = undefined;
var created_name_len: usize = 0;
var nodes_msg: ?[]const u8 = null;
/// Node id waiting for a second tap on Delete
var confirm_delete: i64 = 0;

/// Changes when anything a node card shows changes.
fn nodesSignature() u64 {
    var h = std.hash.Wyhash.init(0);
    db_lock.lockUncancelable(io);
    defer db_lock.unlock(io);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    const nodes = db.nodeList(tmp.allocator()) catch return 0;
    const t = now();
    for (nodes) |n| {
        h.update(n.name);
        h.update(std.mem.asBytes(&n.state));
        h.update(n.request_key orelse "");
        h.update(n.status orelse "");
        h.update(std.mem.asBytes(&n.online));
        // "x min ago" changes every minute
        const bucket: i64 = if (n.online) -2 else if (n.last_seen) |ls| @divTrunc(t - ls, 60) else -1;
        h.update(std.mem.asBytes(&bucket));
    }
    return h.final();
}

fn renderNodes() void {
    const a = beginPage();
    switch (nodes_mode) {
        .list => renderNodeList(a),
        .form => renderNodeForm(a),
        .created => renderNodeCreated(a),
        .info => renderNodeInfo(a),
    }
}

fn renderNodeList(a: Allocator) void {
    last_signature = nodesSignature();
    db_lock.lockUncancelable(io);
    const nodes = db.nodeList(a) catch {
        db_lock.unlock(io);
        _ = header(content, "Nodes", "Database error.");
        return;
    };
    db_lock.unlock(io);

    var online: usize = 0;
    var pending: usize = 0;
    for (nodes) |n| {
        if (n.state == .pending) pending += 1;
        if (n.state == .approved and n.online) online += 1;
    }
    const h = header(content, "Nodes", zfmt(a, "{d} nodes · {d} online · {d} waiting for approval", .{ nodes.len, online, pending }));
    refs.new_node_btn = button(h.actions, lv.LV_SYMBOL_PLUS ++ " New node", onNewNode, null);
    showNodesMsg(a);

    // Registration requests first
    for (nodes) |n| {
        if (n.state != .pending) continue;
        const c = card(content);
        lv.lv_obj_set_style_border_side(c, lv.LV_BORDER_SIDE_LEFT, 0);
        lv.lv_obj_set_style_border_width(c, dp(4), 0);
        lv.lv_obj_set_style_border_color(c, lv.lv_color_hex(color_warning), 0);
        _ = bold(c, zfmt(a, "{s} asks to register", .{n.name}));
        _ = muted(c, zfmt(a, "Hardware key {s}", .{n.request_key orelse ""}));
        _ = muted(c, "Check it on the device with: tgnode id");
        if (parseStatus(a, n.status)) |st| statusLines(c, a, st);
        const row = box(c, lv.LV_FLEX_FLOW_ROW);
        const ok = button(row, lv.LV_SYMBOL_OK ++ " Approve", onApprove, idPtr(n.id));
        const no = outlineButton(row, "Reject", onReject, idPtr(n.id), true);
        if (refs.first_approve_btn == null) {
            refs.first_approve_btn = ok;
            refs.first_reject_btn = no;
        }
    }

    for (nodes) |n| {
        if (n.state == .pending) continue;
        const c = card(content);
        // The card opens the node's info; its buttons keep their own action
        lv.lv_obj_set_clickable(c, true);
        _ = lv.lv_obj_add_event_cb(c, onNodeCard, lv.LV_EVENT_CLICKED, idPtr(n.id));
        if (refs.first_node_card == null) refs.first_node_card = c;
        const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
        const name = bold(top_row, zfmt(a, "{s}", .{n.name}));
        lv.lv_obj_set_width(name, lv.LV_SIZE_CONTENT);
        const is_online = n.state == .approved and n.online;
        switch (n.state) {
            .approved => _ = chip(top_row, if (is_online) "online" else "offline", if (is_online) color_success else color_dim),
            .waiting => _ = chip(top_row, "waiting for the device", color_primary),
            .disabled => _ = chip(top_row, "disabled", color_danger),
            .pending => {},
        }
        if (n.description.len > 0) _ = label(c, zfmt(a, "{s}", .{n.description}));
        if (parseStatus(a, n.status)) |st| statusLines(c, a, st);
        switch (n.state) {
            .waiting => _ = muted(c, zfmt(a, "Node key valid until {s}", .{dateTime(a, n.token_expires)})),
            else => if (!is_online) {
                _ = muted(c, zfmt(a, "Last seen {s}", .{ago(a, n.last_seen)}));
            },
        }
        const row = box(c, lv.LV_FLEX_FLOW_ROW);
        switch (n.state) {
            .approved => _ = outlineButton(row, "Disable", onToggleDisabled, idPtr(n.id), false),
            .disabled => _ = outlineButton(row, "Enable", onToggleDisabled, idPtr(n.id), false),
            else => {},
        }
        _ = outlineButton(row, "New node key", onNewNodeKey, idPtr(n.id), false);
        _ = outlineButton(row, if (confirm_delete == n.id) "Tap again to delete" else "Delete", onDeleteNode, idPtr(n.id), true);
    }
}

// --- node info ---------------------------------------------------------------

fn onNodeCard(e: ?*lv.lv_event_t) callconv(.c) void {
    info_id = eventId(e);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const n = db.nodeGet(tmp.allocator(), info_id) catch null;
    db_lock.unlock(io);
    // Fresh system info if it is online; it arrives within a moment
    if (n) |x| if (x.online) if (service) |s| s.requestStatusOf(x.name);
    setNodesMode(.info);
}

fn onNodeRefresh(_: ?*lv.lv_event_t) callconv(.c) void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const n = db.nodeGet(tmp.allocator(), info_id) catch null;
    db_lock.unlock(io);
    const x = n orelse return;
    if (!x.online) {
        nodes_msg = "The node is offline; it reports when it connects.";
    } else if (service) |s| {
        s.requestStatusOf(x.name);
    } else nodes_msg = "termgate is not connected to the relay.";
    renderPage();
}

/// Changes when anything the info view shows changes.
fn nodeInfoSignature() u64 {
    var h = std.hash.Wyhash.init(2);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    const a = tmp.allocator();
    db_lock.lockUncancelable(io);
    defer db_lock.unlock(io);
    const n = (db.nodeGet(a, info_id) catch return 0) orelse return 1;
    h.update(std.mem.asBytes(&n.state));
    h.update(std.mem.asBytes(&n.online));
    h.update(n.status orelse "");
    h.update(n.request_key orelse "");
    const bucket: i64 = if (n.online) -2 else if (n.last_seen) |ls| @divTrunc(now() - ls, 60) else -1;
    h.update(std.mem.asBytes(&bucket));
    const list = db.sessionsOfNode(a, n.name, 20) catch return 0;
    for (list) |x| {
        h.update(x.sid);
        h.update(std.mem.asBytes(&x.ended));
    }
    const minute = @divTrunc(now(), 60);
    h.update(std.mem.asBytes(&minute));
    return h.final();
}

/// "3 days 4 h", "5 h 12 min", "8 min"
fn uptime(a: Allocator, secs: u64) [*:0]const u8 {
    if (secs >= 86400) return zfmt(a, "{d} days {d} h", .{ secs / 86400, (secs % 86400) / 3600 });
    return duration(a, @intCast(secs));
}

/// One "name  value" line of the info view.
fn infoRow(parent: ?*lv.lv_obj_t, name: [*:0]const u8, value: [*:0]const u8) ?*lv.lv_obj_t {
    const row = box(parent, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_row(row, 0, 0);
    const k = muted(row, name);
    lv.lv_obj_set_width(k, lv.lv_pct(28));
    const v = label(row, value);
    lv.lv_obj_set_width(v, lv.lv_pct(68));
    return v;
}

fn renderNodeInfo(a: Allocator) void {
    last_signature = nodeInfoSignature();
    db_lock.lockUncancelable(io);
    const found = db.nodeGet(a, info_id) catch null;
    const active = db.sessionsActive(a) catch &.{};
    const recent = if (found) |n| db.sessionsOfNode(a, n.name, 20) catch &.{} else &.{};
    db_lock.unlock(io);
    const n = found orelse {
        nodes_mode = .list;
        return renderNodes();
    };

    const h = header(content, zfmt(a, "{s}", .{n.name}), if (n.description.len > 0) zfmt(a, "{s}", .{n.description}) else "No description");
    refs.node_back_btn = outlineButton(h.actions, lv.LV_SYMBOL_LEFT ++ " Nodes", onNodesBack, null, false);
    showNodesMsg(a);

    // Connection and registration
    {
        const c = card(content);
        const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
        const t = bold(top_row, "Connection");
        lv.lv_obj_set_width(t, lv.LV_SIZE_CONTENT);
        const is_online = n.state == .approved and n.online;
        refs.node_state_chip = switch (n.state) {
            .approved => chip(top_row, if (is_online) "online" else "offline", if (is_online) color_success else color_dim),
            .waiting => chip(top_row, "waiting for the device", color_primary),
            .pending => chip(top_row, "waiting for approval", color_warning),
            .disabled => chip(top_row, "disabled", color_danger),
        };
        if (n.state == .approved or n.state == .disabled)
            _ = infoRow(c, "Last seen", if (is_online) "connected now" else zfmt(a, "{s} ({s})", .{ ago(a, n.last_seen), dateTime(a, n.last_seen) }));
        _ = infoRow(c, "Hardware key", zfmt(a, "{s}", .{n.hardware_key orelse n.request_key orelse "-"}));
        _ = infoRow(c, "Added", dateTime(a, n.created));
        if (n.state == .waiting) _ = infoRow(c, "Node key valid until", dateTime(a, n.token_expires));
    }

    // System info, as the node last reported it
    {
        const c = card(content);
        const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
        const t = bold(top_row, "System");
        lv.lv_obj_set_width(t, lv.LV_SIZE_CONTENT);
        lv.lv_obj_set_flex_grow(t, 1);
        refs.node_refresh_btn = outlineButton(top_row, lv.LV_SYMBOL_REFRESH ++ " Refresh", onNodeRefresh, null, false);
        if (parseStatus(a, n.status)) |st| {
            refs.node_hostname = infoRow(c, "Hostname", zfmt(a, "{s}", .{st.hostname}));
            _ = infoRow(c, "Operating system", zfmt(a, "{s}", .{st.os}));
            _ = infoRow(c, "Kernel", zfmt(a, "{s} ({s})", .{ st.kernel, st.arch }));
            _ = infoRow(c, "CPUs", zfmt(a, "{d} · load {d:.2} {d:.2} {d:.2}", .{ st.cpus, st.load[0], st.load[1], st.load[2] }));
            _ = infoRow(c, "Uptime", uptime(a, st.uptime_s));
            const mem_used = st.mem_total_kb -| st.mem_available_kb;
            const mem_pct = if (st.mem_total_kb > 0) mem_used * 100 / st.mem_total_kb else 0;
            _ = infoRow(c, "Memory", zfmt(a, "{d:.1} of {d:.1} GB used ({d}%)", .{ gb(mem_used), gb(st.mem_total_kb), mem_pct }));
            const disk_used = st.disk_total_bytes -| st.disk_free_bytes;
            const disk_pct = if (st.disk_total_bytes > 0) disk_used * 100 / st.disk_total_bytes else 0;
            _ = infoRow(c, "Disk (/)", zfmt(a, "{d:.1} GB free of {d:.1} GB ({d}% used)", .{
                @as(f64, @floatFromInt(st.disk_free_bytes)) / 1e9,
                @as(f64, @floatFromInt(st.disk_total_bytes)) / 1e9,
                disk_pct,
            }));
            _ = infoRow(c, "tgnode", zfmt(a, "{s}", .{st.version}));
        } else _ = muted(c, "The node has not reported yet.");
    }

    // Sessions on this node
    {
        const c = card(content);
        _ = bold(c, "Open sessions");
        var open: usize = 0;
        const t = now();
        for (active, 0..) |x, i| {
            if (!std.mem.eql(u8, x.node, n.name)) continue;
            open += 1;
            const row = box(c, lv.LV_FLEX_FLOW_ROW);
            const l = label(row, zfmt(a, "{s} · open for {s}", .{ x.person, duration(a, t - x.started) }));
            lv.lv_obj_set_flex_grow(l, 1);
            // Index into the active list, as on the Sessions page
            _ = button(row, "\u{f06e} Watch", onWatch, @ptrFromInt(i + 1));
            _ = outlineButton(row, "End", onEndSession, @ptrFromInt(i + 1), true);
        }
        refs.node_sessions = open;
        if (open == 0) _ = muted(c, "None.");

        if (recent.len > 0) {
            _ = bold(c, "Recent sessions");
            for (recent) |x| {
                const dur: [*:0]const u8 = if (x.ended) |e| duration(a, e - x.started) else "open";
                _ = muted(c, zfmt(a, "{s} · {s} · {s}", .{ dateTime(a, x.started), x.person, dur }));
            }
        }
    }

    // What the admin can do
    {
        const c = card(content);
        const row = box(c, lv.LV_FLEX_FLOW_ROW);
        switch (n.state) {
            .approved => _ = outlineButton(row, "Disable", onToggleDisabled, idPtr(n.id), false),
            .disabled => _ = outlineButton(row, "Enable", onToggleDisabled, idPtr(n.id), false),
            else => {},
        }
        _ = outlineButton(row, "New node key", onNewNodeKey, idPtr(n.id), false);
        _ = outlineButton(row, if (confirm_delete == n.id) "Tap again to delete" else "Delete", onDeleteNode, idPtr(n.id), true);
    }
}

fn renderNodeForm(a: Allocator) void {
    const h = header(content, "New node", "Give the device a name; the node key you get next registers it.");
    _ = h;
    showNodesMsg(a);
    const c = card(content);
    refs.node_name_ta = field(c, a, "Name", core.node.max_len, "", "Lowercase letters, digits and _, starting with a letter: ist_kadikoy_gw01");
    refs.node_desc_ta = field(c, a, "Description", 200, "", "Where it is, what it does (optional)");
    const row = box(c, lv.LV_FLEX_FLOW_ROW);
    refs.node_create_btn = button(row, "Create", onCreateNode, null);
    _ = outlineButton(row, "Cancel", onNodesBack, null, false);
}

fn renderNodeCreated(a: Allocator) void {
    const name = created_name[0..created_name_len];
    const code = created_code[0..created_code_len];
    _ = header(content, zfmt(a, "Node key for {s}", .{name}), "Shown once. Valid for 24 hours, for one registration.");
    const c = card(content);
    _ = bold(c, "On the device, run tgnode once with this key:");
    const cmd = label(c, zfmt(a, "tgnode --registration {s}", .{code}));
    lv.lv_obj_set_style_text_font(cmd, font_small, 0);
    refs.code_label = cmd;
    _ = muted(c, "The device then appears here with its hardware key and asks to register; approve it to finish.");
    const row = box(c, lv.LV_FLEX_FLOW_ROW);
    _ = button(row, lv.LV_SYMBOL_COPY ++ " Copy command", onCopyCommand, null);
    refs.done_btn = outlineButton(row, "Done", onNodesBack, null, false);
}

fn showNodesMsg(a: Allocator) void {
    const m = nodes_msg orelse return;
    nodes_msg = null;
    const c = card(content);
    messageLook(c);
    refs.msg_label = label(c, zfmt(a, "{s}", .{m}));
}

pub fn dateTime(a: Allocator, t: ?i64) [*:0]const u8 {
    const v = t orelse return "-";
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(v, 0)) };
    const day = es.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    const ds = es.getDaySeconds();
    return zfmt(a, "{d}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2} UTC", .{ day.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour() });
}

pub fn idPtr(id: i64) ?*anyopaque {
    return @ptrFromInt(@as(usize, @intCast(id)));
}

fn eventId(e: ?*lv.lv_event_t) i64 {
    return @intCast(@intFromPtr(lv.lv_event_get_user_data(e)));
}

fn setNodesMode(m: NodesMode) void {
    nodes_mode = m;
    renderPage();
}

fn onNewNode(_: ?*lv.lv_event_t) callconv(.c) void {
    setNodesMode(.form);
}

fn onNodesBack(_: ?*lv.lv_event_t) callconv(.c) void {
    setNodesMode(.list);
}

/// A new node key for `name`'s record: random token, its hash stored.
fn makeCode(name: []const u8) ![]const u8 {
    const r = relay orelse return error.NoRelay;
    var tok: [32]u8 = undefined;
    io.random(&tok);
    const text = try core.code.format(arena.allocator(), r.host, r.port, r.ca_fingerprint, tok);
    if (text.len > created_code.len or name.len > created_name.len) return error.TooLong;
    @memcpy(created_code[0..text.len], text);
    created_code_len = text.len;
    @memcpy(created_name[0..name.len], name);
    created_name_len = name.len;
    return text;
}

const node_key_lifetime_s = 24 * 3600;

fn onCreateNode(_: ?*lv.lv_event_t) callconv(.c) void {
    const name = std.mem.trim(u8, taText(refs.node_name_ta), " ");
    const desc = std.mem.trim(u8, taText(refs.node_desc_ta), " ");
    if (!core.node.isValidName(name)) {
        nodes_msg = "The name must be lowercase letters, digits and _, start with a letter, at most 63 characters.";
        return renderPage();
    }
    const text = makeCode(name) catch |e| {
        nodes_msg = if (e == error.NoRelay) "The relay is not configured yet (see Settings)." else "Could not create the node key.";
        return renderPage();
    };
    const parsed = core.code.parse(text) catch return;
    const th = dbm.tokenHash(parsed.token);
    db_lock.lockUncancelable(io);
    const res = db.nodeCreate(name, desc, &th, now() + node_key_lifetime_s, now());
    db_lock.unlock(io);
    _ = res catch |e| {
        nodes_msg = if (e == error.Duplicate) "A node with this name exists already." else "Database error.";
        return renderPage();
    };
    setNodesMode(.created);
}

fn onNewNodeKey(e: ?*lv.lv_event_t) callconv(.c) void {
    const id = eventId(e);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const n = (db.nodeGet(tmp.allocator(), id) catch null) orelse {
        db_lock.unlock(io);
        return;
    };
    db_lock.unlock(io);
    const text = makeCode(n.name) catch |err| {
        nodes_msg = if (err == error.NoRelay) "The relay is not configured yet (see Settings)." else "Could not create the node key.";
        return renderPage();
    };
    const parsed = core.code.parse(text) catch return;
    const th = dbm.tokenHash(parsed.token);
    db_lock.lockUncancelable(io);
    db.nodeNewToken(id, &th, now() + node_key_lifetime_s) catch {};
    db_lock.unlock(io);
    setNodesMode(.created);
}

fn onApprove(e: ?*lv.lv_event_t) callconv(.c) void {
    db_lock.lockUncancelable(io);
    db.nodeApprove(eventId(e)) catch |err| {
        nodes_msg = if (err == error.Duplicate) "This hardware key is already registered as another node." else "Could not approve.";
    };
    db_lock.unlock(io);
    renderPage();
}

fn onReject(e: ?*lv.lv_event_t) callconv(.c) void {
    db_lock.lockUncancelable(io);
    db.nodeReject(eventId(e)) catch {};
    db_lock.unlock(io);
    renderPage();
}

fn onToggleDisabled(e: ?*lv.lv_event_t) callconv(.c) void {
    const id = eventId(e);
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const n = db.nodeGet(tmp.allocator(), id) catch null;
    if (n) |x| db.nodeSetDisabled(id, x.state != .disabled) catch {};
    db_lock.unlock(io);
    if (n) |x| if (x.state == .approved) if (service) |s| s.kickNode(x.name);
    renderPage();
}

fn onDeleteNode(e: ?*lv.lv_event_t) callconv(.c) void {
    const id = eventId(e);
    if (confirm_delete != id) {
        confirm_delete = id;
        return renderPage();
    }
    confirm_delete = 0;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    db_lock.lockUncancelable(io);
    const n = db.nodeGet(tmp.allocator(), id) catch null;
    db.nodeDelete(id) catch {};
    db_lock.unlock(io);
    if (n) |x| if (x.state == .approved) if (service) |s| s.kickNode(x.name);
    renderPage();
}

fn onCopyCommand(_: ?*lv.lv_event_t) callconv(.c) void {
    var buf: [400]u8 = undefined;
    const cmd = std.fmt.bufPrintSentinel(&buf, "tgnode --registration {s}", .{created_code[0..created_code_len]}, 0) catch return;
    if (copy_text) |f| f(cmd.ptr);
}

// ---------------------------------------------------------------------------
// Building blocks

pub fn zfmt(a: Allocator, comptime fmt: []const u8, args: anytype) [*:0]const u8 {
    return (a.dupeSentinel(u8, std.fmt.allocPrint(a, fmt, args) catch return "", 0) catch return "").ptr;
}

/// Transparent container for layout
pub fn box(parent: ?*lv.lv_obj_t, flow: lv.lv_flex_flow_t) ?*lv.lv_obj_t {
    const b = lv.lv_obj_create(parent);
    lv.lv_obj_remove_style_all(b);
    lv.lv_obj_set_size(b, lv.lv_pct(100), lv.LV_SIZE_CONTENT);
    lv.lv_obj_set_flex_flow(b, flow);
    lv.lv_obj_set_flex_align(b, lv.LV_FLEX_ALIGN_START, lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER);
    lv.lv_obj_set_style_pad_column(b, dp(8), 0);
    lv.lv_obj_set_style_pad_row(b, dp(6), 0);
    return b;
}

/// A card that carries a message for the admin: amber frame.
pub fn messageLook(c: ?*lv.lv_obj_t) void {
    lv.lv_obj_set_style_border_color(c, lv.lv_color_hex(color_warning), 0);
    lv.lv_obj_set_style_text_color(c, lv.lv_color_hex(color_warning), 0);
}

/// A card (column): the theme's surface with a light shadow
pub fn card(parent: ?*lv.lv_obj_t) ?*lv.lv_obj_t {
    const c = lv.lv_obj_create(parent);
    lv.lv_obj_set_size(c, lv.lv_pct(100), lv.LV_SIZE_CONTENT);
    lv.lv_obj_set_flex_flow(c, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_style_pad_all(c, dp(pad + 2), 0);
    lv.lv_obj_set_style_pad_row(c, dp(8), 0);
    lv.lv_obj_set_style_radius(c, dp(10), 0);
    lv.lv_obj_set_style_bg_color(c, lv.lv_color_hex(color_panel), 0);
    lv.lv_obj_set_style_border_width(c, 1, 0);
    lv.lv_obj_set_style_border_color(c, lv.lv_color_hex(color_line), 0);
    lv.lv_obj_set_style_shadow_width(c, dp(12), 0);
    lv.lv_obj_set_style_shadow_offset_y(c, dp(2), 0);
    lv.lv_obj_set_style_shadow_opa(c, lv.LV_OPA_10, 0);
    lv.lv_obj_set_scrollable(c, false);
    return c;
}

pub fn label(parent: ?*lv.lv_obj_t, s: [*:0]const u8) ?*lv.lv_obj_t {
    const l = lv.lv_label_create(parent);
    lv.lv_label_set_text(l, s);
    lv.lv_label_set_long_mode(l, lv.LV_LABEL_LONG_MODE_WRAP);
    lv.lv_obj_set_width(l, lv.lv_pct(100));
    return l;
}

pub fn title(parent: ?*lv.lv_obj_t, s: [*:0]const u8) ?*lv.lv_obj_t {
    const l = label(parent, s);
    lv.lv_obj_set_style_text_font(l, font_title, 0);
    lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color_primary), 0);
    return l;
}

pub fn bold(parent: ?*lv.lv_obj_t, s: [*:0]const u8) ?*lv.lv_obj_t {
    const l = label(parent, s);
    lv.lv_obj_set_style_text_font(l, font_bold, 0);
    return l;
}

/// Small, faded text
pub fn muted(parent: ?*lv.lv_obj_t, s: [*:0]const u8) ?*lv.lv_obj_t {
    const l = label(parent, s);
    lv.lv_obj_set_style_text_font(l, font_small, 0);
    lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color_dim), 0);
    return l;
}

/// The right a button needs, by what it calls: without the right the
/// button is not shown (the server refuses the call anyway).
const Guard = struct { cb: lv.lv_event_cb_t, module: []const u8, action: []const u8 };
const guards = [_]Guard{
    .{ .cb = onNewNode, .module = "node", .action = "insert" },
    .{ .cb = onNewNodeKey, .module = "node", .action = "insert" },
    .{ .cb = onApprove, .module = "node", .action = "update" },
    .{ .cb = onReject, .module = "node", .action = "update" },
    .{ .cb = onToggleDisabled, .module = "node", .action = "update" },
    .{ .cb = onDeleteNode, .module = "node", .action = "delete" },
    .{ .cb = onInvite, .module = "user", .action = "access" },
    .{ .cb = onRevoke, .module = "user", .action = "access" },
    .{ .cb = onWatch, .module = "session", .action = "watch" },
    .{ .cb = onEndSession, .module = "session", .action = "end" },
};

/// Primary (filled) button
pub fn button(parent: ?*lv.lv_obj_t, s: [*:0]const u8, cb: lv.lv_event_cb_t, user_data: ?*anyopaque) ?*lv.lv_obj_t {
    const b = lv.lv_button_create(parent);
    const l = lv.lv_label_create(b);
    lv.lv_label_set_text(l, s);
    lv.lv_obj_center(l);
    lv.lv_obj_set_style_radius(b, dp(radius), 0);
    lv.lv_obj_set_style_shadow_width(b, 0, 0);
    lv.lv_obj_set_style_pad_ver(b, dp(8), 0);
    lv.lv_obj_set_style_pad_hor(b, dp(12), 0);
    _ = lv.lv_obj_add_event_cb(b, cb, lv.LV_EVENT_CLICKED, user_data);
    // A form's filled button is its default: Enter in a field presses it
    lv.lv_obj_add_flag(b, default_button_flag);
    for (guards) |g| {
        if (g.cb == cb and !session.can(g.module, g.action)) lv.lv_obj_set_hidden(b, true);
    }
    return b;
}

/// Outlined (secondary) button; danger: red
pub fn outlineButton(parent: ?*lv.lv_obj_t, s: [*:0]const u8, cb: lv.lv_event_cb_t, user_data: ?*anyopaque, danger: bool) ?*lv.lv_obj_t {
    const b = button(parent, s, cb, user_data);
    const color = lv.lv_color_hex(if (danger) color_danger else color_primary);
    lv.lv_obj_set_style_bg_opa(b, lv.LV_OPA_TRANSP, 0);
    lv.lv_obj_set_style_border_color(b, color, 0);
    lv.lv_obj_set_style_border_width(b, 1, 0);
    lv.lv_obj_set_style_text_color(b, color, 0);
    lv.lv_obj_set_style_shadow_width(b, 0, 0);
    return b;
}

/// Small framed tag (state of a node or person)
pub fn chip(parent: ?*lv.lv_obj_t, s: [*:0]const u8, color: u32) ?*lv.lv_obj_t {
    const l = lv.lv_label_create(parent);
    lv.lv_label_set_text(l, s);
    lv.lv_obj_set_style_text_font(l, font_small, 0);
    lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color), 0);
    lv.lv_obj_set_style_border_color(l, lv.lv_color_hex(color), 0);
    lv.lv_obj_set_style_border_width(l, 1, 0);
    lv.lv_obj_set_style_radius(l, dp(radius), 0);
    lv.lv_obj_set_style_pad_hor(l, dp(8), 0);
    lv.lv_obj_set_style_pad_ver(l, dp(2), 0);
    return l;
}

pub fn textarea(parent: ?*lv.lv_obj_t, one_line: bool, max_len: u32, initial: []const u8, a: Allocator) ?*lv.lv_obj_t {
    const ta = lv.lv_textarea_create(parent);
    lv.lv_obj_set_width(ta, lv.lv_pct(100));
    lv.lv_textarea_set_one_line(ta, one_line);
    lv.lv_textarea_set_max_length(ta, max_len);
    if (one_line) _ = lv.lv_obj_add_event_cb(ta, onFieldEnter, lv.LV_EVENT_READY, null);
    // Text is selected with the pointer; see "Text box" below
    lv.lv_textarea_set_text_selection(ta, true);
    _ = lv.lv_obj_add_event_cb(ta, onTaPointer, lv.LV_EVENT_ALL, null);
    _ = lv.lv_obj_add_event_cb(ta, onTaKey, lv.LV_EVENT_KEY | lv.LV_EVENT_PREPROCESS, null);
    lv.lv_obj_set_style_radius(ta, dp(radius), 0);
    lv.lv_textarea_set_text(ta, (a.dupeSentinel(u8, initial, 0) catch return ta).ptr);
    return ta;
}

/// Marks the filled buttons (see `button`).
const default_button_flag = lv.LV_OBJ_FLAG_USER_1;

/// Enter in a field: presses the default button of the form the field is
/// in (the nearest box around the field that has one).
fn onFieldEnter(e: ?*lv.lv_event_t) callconv(.c) void {
    var box_: ?*lv.lv_obj_t = lv.lv_obj_get_parent(lv.lv_event_get_target_obj(e));
    while (box_) |b| : (box_ = lv.lv_obj_get_parent(b)) {
        if (defaultButton(b)) |btn| {
            _ = lv.lv_obj_send_event(btn, lv.LV_EVENT_CLICKED, null);
            return;
        }
        if (b == content) return;
    }
}

fn defaultButton(parent: ?*lv.lv_obj_t) ?*lv.lv_obj_t {
    var i: u32 = 0;
    while (i < lv.lv_obj_get_child_count(parent)) : (i += 1) {
        const child = lv.lv_obj_get_child(parent, @intCast(i));
        if (lv.lv_obj_has_flag(child, lv.LV_OBJ_FLAG_HIDDEN)) continue;
        if (lv.lv_obj_has_flag(child, default_button_flag)) return child;
        if (defaultButton(child)) |b| return b;
    }
    return null;
}

pub fn taText(ta: ?*lv.lv_obj_t) []const u8 {
    return std.mem.span(lv.lv_textarea_get_text(ta));
}

/// Form field: bold name, text area, optional help
pub fn field(parent: ?*lv.lv_obj_t, a: Allocator, name: [*:0]const u8, max_len: u32, initial: []const u8, help: ?[*:0]const u8) ?*lv.lv_obj_t {
    _ = bold(parent, name);
    const ta = textarea(parent, true, max_len, initial, a);
    if (help) |h| _ = muted(parent, h);
    return ta;
}

/// Square icon button without a frame (top bar)
pub fn flatIconButton(parent: ?*lv.lv_obj_t, symbol: [*:0]const u8, cb: lv.lv_event_cb_t) ?*lv.lv_obj_t {
    const b = lv.lv_button_create(parent);
    lv.lv_obj_set_size(b, dp(icon_btn), dp(icon_btn));
    lv.lv_obj_set_style_bg_opa(b, lv.LV_OPA_TRANSP, 0);
    lv.lv_obj_set_style_shadow_width(b, 0, 0);
    lv.lv_obj_set_style_text_color(b, lv.lv_color_hex(color_text), 0);
    const l = lv.lv_label_create(b);
    lv.lv_label_set_text(l, symbol);
    lv.lv_obj_center(l);
    _ = lv.lv_obj_add_event_cb(b, cb, lv.LV_EVENT_CLICKED, null);
    return b;
}

pub const Header = struct { card: ?*lv.lv_obj_t, actions: ?*lv.lv_obj_t, subtitle: ?*lv.lv_obj_t };

/// Card at the top of a page: title, description and actions on the right.
pub fn header(parent: ?*lv.lv_obj_t, title_text: [*:0]const u8, subtitle: [*:0]const u8) Header {
    const c = card(parent);
    const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
    const texts = box(top_row, lv.LV_FLEX_FLOW_COLUMN);
    lv.lv_obj_set_width(texts, 1);
    lv.lv_obj_set_flex_grow(texts, 1);
    lv.lv_obj_set_style_pad_row(texts, dp(2), 0);
    _ = title(texts, title_text);
    const sub: ?*lv.lv_obj_t = if (subtitle[0] != 0) muted(texts, subtitle) else null;
    const actions = box(top_row, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_width(actions, lv.LV_SIZE_CONTENT);
    return .{ .card = c, .actions = actions, .subtitle = sub };
}

// ---------------------------------------------------------------------------
// Lists, forms, messages and the confirm dialog (the screens in src/panel/)

pub fn pageArena() Allocator {
    return arena.allocator();
}

pub fn relayInfo() ?Relay {
    return relay;
}

pub fn relayConnected() bool {
    return service != null;
}

/// Draws the current page again (after a change on it).
pub fn rerender() void {
    renderPage();
}

/// The signed-in user's rights may have changed (its roles, or a role's
/// rights): read them again and show the menu accordingly.
pub fn reloadRights() void {
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    session.resume_(tmp.allocator());
    styleMenuItems();
}

pub fn z(a: Allocator, text: []const u8) [*:0]const u8 {
    return (a.dupeSentinel(u8, text, 0) catch return "").ptr;
}

pub fn iconButton(parent: ?*lv.lv_obj_t, symbol: [*:0]const u8, cb: lv.lv_event_cb_t, user_data: ?*anyopaque, danger: bool) ?*lv.lv_obj_t {
    const b = outlineButton(parent, symbol, cb, user_data, danger);
    lv.lv_obj_set_size(b, dp(icon_btn - 6), dp(icon_btn - 6));
    lv.lv_obj_set_style_pad_all(b, 0, 0);
    // Not a form's default button
    lv.lv_obj_remove_flag(b, default_button_flag);
    return b;
}

pub fn checkbox(parent: ?*lv.lv_obj_t, text: [*:0]const u8, checked: bool) ?*lv.lv_obj_t {
    const cb = lv.lv_checkbox_create(parent);
    lv.lv_checkbox_set_text(cb, text);
    if (checked) lv.lv_obj_add_state(cb, lv.LV_STATE_CHECKED);
    return cb;
}

pub fn isChecked(cb: ?*lv.lv_obj_t) bool {
    return lv.lv_obj_has_state(cb, lv.LV_STATE_CHECKED);
}

pub fn setChecked(cb: ?*lv.lv_obj_t, on: bool) void {
    if (on) lv.lv_obj_add_state(cb, lv.LV_STATE_CHECKED) else lv.lv_obj_remove_state(cb, lv.LV_STATE_CHECKED);
}

/// Dropdown with the given options; `index` is the one selected.
pub fn dropdown(parent: ?*lv.lv_obj_t, options: []const []const u8, index: usize) ?*lv.lv_obj_t {
    const a = arena.allocator();
    var opts: std.ArrayList(u8) = .empty;
    for (options, 0..) |o, i| {
        if (i > 0) opts.append(a, '\n') catch {};
        opts.appendSlice(a, o) catch {};
    }
    opts.append(a, 0) catch {};
    const dd = lv.lv_dropdown_create(parent);
    lv.lv_dropdown_set_options(dd, @ptrCast(opts.items.ptr));
    lv.lv_dropdown_set_selected(dd, @intCast(index));
    lv.lv_obj_set_style_radius(dd, dp(radius), 0);
    lv.lv_obj_set_style_text_font(lv.lv_dropdown_get_list(dd), font_normal, 0);
    return dd;
}

pub fn selected(dd: ?*lv.lv_obj_t) usize {
    return lv.lv_dropdown_get_selected(dd);
}

/// Form title card with a back button; the form's fields go into `card`.
pub fn formHeader(parent: ?*lv.lv_obj_t, title_text: [*:0]const u8, on_back: lv.lv_event_cb_t) struct { card: ?*lv.lv_obj_t, back: ?*lv.lv_obj_t } {
    const c = card(parent);
    const top_row = box(c, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_column(top_row, dp(12), 0);
    const back_btn = iconButton(top_row, lv.LV_SYMBOL_LEFT, on_back, null, false);
    const t = title(top_row, title_text);
    lv.lv_obj_set_width(t, 1);
    lv.lv_obj_set_flex_grow(t, 1);
    return .{ .card = c, .back = back_btn };
}

/// Save + Cancel row at the end of a form; returns the Save button.
pub fn formButtons(parent: ?*lv.lv_obj_t, on_submit: lv.lv_event_cb_t, on_cancel: ?lv.lv_event_cb_t) ?*lv.lv_obj_t {
    const row = box(parent, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_style_pad_top(row, dp(6), 0);
    const submit = button(row, "Save", on_submit, null);
    if (on_cancel) |cb| {
        const c = outlineButton(row, "Cancel", cb, null, false);
        lv.lv_obj_remove_flag(c, default_button_flag);
    }
    return submit;
}

/// A list: a card with a header row and rows of cells. `widths` are
/// percentages of the cell area; the action buttons come after the cells.
pub const Table = struct {
    card: ?*lv.lv_obj_t,
    widths: []const i32,

    pub fn init(parent: ?*lv.lv_obj_t, columns: []const [*:0]const u8, widths: []const i32) Table {
        const c = card(parent);
        lv.lv_obj_set_style_pad_row(c, 0, 0);
        lv.lv_obj_set_style_pad_ver(c, dp(6), 0);
        const t: Table = .{ .card = c, .widths = widths };
        const head = t.rawRow(true);
        for (columns, 0..) |col, i| {
            const l = bold(head.cells, col);
            lv.lv_obj_set_width(l, lv.lv_pct(widths[i]));
            lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(color_dim), 0);
        }
        return t;
    }

    const RawRow = struct { cells: ?*lv.lv_obj_t, actions: ?*lv.lv_obj_t };

    fn rawRow(t: Table, is_header: bool) RawRow {
        const line = box(t.card, lv.LV_FLEX_FLOW_ROW);
        lv.lv_obj_set_style_pad_ver(line, dp(if (is_header) 6 else 4), 0);
        lv.lv_obj_set_style_border_side(line, lv.LV_BORDER_SIDE_BOTTOM, 0);
        lv.lv_obj_set_style_border_width(line, 1, 0);
        lv.lv_obj_set_style_border_color(line, lv.lv_color_hex(color_line), 0);
        const cells = box(line, lv.LV_FLEX_FLOW_ROW);
        lv.lv_obj_set_style_pad_column(cells, 0, 0);
        lv.lv_obj_set_width(cells, 1);
        lv.lv_obj_set_flex_grow(cells, 1);
        const actions = box(line, lv.LV_FLEX_FLOW_ROW);
        lv.lv_obj_set_width(actions, dp(2 * icon_btn));
        lv.lv_obj_set_style_pad_column(actions, dp(6), 0);
        lv.lv_obj_set_flex_align(actions, lv.LV_FLEX_ALIGN_END, lv.LV_FLEX_ALIGN_CENTER, lv.LV_FLEX_ALIGN_CENTER);
        return .{ .cells = cells, .actions = actions };
    }

    /// A row; returns the actions box.
    pub fn row(t: Table, cells: []const [*:0]const u8) ?*lv.lv_obj_t {
        const r = t.rawRow(false);
        for (cells, 0..) |c, i| {
            const l = label(r.cells, c);
            lv.lv_obj_set_width(l, lv.lv_pct(t.widths[i]));
            lv.lv_obj_set_style_pad_right(l, dp(8), 0);
        }
        return r.actions;
    }
};

pub const MsgKind = enum { success, warning, info };

var msg_box: ?*lv.lv_obj_t = null;
var pending_msg: ?MsgKind = null;
var pending_buf: [200]u8 = undefined;
var pending_len: usize = 0;

/// Shows a message under the page's title card (replaces the one before).
pub fn showMsg(kind: MsgKind, msg: []const u8) void {
    if (msg_box == null) {
        const c = card(content);
        _ = label(c, "");
        // Right under the title card (always the first child)
        lv.lv_obj_move_to_index(c, if (lv.lv_obj_get_child_count(content) > 1) 1 else 0);
        msg_box = c;
    }
    const color = lv.lv_color_hex(switch (kind) {
        .success => color_success,
        .warning => color_warning,
        .info => color_primary,
    });
    lv.lv_obj_set_style_border_color(msg_box, color, 0);
    lv.lv_obj_set_style_text_color(msg_box, color, 0);
    const l = lv.lv_obj_get_child(msg_box, 0);
    lv.lv_label_set_text(l, z(arena.allocator(), msg));
    refs.msg_label = l;
    // A long form can push the message out of sight
    lv.lv_obj_update_layout(content);
    lv.lv_obj_scroll_to_view(msg_box, false);
}

/// A message to show after the page is drawn the next time.
pub fn setPendingMsg(kind: MsgKind, msg: []const u8) void {
    pending_len = @min(msg.len, pending_buf.len);
    @memcpy(pending_buf[0..pending_len], msg[0..pending_len]);
    pending_msg = kind;
}

pub fn flushPendingMsg() void {
    if (pending_msg) |kind| {
        pending_msg = null;
        showMsg(kind, pending_buf[0..pending_len]);
    }
}

/// Asks before something is deleted; `on_yes` gets the dialog as its user
/// data and closes it with closeConfirm.
pub fn confirm(question: [*:0]const u8, detail: [*:0]const u8, on_yes: lv.lv_event_cb_t) void {
    const mb = lv.lv_msgbox_create(null);
    lv.lv_obj_set_width(mb, @min(dp(420), lv.lv_display_get_horizontal_resolution(null) - dp(24)));
    lv.lv_obj_set_style_radius(mb, dp(radius), 0);
    lv.lv_obj_set_style_pad_all(mb, dp(6), 0);
    lv.lv_obj_set_style_bg_color(mb, lv.lv_color_hex(color_panel), 0);
    lv.lv_obj_set_style_border_width(mb, 1, 0);
    lv.lv_obj_set_style_border_color(mb, lv.lv_color_hex(color_line), 0);
    lv.lv_obj_set_style_text_color(mb, lv.lv_color_hex(color_text), 0);
    lv.lv_obj_set_style_text_font(mb, font_normal, 0);
    const t = lv.lv_msgbox_add_title(mb, "Are you sure?");
    lv.lv_obj_set_style_text_font(t, font_bold, 0);
    lv.lv_obj_set_style_bg_color(lv.lv_msgbox_get_header(mb), lv.lv_color_hex(color_panel), 0);
    const q = lv.lv_msgbox_add_text(mb, question);
    lv.lv_label_set_long_mode(q, lv.LV_LABEL_LONG_MODE_WRAP);
    const d = lv.lv_msgbox_add_text(mb, detail);
    lv.lv_label_set_long_mode(d, lv.LV_LABEL_LONG_MODE_WRAP);
    lv.lv_obj_set_style_text_color(d, lv.lv_color_hex(color_primary), 0);

    const cancel = lv.lv_msgbox_add_footer_button(mb, "Cancel");
    lv.lv_obj_set_style_bg_opa(cancel, lv.LV_OPA_TRANSP, 0);
    lv.lv_obj_set_style_border_width(cancel, 1, 0);
    lv.lv_obj_set_style_border_color(cancel, lv.lv_color_hex(color_primary), 0);
    lv.lv_obj_set_style_text_color(cancel, lv.lv_color_hex(color_primary), 0);
    _ = lv.lv_obj_add_event_cb(cancel, onConfirmCancel, lv.LV_EVENT_CLICKED, mb);
    const yes = lv.lv_msgbox_add_footer_button(mb, "Yes");
    lv.lv_obj_set_style_bg_color(yes, lv.lv_color_hex(color_danger), 0);
    lv.lv_obj_set_style_text_color(yes, lv.lv_color_hex(color_on_primary), 0);
    _ = lv.lv_obj_add_event_cb(yes, on_yes, lv.LV_EVENT_CLICKED, mb);
    refs.confirm_yes_btn = yes;

    const footer = lv.lv_msgbox_get_footer(mb);
    lv.lv_obj_set_height(footer, lv.LV_SIZE_CONTENT);
    lv.lv_obj_set_style_bg_color(footer, lv.lv_color_hex(color_panel), 0);
    lv.lv_obj_set_style_pad_all(footer, dp(10), 0);
    lv.lv_obj_set_style_pad_column(footer, dp(12), 0);
    for ([_]?*lv.lv_obj_t{ cancel, yes }) |b| {
        lv.lv_obj_set_height(b, lv.LV_SIZE_CONTENT);
        lv.lv_obj_set_style_pad_ver(b, dp(8), 0);
        lv.lv_obj_set_style_radius(b, dp(radius), 0);
        lv.lv_obj_set_style_shadow_width(b, 0, 0);
    }
}

/// Closes the dialog of a Yes / Cancel button.
pub fn closeConfirm(e: ?*lv.lv_event_t) void {
    const mb: ?*lv.lv_obj_t = @ptrCast(@alignCast(lv.lv_event_get_user_data(e)));
    lv.lv_msgbox_close(mb);
    refs.confirm_yes_btn = null;
}

fn onConfirmCancel(e: ?*lv.lv_event_t) callconv(.c) void {
    closeConfirm(e);
}

// ---------------------------------------------------------------------------
// Text box: selection and the Select all / Cut / Copy / Paste bar
//
// Text is selected by dragging. With a selection, typing replaces it and
// Backspace or Delete removes it. A long press, or the end of a drag that
// selected something, shows the bar over the field. Not for passwords.

const no_sel: u32 = 0xFFFF; // LV_LABEL_TEXT_SELECTION_OFF

var edit_ta: ?*lv.lv_obj_t = null;
var edit_menu: ?*lv.lv_obj_t = null;
var long_pressed = false;

pub const EditAction = enum(usize) { select_all = 1, copy, cut, paste };

const Sel = struct { start: u32, end: u32 };

fn selection(ta: ?*lv.lv_obj_t) ?Sel {
    const lbl = lv.lv_textarea_get_label(ta);
    const s = lv.lv_label_get_text_selection_start(lbl);
    const e = lv.lv_label_get_text_selection_end(lbl);
    if (s == no_sel or e == no_sel or s == e) return null;
    return .{ .start = @min(s, e), .end = @max(s, e) };
}

fn byteOffset(s: []const u8, char_idx: u32) usize {
    var n: u32 = 0;
    for (s, 0..) |b, i| {
        if (b & 0xC0 != 0x80) {
            if (n == char_idx) return i;
            n += 1;
        }
    }
    return s.len;
}

fn charCount(s: []const u8) u32 {
    var n: u32 = 0;
    for (s) |b| {
        if (b & 0xC0 != 0x80) n += 1;
    }
    return n;
}

fn deleteSelection(ta: ?*lv.lv_obj_t, sel: Sel) void {
    const t = taText(ta);
    const joined = std.mem.concatWithSentinel(gpa, u8, &.{ t[0..byteOffset(t, sel.start)], t[byteOffset(t, sel.end)..] }, 0) catch return;
    defer gpa.free(joined);
    lv.lv_textarea_clear_selection(ta);
    lv.lv_textarea_set_text(ta, joined.ptr);
    lv.lv_textarea_set_cursor_pos(ta, @intCast(sel.start));
}

fn copySelection(ta: ?*lv.lv_obj_t, sel: Sel) void {
    const t = taText(ta);
    const zs = gpa.dupeSentinel(u8, t[byteOffset(t, sel.start)..byteOffset(t, sel.end)], 0) catch return;
    defer gpa.free(zs);
    if (copy_text) |f| f(zs.ptr);
}

fn onTaKey(e: ?*lv.lv_event_t) callconv(.c) void {
    const ta = lv.lv_event_get_target_obj(e);
    if (edit_ta == ta) closeEditMenu(false);
    const sel = selection(ta) orelse return;
    const key = lv.lv_event_get_key(e);
    switch (key) {
        lv.LV_KEY_BACKSPACE, lv.LV_KEY_DEL => {
            deleteSelection(ta, sel);
            lv.lv_event_stop_processing(e);
        },
        lv.LV_KEY_ENTER => deleteSelection(ta, sel),
        else => if (key >= 0x20) deleteSelection(ta, sel) else lv.lv_textarea_clear_selection(ta),
    }
}

fn onTaPointer(e: ?*lv.lv_event_t) callconv(.c) void {
    const ta = lv.lv_event_get_target_obj(e);
    switch (lv.lv_event_get_code(e)) {
        lv.LV_EVENT_PRESSED => long_pressed = false,
        lv.LV_EVENT_LONG_PRESSED => long_pressed = true,
        lv.LV_EVENT_RELEASED => {
            if (long_pressed or selection(ta) != null) openEditMenu(ta);
            long_pressed = false;
        },
        lv.LV_EVENT_DELETE => if (edit_ta == ta) closeEditMenu(false),
        else => {},
    }
}

fn closeEditMenu(clear_sel: bool) void {
    if (clear_sel) {
        if (edit_ta) |ta| lv.lv_textarea_clear_selection(ta);
    }
    edit_ta = null;
    if (edit_menu) |m| {
        edit_menu = null;
        clearEditRefs();
        lv.lv_obj_set_hidden(m, true);
        lv.lv_obj_delete_async(m);
    }
}

fn clearEditRefs() void {
    refs.edit_select_all_btn = null;
    refs.edit_cut_btn = null;
    refs.edit_copy_btn = null;
    refs.edit_paste_btn = null;
}

fn onEditMenuDeleted(e: ?*lv.lv_event_t) callconv(.c) void {
    if (lv.lv_event_get_target_obj(e) != edit_menu) return;
    edit_menu = null;
    edit_ta = null;
    clearEditRefs();
}

fn onEditBackdrop(_: ?*lv.lv_event_t) callconv(.c) void {
    closeEditMenu(true);
}

fn onEditItem(e: ?*lv.lv_event_t) callconv(.c) void {
    const ta = edit_ta orelse return;
    editAction(ta, @enumFromInt(@intFromPtr(lv.lv_event_get_user_data(e))));
}

fn editAction(ta: ?*lv.lv_obj_t, action: EditAction) void {
    if (lv.lv_textarea_get_password_mode(ta) and action != .paste) return; // no copying of passwords
    switch (action) {
        .select_all => {
            const lbl = lv.lv_textarea_get_label(ta);
            lv.lv_label_set_text_selection_start(lbl, 0);
            lv.lv_label_set_text_selection_end(lbl, charCount(taText(ta)));
            _ = lv.lv_obj_invalidate(ta);
            openEditMenu(ta);
            return;
        },
        .copy => if (selection(ta)) |sel| copySelection(ta, sel),
        .cut => if (selection(ta)) |sel| {
            copySelection(ta, sel);
            deleteSelection(ta, sel);
        },
        // The text arrives as typed text, which replaces the selection
        .paste => {
            const sel = selection(ta);
            closeEditMenu(false);
            if (sel) |x| deleteSelection(ta, x);
            if (paste_text) |f| f();
            return;
        },
    }
    closeEditMenu(true);
}

/// The same from the keyboard (Ctrl+A, Ctrl+C, Ctrl+X) for the field that
/// has the focus. False: no text field has the focus.
pub fn editKey(action: EditAction) bool {
    const ta = lv.lv_group_get_focused(lv.lv_group_get_default());
    if (!termgate_is_textarea(ta)) return false;
    editAction(ta, action);
    return true;
}

fn openEditMenu(ta: ?*lv.lv_obj_t) void {
    closeEditMenu(false);
    if (lv.lv_textarea_get_password_mode(ta)) return; // no copying of passwords
    const has_sel = selection(ta) != null;
    const has_text = taText(ta).len > 0;
    const has_clip = paste_text != null;
    if (!has_sel and !has_text and !has_clip) return;

    const back = lv.lv_obj_create(lv.lv_layer_top());
    lv.lv_obj_remove_style_all(back);
    lv.lv_obj_set_size(back, lv.lv_pct(100), lv.lv_pct(100));
    _ = lv.lv_obj_add_event_cb(back, onEditBackdrop, lv.LV_EVENT_PRESSED, null);
    _ = lv.lv_obj_add_event_cb(back, onEditMenuDeleted, lv.LV_EVENT_DELETE, null);

    const bar = lv.lv_obj_create(back);
    lv.lv_obj_remove_style_all(bar);
    lv.lv_obj_set_size(bar, lv.LV_SIZE_CONTENT, lv.LV_SIZE_CONTENT);
    lv.lv_obj_set_style_bg_color(bar, lv.lv_color_hex(0x303030), 0);
    lv.lv_obj_set_style_bg_opa(bar, lv.LV_OPA_COVER, 0);
    lv.lv_obj_set_style_radius(bar, dp(8), 0);
    lv.lv_obj_set_style_shadow_width(bar, dp(12), 0);
    lv.lv_obj_set_style_shadow_opa(bar, lv.LV_OPA_30, 0);
    lv.lv_obj_set_style_pad_hor(bar, dp(4), 0);
    lv.lv_obj_set_flex_flow(bar, lv.LV_FLEX_FLOW_ROW);
    lv.lv_obj_set_scrollable(bar, false);

    const Item = struct { name: [*:0]const u8, action: EditAction, show: bool };
    const items = [_]Item{
        .{ .name = "Select all", .action = .select_all, .show = has_text and !has_sel },
        .{ .name = "Cut", .action = .cut, .show = has_sel },
        .{ .name = "Copy", .action = .copy, .show = has_sel },
        .{ .name = "Paste", .action = .paste, .show = has_clip },
    };
    for (items) |it| {
        if (!it.show) continue;
        const l = lv.lv_label_create(bar);
        lv.lv_label_set_text(l, it.name);
        lv.lv_obj_set_style_text_color(l, lv.lv_color_hex(0xFFFFFF), 0);
        lv.lv_obj_set_style_text_font(l, font_bold, 0);
        lv.lv_obj_set_style_pad_hor(l, dp(12), 0);
        lv.lv_obj_set_style_pad_ver(l, dp(10), 0);
        lv.lv_obj_set_clickable(l, true);
        lv.lv_obj_set_style_bg_color(l, lv.lv_color_hex(0x505050), lv.LV_STATE_PRESSED);
        lv.lv_obj_set_style_bg_opa(l, lv.LV_OPA_COVER, lv.LV_STATE_PRESSED);
        _ = lv.lv_obj_add_event_cb(l, onEditItem, lv.LV_EVENT_CLICKED, @ptrFromInt(@intFromEnum(it.action)));
        switch (it.action) {
            .paste => refs.edit_paste_btn = l,
            .copy => refs.edit_copy_btn = l,
            .select_all => refs.edit_select_all_btn = l,
            .cut => refs.edit_cut_btn = l,
        }
    }

    lv.lv_obj_update_layout(bar);
    var area: lv.lv_area_t = undefined;
    lv.lv_obj_get_coords(ta, &area);
    const w = lv.lv_obj_get_width(bar);
    const h = lv.lv_obj_get_height(bar);
    const scr_w = lv.lv_display_get_horizontal_resolution(null);
    var y = area.y1 - h - dp(6);
    if (y < 0) y = area.y2 + dp(6);
    const x = std.math.clamp(area.x1, dp(4), @max(dp(4), scr_w - w - dp(4)));
    lv.lv_obj_set_pos(bar, x, y);

    edit_ta = ta;
    edit_menu = back;
}
