//! termgate's panel in the browser: the platform layer (wasm32-emscripten,
//! built by `zig build`). SDL3 gives the window (the page's canvas), the
//! pointer, the keyboard and the drawing; LVGL draws the screens into a
//! pixel buffer that SDL shows. What SDL does not do in a browser is in
//! the page (web/loader.js, called through web/library.js): the calls to
//! the server, a phone's keyboard, the clipboard and the remembered theme.
//!
//! The screens (ui.zig) use the database and the relay service by the
//! names termgate's own modules have; here these are calls to the server
//! (remote_db.zig, remote_service.zig). session.zig is the sign-in.

const std = @import("std");
const Io = std.Io;
const sdl = @import("sdl");
const lv = @import("lvgl");
const ui = @import("ui");
const dbm = @import("db");
const service_mod = @import("service");
const session = @import("session");
const rpc = @import("rpc");

// web/library.js
extern "env" fn tg_copy(text: [*]const u8, len: usize) void;
/// A text field got (1) or lost (0) the focus. On a phone the page's
/// hidden field takes it, so that the phone shows its keyboard.
extern "env" fn tg_keyboard(show: i32) void;
/// Reads the clipboard and types its text into the focused field.
extern "env" fn tg_paste() void;
/// 1: the page may read the clipboard (a secure page).
extern "env" fn tg_can_paste() i32;
/// The user chose the light (0) or dark (1) theme: the browser remembers it.
extern "env" fn tg_theme(dark_on: i32) void;
/// 1: the page runs its self-test, which drives the frames itself.
extern "env" fn tg_test_mode() i32;

// src/lv_helpers.c
extern fn termgate_is_textarea(obj: ?*const lv.lv_obj_t) bool;

const gpa = std.heap.c_allocator;
var threaded: Io.Threaded = .init_single_threaded;
var io: Io = undefined;

var window: ?*sdl.SDL_Window = null;
var renderer: ?*sdl.SDL_Renderer = null;
var texture: ?*sdl.SDL_Texture = null;
var display: ?*lv.lv_display_t = null;
/// Buffer LVGL draws into; as large as the canvas in pixels.
var frame: []u32 = &.{};
var frame_w: i32 = 0;
var frame_h: i32 = 0;
/// Canvas pixels per CSS pixel
var pixel_density: f32 = 1;

/// The self-test sets the time with each frame (tg_frame).
var test_mode = false;
var now_ms: u32 = 0;

var mouse_x: i32 = 0;
var mouse_y: i32 = 0;
var mouse_down = false;
var pointer: ?*lv.lv_indev_t = null;

// Keyboard queue (read by the keypad indev). Each element: a character's
// UTF-8 bytes packed little-endian into a u32, or an LV_KEY_* control key.
var key_queue: [256]u32 = undefined;
var key_count: usize = 0;
var key_release_pending = false;
var keypad: ?*lv.lv_indev_t = null;
/// The page writes text from a phone's keyboard or the clipboard here,
/// then calls tg_text.
var text_buf: [4096]u8 = undefined;

var db: dbm.Db = .{};
var db_lock: Io.Mutex = .init;
var service: service_mod.Service = undefined;

fn tickCb() callconv(.c) u32 {
    return if (test_mode) now_ms else @truncate(sdl.SDL_GetTicks());
}

fn present() void {
    _ = sdl.SDL_UpdateTexture(texture, null, frame.ptr, frame_w * 4);
    _ = sdl.SDL_RenderClear(renderer);
    _ = sdl.SDL_RenderTexture(renderer, texture, null, null);
    _ = sdl.SDL_RenderPresent(renderer);
}

fn flushCb(disp: ?*lv.lv_display_t, _: [*c]const lv.lv_area_t, _: [*c]u8) callconv(.c) void {
    if (lv.lv_display_flush_is_last(disp)) present();
    lv.lv_display_flush_ready(disp);
}

fn pointerRead(_: ?*lv.lv_indev_t, data: [*c]lv.lv_indev_data_t) callconv(.c) void {
    data.*.point.x = mouse_x;
    data.*.point.y = mouse_y;
    data.*.state = if (mouse_down) lv.LV_INDEV_STATE_PRESSED else lv.LV_INDEV_STATE_RELEASED;
}

fn keypadRead(_: ?*lv.lv_indev_t, data: [*c]lv.lv_indev_data_t) callconv(.c) void {
    if (key_release_pending) {
        key_release_pending = false;
        data.*.state = lv.LV_INDEV_STATE_RELEASED;
        return;
    }
    if (key_count > 0) {
        data.*.key = key_queue[0];
        data.*.state = lv.LV_INDEV_STATE_PRESSED;
        std.mem.copyForwards(u32, key_queue[0 .. key_count - 1], key_queue[1..key_count]);
        key_count -= 1;
        key_release_pending = true;
    }
}

fn pushKey(key: u32) void {
    if (key_count < key_queue.len) {
        key_queue[key_count] = key;
        key_count += 1;
    }
}

fn flushKeys() void {
    while (key_count > 0) {
        lv.lv_indev_read(keypad); // press
        lv.lv_indev_read(keypad); // release
    }
}

/// Text into the focused field, each UTF-8 character as one key.
fn typeText(s: []const u8) void {
    var i: usize = 0;
    while (i < s.len) {
        const n = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        const end = @min(i + n, s.len);
        var packed_key: u32 = 0;
        for (s[i..end], 0..) |byte, j| packed_key |= @as(u32, byte) << @intCast(j * 8);
        pushKey(packed_key);
        i = end;
        if (key_count == key_queue.len) flushKeys();
    }
    flushKeys();
}

fn onFocusChanged(g: ?*lv.lv_group_t) callconv(.c) void {
    const text_field = termgate_is_textarea(lv.lv_group_get_focused(g));
    if (text_field) _ = sdl.SDL_StartTextInput(window) else _ = sdl.SDL_StopTextInput(window);
    tg_keyboard(@intFromBool(text_field));
}

fn pasteText() void {
    tg_paste();
}

fn themeChanged(dark_on: bool) void {
    tg_theme(@intFromBool(dark_on));
}

fn copyText(text: [*:0]const u8) void {
    const s = std.mem.span(text);
    tg_copy(s.ptr, s.len);
}

/// A user has signed in (or its session was still good): the screens
/// get the relay's address and the service.
fn onSignedIn() void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const Info = struct { host: []const u8, port: u16, ca_fingerprint: []const u8 };
    const info = rpc.result(Info, error{Failed}, error.Failed, arena.allocator(), "relay.info", .{}) catch return;
    var fp: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&fp, info.ca_fingerprint) catch return;
    // The host lives as long as the page
    const host = gpa.dupe(u8, info.host) catch return;
    ui.setRelay(.{ .host = host, .port = info.port, .ca_fingerprint = fp });
    ui.setService(&service);
}

/// Makes the picture as large as the canvas.
fn syncSize() bool {
    var w: c_int = 0;
    var h: c_int = 0;
    _ = sdl.SDL_GetWindowSizeInPixels(window, &w, &h);
    w = @max(w, 240);
    h = @max(h, 200);
    pixel_density = sdl.SDL_GetWindowPixelDensity(window);
    if (pixel_density <= 0) pixel_density = 1;
    if (w == frame_w and h == frame_h) return true;
    const pixels = gpa.alloc(u32, @intCast(w * h)) catch return false;
    @memset(pixels, 0);
    if (texture) |t| sdl.SDL_DestroyTexture(t);
    texture = sdl.SDL_CreateTexture(renderer, sdl.SDL_PIXELFORMAT_ARGB8888, sdl.SDL_TEXTUREACCESS_STREAMING, w, h) orelse return false;
    const old = frame;
    frame = pixels;
    frame_w = w;
    frame_h = h;
    if (display == null) {
        display = lv.lv_display_create(w, h);
        lv.lv_display_set_flush_cb(display, flushCb);
    } else {
        lv.lv_display_set_resolution(display, w, h);
    }
    lv.lv_display_set_buffers(display, frame.ptr, null, @intCast(frame.len * 4), lv.LV_DISPLAY_RENDER_MODE_DIRECT);
    if (old.len > 0) gpa.free(old);
    return true;
}

fn controlKey(key: sdl.SDL_Keycode, shift: bool) ?u32 {
    return switch (key) {
        sdl.SDLK_BACKSPACE => lv.LV_KEY_BACKSPACE,
        sdl.SDLK_DELETE => lv.LV_KEY_DEL,
        sdl.SDLK_RETURN, sdl.SDLK_KP_ENTER => lv.LV_KEY_ENTER,
        sdl.SDLK_LEFT => lv.LV_KEY_LEFT,
        sdl.SDLK_RIGHT => lv.LV_KEY_RIGHT,
        sdl.SDLK_UP => lv.LV_KEY_UP,
        sdl.SDLK_DOWN => lv.LV_KEY_DOWN,
        sdl.SDLK_HOME => lv.LV_KEY_HOME,
        sdl.SDLK_END => lv.LV_KEY_END,
        sdl.SDLK_ESCAPE => lv.LV_KEY_ESC,
        sdl.SDLK_TAB => if (shift) lv.LV_KEY_PREV else lv.LV_KEY_NEXT,
        else => null,
    };
}

/// Mouse wheel: scrolls what is under the pointer.
fn wheel(dy: i32) void {
    var p: lv.lv_point_t = .{ .x = mouse_x, .y = mouse_y };
    var obj = lv.lv_indev_search_obj(lv.lv_layer_top(), &p);
    if (obj == null) obj = lv.lv_indev_search_obj(lv.lv_screen_active(), &p);
    while (obj) |o| : (obj = lv.lv_obj_get_parent(o)) {
        if (lv.lv_obj_is_scrollable(o) and (lv.lv_obj_get_scroll_top(o) > 0 or lv.lv_obj_get_scroll_bottom(o) > 0)) {
            lv.lv_obj_scroll_by_bounded(o, 0, dy, false);
            break;
        }
    }
}

/// Input is handled the moment SDL gets it, inside the browser's own
/// event: a tap on a text field must focus the page's hidden field there,
/// the only moment a phone lets a page open its keyboard.
fn onEvent(_: ?*anyopaque, e: [*c]sdl.SDL_Event) callconv(.c) bool {
    const ev: *const sdl.SDL_Event = e;
    switch (ev.type) {
        sdl.SDL_EVENT_WINDOW_PIXEL_SIZE_CHANGED, sdl.SDL_EVENT_WINDOW_RESIZED => {
            if (syncSize()) ui.resized();
        },
        sdl.SDL_EVENT_MOUSE_MOTION => {
            mouse_x = @intFromFloat(ev.motion.x * pixel_density);
            mouse_y = @intFromFloat(ev.motion.y * pixel_density);
            lv.lv_indev_read(pointer);
        },
        sdl.SDL_EVENT_MOUSE_BUTTON_DOWN, sdl.SDL_EVENT_MOUSE_BUTTON_UP => {
            if (ev.button.button != sdl.SDL_BUTTON_LEFT) return true;
            mouse_x = @intFromFloat(ev.button.x * pixel_density);
            mouse_y = @intFromFloat(ev.button.y * pixel_density);
            mouse_down = ev.type == sdl.SDL_EVENT_MOUSE_BUTTON_DOWN;
            lv.lv_indev_read(pointer);
        },
        sdl.SDL_EVENT_MOUSE_WHEEL => wheel(@intFromFloat(ev.wheel.y * 40 * pixel_density)),
        sdl.SDL_EVENT_TEXT_INPUT => typeText(std.mem.span(ev.text.text)),
        sdl.SDL_EVENT_KEY_DOWN => {
            const ctrl = (ev.key.mod & (sdl.SDL_KMOD_CTRL | sdl.SDL_KMOD_GUI)) != 0;
            if (ctrl) {
                // In a text field: select all, copy, cut, paste
                switch (ev.key.key) {
                    sdl.SDLK_A => _ = ui.editKey(.select_all),
                    sdl.SDLK_C => _ = ui.editKey(.copy),
                    sdl.SDLK_X => _ = ui.editKey(.cut),
                    sdl.SDLK_V => if (ui.paste_text) |p| p(),
                    else => {},
                }
                return true;
            }
            if (controlKey(ev.key.key, (ev.key.mod & sdl.SDL_KMOD_SHIFT) != 0)) |k| {
                pushKey(k);
                flushKeys();
            }
        },
        else => {},
    }
    return true;
}

fn loop() callconv(.c) void {
    var ev: sdl.SDL_Event = undefined;
    // Input was handled by onEvent; this empties SDL's queue
    while (sdl.SDL_PollEvent(&ev)) {}
    _ = lv.lv_timer_handler();
}

export fn main() c_int {
    io = threaded.io();
    test_mode = tg_test_mode() != 0;
    // Keys come from the canvas only: while a phone's keyboard is open, the
    // page's hidden field has the focus and passes on what is typed
    _ = sdl.SDL_SetHint(sdl.SDL_HINT_EMSCRIPTEN_KEYBOARD_ELEMENT, "#canvas");
    if (!sdl.SDL_Init(sdl.SDL_INIT_VIDEO)) return 1;
    window = sdl.SDL_CreateWindow("termgate", 800, 600, sdl.SDL_WINDOW_RESIZABLE | sdl.SDL_WINDOW_HIGH_PIXEL_DENSITY) orelse return 1;
    renderer = sdl.SDL_CreateRenderer(window, null) orelse return 1;

    lv.lv_init();
    lv.lv_tick_set_cb(tickCb);
    if (!syncSize()) return 1;

    pointer = lv.lv_indev_create();
    lv.lv_indev_set_type(pointer, lv.LV_INDEV_TYPE_POINTER);
    lv.lv_indev_set_read_cb(pointer, pointerRead);
    // Read when SDL reports the pointer, not on a timer (see onEvent)
    lv.lv_indev_set_mode(pointer, lv.LV_INDEV_MODE_EVENT);
    const group = lv.lv_group_create();
    lv.lv_group_set_default(group);
    keypad = lv.lv_indev_create();
    lv.lv_indev_set_type(keypad, lv.LV_INDEV_TYPE_KEYPAD);
    lv.lv_indev_set_read_cb(keypad, keypadRead);
    lv.lv_indev_set_mode(keypad, lv.LV_INDEV_MODE_EVENT);
    lv.lv_indev_set_group(keypad, group);
    lv.lv_group_set_focus_cb(group, onFocusChanged);

    service = .{ .gpa = gpa, .io = io };
    ui.copy_text = copyText;
    ui.on_theme = themeChanged;
    if (tg_can_paste() != 0) ui.paste_text = pasteText;
    ui.on_signed_in = onSignedIn;
    {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        session.resume_(arena.allocator());
    }
    ui.init(gpa, io, &db, &db_lock, pixel_density, true) catch return 2;
    if (session.signedIn()) {
        onSignedIn();
        ui.refresh();
    }
    if (!sdl.SDL_AddEventWatch(onEvent, null)) return 1;
    // The self-test calls tg_frame itself
    if (!test_mode) sdl.emscripten_set_main_loop(loop, 0, false);
    return 0;
}

/// The visible part of the page is `w` x `h` CSS pixels (the page tells,
/// at the start and on every change: a phone's keyboard takes its share).
/// SDL makes the canvas that large, in device pixels.
export fn tg_resize(w: i32, h: i32) void {
    _ = sdl.SDL_SetWindowSize(window, @max(w, 240), @max(h, 200));
}

/// The theme the browser remembers (before main), or a change of it.
export fn tg_set_dark(on: i32) void {
    ui.setDark(on != 0) catch {};
}

/// A control key from the page's hidden field (a phone's keyboard):
/// 1 Backspace, 2 Delete, 3 Enter, 4 Left, 5 Right, 6 Up, 7 Down, 8 Home,
/// 9 End, 10 Escape, 11 Tab, 12 Shift+Tab.
export fn tg_key(code: i32) void {
    const k: u32 = switch (code) {
        1 => lv.LV_KEY_BACKSPACE,
        2 => lv.LV_KEY_DEL,
        3 => lv.LV_KEY_ENTER,
        4 => lv.LV_KEY_LEFT,
        5 => lv.LV_KEY_RIGHT,
        6 => lv.LV_KEY_UP,
        7 => lv.LV_KEY_DOWN,
        8 => lv.LV_KEY_HOME,
        9 => lv.LV_KEY_END,
        10 => lv.LV_KEY_ESC,
        11 => lv.LV_KEY_NEXT,
        12 => lv.LV_KEY_PREV,
        else => return,
    };
    pushKey(k);
    flushKeys();
}

/// Where the page writes text from a phone's keyboard or the clipboard.
export fn tg_text_buf() [*]u8 {
    return &text_buf;
}

export fn tg_text_cap() usize {
    return text_buf.len;
}

/// `len` bytes of text are in the buffer: typed into the focused field.
export fn tg_text(len: usize) void {
    typeText(text_buf[0..@min(len, text_buf.len)]);
}

// --- for the page's self-test (index.html?test) --------------------------------

/// One frame at time `ms` (the self-test drives the frames).
export fn tg_frame(ms: u32) void {
    now_ms = ms;
    _ = lv.lv_timer_handler();
}

/// Ctrl+A (1), Ctrl+C (2), Ctrl+X (3) in the focused text field. Returns 0
/// when no text field has the focus.
export fn tg_edit(code: i32) i32 {
    const action: ui.EditAction = switch (code) {
        1 => .select_all,
        2 => .copy,
        3 => .cut,
        else => return 0,
    };
    return @intFromBool(ui.editKey(action));
}

/// 1: the dark theme is on.
export fn tg_test_dark() i32 {
    return @intFromBool(ui.isDark());
}

/// 0: the sign-in screen is shown; 1: signed in.
export fn tg_test_signed_in() i32 {
    return @intFromBool(session.signedIn());
}

/// The screen objects the self-test names by number.
fn testObject(what: i32) ?*lv.lv_obj_t {
    const r = &ui.refs;
    return switch (what) {
        1 => r.signin_btn,
        2 => r.signin_name_ta,
        3 => r.signin_password_ta,
        4 => r.signin_code_ta,
        5 => r.first_audit_row,
        6 => r.first_watch_btn,
        7 => r.settings_btn,
        8 => r.new_user_btn,
        9 => r.watch_history_btn,
        10 => r.first_node_card,
        11 => r.new_node_btn,
        12 => r.node_name_ta,
        13 => r.node_create_btn,
        14 => r.done_btn,
        15 => r.invite_btn,
        16 => r.inv_name_ta,
        17 => r.inv_nodes_ta,
        18 => r.inv_run_as_ta,
        19 => r.inv_uses_ta,
        20 => r.inv_create_btn,
        21 => r.user_name_ta,
        22 => r.user_create_btn,
        23 => r.set_minutes_ta,
        24 => r.set_save_btn,
        25 => r.backdrop,
        26 => r.sign_out_btn,
        27 => r.signin_qr,
        28 => r.new_role_btn,
        29 => r.role_name_ta,
        33 => r.role_save_btn,
        34 => r.last_role_edit_btn,
        35 => r.last_role_delete_btn,
        36 => r.confirm_yes_btn,
        37 => r.last_user_edit_btn,
        38 => r.user_grant_btn,
        39 => r.last_user_delete_btn,
        // Rights in the role form
        41 => ui.panel_roles.rightBox("node", "browse"),
        42 => ui.panel_roles.rightBox("session", "watch"),
        43 => r.theme_cb,
        44 => r.menu_btn,
        45 => r.edit_select_all_btn,
        46 => r.edit_cut_btn,
        47 => r.edit_copy_btn,
        48 => r.last_user_select_btn,
        49 => r.acting_btn,
        // Labels (for tg_test_text)
        30 => r.code_label,
        31 => r.set_msg,
        32 => r.msg_label,
        else => null,
    };
}

/// Moves the pointer to the middle of a screen object (see testObject),
/// scrolled into view first. Returns 0 if it is not on the screen.
export fn tg_test_tap(what: i32) i32 {
    const obj = testObject(what) orelse return 0;
    // What is hidden cannot be tapped
    if (lv.lv_obj_has_flag(obj, lv.LV_OBJ_FLAG_HIDDEN)) return 0;
    lv.lv_obj_scroll_to_view_recursive(obj, false);
    lv.lv_obj_update_layout(lv.lv_screen_active());
    lv.lv_obj_update_layout(lv.lv_layer_top());
    var area: lv.lv_area_t = undefined;
    lv.lv_obj_get_coords(obj, &area);
    mouse_x = @divTrunc(area.x1 + area.x2, 2);
    mouse_y = @divTrunc(area.y1 + area.y2, 2);
    return 1;
}

/// Copies a label's text into the text buffer; returns its length (0 if
/// the label is not on the screen).
export fn tg_test_text(what: i32) usize {
    const obj = testObject(what) orelse return 0;
    const t = std.mem.span(lv.lv_label_get_text(obj));
    const n = @min(t.len, text_buf.len);
    @memcpy(text_buf[0..n], t[0..n]);
    return n;
}

/// Copies a text field's text into the text buffer; returns its length.
export fn tg_test_value(what: i32) usize {
    const obj = testObject(what) orelse return 0;
    if (!termgate_is_textarea(obj)) return 0;
    const t = std.mem.span(lv.lv_textarea_get_text(obj));
    const n = @min(t.len, text_buf.len);
    @memcpy(text_buf[0..n], t[0..n]);
    return n;
}

/// Shows a page: 0 Nodes, 1 People, 2 Sessions, 3 Audit, 4 Users, 5 Roles,
/// 6 Configuration, 7 Help, 8 Profile.
export fn tg_test_goto(p: i32) void {
    if (p >= 0 and p < ui.page_count) ui.showPage(@enumFromInt(@as(u8, @intCast(p))));
}

/// Presses or releases the pointer where tg_test_tap put it.
export fn tg_test_press(down: i32) void {
    mouse_down = down != 0;
    lv.lv_indev_read(pointer);
}

/// 1: the signed-in user acts as another user.
export fn tg_test_acting() i32 {
    return @intFromBool(session.actingFor() != null);
}

/// Whether the Nodes page shows a node card.
export fn tg_test_has_node() i32 {
    return @intFromBool(ui.refs.first_node_card != null);
}
