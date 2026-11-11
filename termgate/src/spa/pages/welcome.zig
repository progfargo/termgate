//! The first page after signing in, while the panel's pages are being
//! moved here one by one.

const app = @import("../app.zig");
const dom = @import("../dom.zig");
const state = @import("../state.zig");
const layout = @import("../layout.zig");

pub fn render(_: []const u8) void {
    dom.setBodyId("");
    layout.renderDefault("");
    const u = state.user orelse return;
    var b: app.Buf = .{};
    b.raw("<div class=\"row row-header\"><div class=\"col\"><h2>termgate</h2></div></div>");
    b.add("<div class=\"row row-content\"><div class=\"col\"><p>Signed in as <strong>{f}</strong>.</p></div></div>", .{app.esc(u.name)});
    dom.setHtml("main-content", b.str());
    _ = state.renderMessages();
}
