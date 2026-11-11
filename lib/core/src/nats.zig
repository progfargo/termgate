//! NATS client.

pub const protocol = @import("nats/protocol.zig");
pub const Conn = @import("nats/Conn.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
