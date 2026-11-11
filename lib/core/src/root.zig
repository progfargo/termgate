//! Code shared by the binaries (termgate, tgterm, tgnode):
//! NATS client, nkeys, JWT, grants and TLS. No UI.

pub const nkeys = @import("nkeys.zig");
pub const jwt = @import("jwt.zig");
pub const node = @import("node.zig");
pub const grant = @import("grant.zig");
pub const session = @import("session.zig");
pub const e2e = @import("e2e.zig");
pub const approval = @import("approval.zig");
pub const callout = @import("callout.zig");
pub const code = @import("code.zig");
pub const perms = @import("perms.zig");
pub const bootstrap = @import("bootstrap.zig");
pub const x509 = @import("x509.zig");
/// Test stand-in for termgate (used by the binaries' integration tests)
pub const standin = @import("standin.zig");
pub const nats = @import("nats.zig");
/// Running the official nats-server (termgate's relay)
pub const natsd = @import("natsd.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
