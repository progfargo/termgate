//! The data termgate's database holds, as the rest of termgate sees it:
//! the types and error sets, without SQLite.

const std = @import("std");
const core = @import("core");

pub const Error = error{ SqliteError, OutOfMemory };

pub const NodeState = enum {
    /// Created by the admin; the node key has not been used yet
    waiting,
    /// A registration request arrived and waits for the admin
    pending,
    /// Registered: the hardware key is bound to the name
    approved,
    /// Switched off by the admin; the callout refuses it
    disabled,
};

/// A user's terminal access: the grant spec an admin chose when giving it
/// (tgterm --invite), and the user's key once the invitation is used.
/// Connecting also needs the right terminal:connect from the user's roles.
pub const Terminal = struct {
    /// The user's id
    id: i64,
    /// The user's name
    name: []const u8,
    kind: core.grant.Kind,
    /// Set once the invitation is used
    user_key: ?[]const u8,
    /// Node name patterns, comma separated
    nodes: []const u8,
    run_as: []const u8,
    max_uses: ?i64,
    grant_exp: ?i64,
    revoked: bool,
    created: i64,
    /// Until when the invitation may be used (unused invitations)
    token_expires: ?i64,
    /// Sessions used so far (null before the invitation is used)
    uses: ?i64,
};

pub const Session = struct {
    sid: []const u8,
    node: []const u8,
    user_key: []const u8,
    /// The user's name
    user: []const u8,
    grant_jti: []const u8,
    started: i64,
    ended: ?i64,
    exit_status: ?i64,
};

/// termgate's settings (Settings panel).
pub const Settings = struct {
    /// Output kept per command in the session log, in characters
    max_command_output: i64 = 10_000,
    /// Sessions are ended after this many minutes; 0: no limit
    max_session_minutes: i64 = 480,
    /// Session logs older than this many days are deleted; 0: kept
    log_days: i64 = 30,
};

/// Who signs in to the panel.
pub const rights = @import("rights.zig");

/// A role: a named set of rights (rights.zig), given to users.
pub const Role = struct {
    id: i64,
    name: []const u8,
    description: []const u8,
    /// How many users have the role
    user_count: i64,
};

/// A role a user has.
pub const RoleRef = struct { id: i64, name: []const u8 };

pub const User = struct {
    id: i64,
    name: []const u8,
    /// Has every right; cannot be deleted or blocked (the first user)
    is_superuser: bool,
    /// Argon2id PHC string
    password_hash: []const u8,
    /// The second step is set up (the user has signed in with a code)
    totp_confirmed: bool,
    /// Last time step a code was accepted for (codes are used once)
    totp_last_step: i64,
    /// Wrong passwords or codes in a row, and until when sign-in is refused
    fail_count: i64,
    locked_until: i64,
    disabled: bool,
    created: i64,
};

/// A browser session; `full` once the second step is done.
/// A browser session. `effective_user_id`: the user the signed-in user
/// acts as (users.select), whose rights then apply; null: itself.
pub const WebSession = struct { user_id: i64, full: bool, effective_user_id: ?i64 = null };

/// One command of a session's log: the line as it was on the screen when
/// Enter was pressed (prompt included), and its output as plain text.
pub const Command = struct {
    seq: i64,
    at: i64,
    line: []const u8,
    /// At most Settings.max_command_output characters
    output: []const u8,
    /// Characters the command printed in all
    output_chars: i64,
    /// false: what is stored did not decrypt (changed, or another key)
    intact: bool = true,
};

pub const Node = struct {
    id: i64,
    name: []const u8,
    description: []const u8,
    state: NodeState,
    /// Bound hardware key (approved nodes)
    hardware_key: ?[]const u8,
    /// Key of the pending registration request
    request_key: ?[]const u8,
    /// Last system info received (JSON), from registration or status.<node>
    status: ?[]const u8,
    created: i64,
    /// When the node was last known to be connected
    last_seen: ?i64,
    /// Until when the node key may be used
    token_expires: ?i64,
    /// Connected to the relay right now (from the relay's connection events)
    online: bool,
};

/// What termgate stores instead of a code's token: its SHA-256, base32
/// (core.code.tokenDigest). Its first 16 characters are the token id used in
/// subjects (register.<id>, invite.<id>).
pub fn tokenHash(token: []const u8) [core.code.part_len]u8 {
    return core.code.tokenDigest(token);
}

/// Something a panel user did (or tried): who, when, which call, on what.
pub const Action = struct {
    id: i64,
    at: i64,
    /// The user's name ("" for a failed sign-in with an unknown name)
    user: []const u8,
    /// The API call, e.g. "db.nodeDelete", "svc.endSession", "login"
    call: []const u8,
    /// What it was about: a node, a user, a session
    detail: []const u8,
    ok: bool,
};

pub const NodeError = error{ InvalidName, Duplicate, NotFound, WrongState } || Error;
pub const TerminalError = error{ InvalidSpec, NotFound, Duplicate } || Error;

/// What terminal access a user gets (the grant's spec).
pub const TerminalSpec = struct {
    kind: core.grant.Kind = .human,
    /// Node name patterns, comma separated ("ist_*,pump??")
    nodes: []const u8,
    run_as: []const u8,
    max_uses: ?u32 = null,
    /// When the grant ends; a grant needs this, max_uses or both
    grant_exp: ?i64 = null,
};
