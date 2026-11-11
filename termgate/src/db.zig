//! termgate's data (SQLite): nodes and their registration, users with
//! their roles and terminal access, grants with use counts, sessions and
//! their logs, the panel's audit.
//!
//! termgate is the authority: the relay keeps no state, and nodes and users
//! hold no credentials besides their own keys. Every decision termgate makes
//! on the relay (auth callout, session approval) reads this database.
//!
//! Read functions allocate the strings of their results with the allocator
//! they get; callers usually pass an arena and free everything at once.
//! SQLite is built serialized (SQLITE_THREADSAFE=1): the panel's server and
//! the relay service use one connection from different threads.

const std = @import("std");
const c = @import("c");
const core = @import("core");
const types = @import("db_types.zig");

pub const Error = types.Error;
pub const NodeState = types.NodeState;
pub const Terminal = types.Terminal;
pub const Session = types.Session;
pub const Settings = types.Settings;
pub const Role = types.Role;
pub const RoleRef = types.RoleRef;
pub const rights = types.rights;
pub const User = types.User;
pub const WebSession = types.WebSession;
pub const Command = types.Command;
pub const Node = types.Node;
pub const tokenHash = types.tokenHash;
pub const Action = types.Action;

/// A log field encrypted: nonce (24 bytes, random), ciphertext, tag. The
/// session, the command's number and the field name are authenticated
/// with it, so a field cannot be moved to another row or column unnoticed.
fn sealLog(gpa: std.mem.Allocator, io: std.Io, key: LogKey, sid: []const u8, seq: i64, field: []const u8, plain: []const u8) error{OutOfMemory}![]u8 {
    const out = try gpa.alloc(u8, Aead.nonce_length + plain.len + Aead.tag_length);
    const nonce = out[0..Aead.nonce_length];
    io.random(nonce);
    var ad_buf: [256]u8 = undefined;
    const ad = logAd(&ad_buf, sid, seq, field);
    Aead.encrypt(out[Aead.nonce_length..][0..plain.len], out[Aead.nonce_length + plain.len ..][0..Aead.tag_length], plain, ad, nonce.*, key);
    return out;
}

fn openLog(a: std.mem.Allocator, key: LogKey, sid: []const u8, seq: i64, field: []const u8, sealed: []const u8) ![]u8 {
    if (sealed.len < Aead.nonce_length + Aead.tag_length) return error.Tampered;
    const n = sealed.len - Aead.nonce_length - Aead.tag_length;
    const out = try a.alloc(u8, n);
    var ad_buf: [256]u8 = undefined;
    const ad = logAd(&ad_buf, sid, seq, field);
    Aead.decrypt(out, sealed[Aead.nonce_length..][0..n], sealed[Aead.nonce_length + n ..][0..Aead.tag_length].*, ad, sealed[0..Aead.nonce_length].*, key) catch return error.Tampered;
    return out;
}

fn logAd(buf: []u8, sid: []const u8, seq: i64, field: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "termgate-log-v1\x00{s}\x00{d}\x00{s}", .{ sid, seq, field }) catch buf[0..0];
}

// src/sqlite_helpers.c
extern fn termgate_sqlite_transient() c.sqlite3_destructor_type;

/// Session logs are encrypted with this key (XChaCha20-Poly1305).
pub const LogKey = [32]u8;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const Db = struct {
    handle: *c.sqlite3,
    /// Without it session logs can be neither written nor read
    log_key: ?LogKey = null,
    /// For random nonces; set with the key
    io: ?std.Io = null,

    pub fn open(path: [:0]const u8) Error!Db {
        var h: ?*c.sqlite3 = null;
        if (c.sqlite3_open(path.ptr, &h) != c.SQLITE_OK) {
            if (h) |hh| _ = c.sqlite3_close(hh);
            return error.SqliteError;
        }
        var db: Db = .{ .handle = h.? };
        errdefer db.close();
        try db.exec("PRAGMA foreign_keys = ON");
        try db.exec("PRAGMA journal_mode = WAL");
        try db.initSchema();
        return db;
    }

    pub fn setLogKey(db: *Db, io: std.Io, key: LogKey) void {
        db.log_key = key;
        db.io = io;
    }

    pub fn close(db: *Db) void {
        const rc = c.sqlite3_close(db.handle);
        std.debug.assert(rc == c.SQLITE_OK);
    }

    fn exec(db: *Db, sql: [*:0]const u8) Error!void {
        if (c.sqlite3_exec(db.handle, sql, null, null, null) != c.SQLITE_OK) return error.SqliteError;
    }

    fn initSchema(db: *Db) Error!void {
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS node (
            \\    nodeId INTEGER PRIMARY KEY,
            \\    name TEXT NOT NULL UNIQUE,
            \\    description TEXT NOT NULL DEFAULT '',
            \\    state TEXT NOT NULL,
            \\    hardwareKey TEXT UNIQUE,
            \\    tokenHash TEXT UNIQUE,
            \\    tokenExpires INTEGER,
            \\    requestKey TEXT,
            \\    status TEXT,
            \\    created INTEGER NOT NULL,
            \\    lastSeen INTEGER,
            \\    online INTEGER NOT NULL DEFAULT 0
            \\)
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS setting (
            \\    name TEXT PRIMARY KEY,
            \\    value INTEGER NOT NULL
            \\)
        );
        // The panel's users and their browser sessions
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS user (
            \\    userId INTEGER PRIMARY KEY,
            \\    name TEXT NOT NULL UNIQUE,
            \\    isSuperuser INTEGER NOT NULL DEFAULT 0,
            \\    passwordHash TEXT NOT NULL,
            \\    totpSecret BLOB,
            \\    totpConfirmed INTEGER NOT NULL DEFAULT 0,
            \\    totpLastStep INTEGER NOT NULL DEFAULT 0,
            \\    failCount INTEGER NOT NULL DEFAULT 0,
            \\    lockedUntil INTEGER NOT NULL DEFAULT 0,
            \\    disabled INTEGER NOT NULL DEFAULT 0,
            \\    created INTEGER NOT NULL,
            \\    nodes TEXT NOT NULL DEFAULT ''
            \\)
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS webSession (
            \\    tokenHash TEXT PRIMARY KEY,
            \\    userId INTEGER NOT NULL REFERENCES user(userId) ON DELETE CASCADE,
            \\    full INTEGER NOT NULL DEFAULT 0,
            \\    created INTEGER NOT NULL,
            \\    expires INTEGER NOT NULL,
            \\    effectiveUserId INTEGER REFERENCES user(userId) ON DELETE SET NULL
            \\)
        );
        // Roles, the rights of each (module and action, see rights.zig) and
        // the roles of each user
        const first_roles = !try db.has("select 1 from sqlite_master where type = 'table' and name = 'role'");
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS role (
            \\    roleId INTEGER PRIMARY KEY,
            \\    name TEXT NOT NULL UNIQUE,
            \\    description TEXT NOT NULL DEFAULT ''
            \\)
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS roleRight (
            \\    roleId INTEGER NOT NULL REFERENCES role(roleId) ON DELETE CASCADE,
            \\    module TEXT NOT NULL,
            \\    action TEXT NOT NULL,
            \\    PRIMARY KEY (roleId, module, action)
            \\)
        );
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS userRole (
            \\    userId INTEGER NOT NULL REFERENCES user(userId) ON DELETE CASCADE,
            \\    roleId INTEGER NOT NULL REFERENCES role(roleId) ON DELETE CASCADE,
            \\    PRIMARY KEY (userId, roleId)
            \\)
        );
        try db.exec("CREATE INDEX IF NOT EXISTS userRoleRole ON userRole(roleId)");
        if (first_roles) try db.seedRoles();
        // A user's terminal access: its invitation (the token's hash until
        // it is used), the key it bound, the invitation's limits and the
        // sessions opened so far. Which nodes is the user's (user.nodes).
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS terminal (
            \\    userId INTEGER PRIMARY KEY REFERENCES user(userId) ON DELETE CASCADE,
            \\    kind TEXT NOT NULL,
            \\    userKey TEXT UNIQUE,
            \\    tokenHash TEXT UNIQUE,
            \\    tokenExpires INTEGER,
            \\    maxUses INTEGER,
            \\    expires INTEGER,
            \\    uses INTEGER NOT NULL DEFAULT 0,
            \\    revoked INTEGER NOT NULL DEFAULT 0,
            \\    created INTEGER NOT NULL
            \\)
        );
        // What panel users did: every changing call and every sign-in
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS action (
            \\    actionId INTEGER PRIMARY KEY,
            \\    at INTEGER NOT NULL,
            \\    user TEXT NOT NULL,
            \\    call TEXT NOT NULL,
            \\    detail TEXT NOT NULL,
            \\    ok INTEGER NOT NULL
            \\)
        );
        // Session logs: the commands of each session and their output
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS sessionCommand (
            \\    sid TEXT NOT NULL,
            \\    seq INTEGER NOT NULL,
            \\    at INTEGER NOT NULL,
            \\    line BLOB NOT NULL,
            \\    output BLOB NOT NULL,
            \\    outputChars INTEGER NOT NULL,
            \\    PRIMARY KEY (sid, seq)
            \\)
        );
        try db.exec("CREATE INDEX IF NOT EXISTS sessionCommandAt ON sessionCommand(at)");
        // Audit: one row per approved session
        try db.exec(
            \\CREATE TABLE IF NOT EXISTS session (
            \\    sessionId INTEGER PRIMARY KEY,
            \\    sid TEXT NOT NULL UNIQUE,
            \\    node TEXT NOT NULL,
            \\    userKey TEXT NOT NULL,
            \\    userName TEXT NOT NULL,
            \\    started INTEGER NOT NULL,
            \\    ended INTEGER,
            \\    exitStatus INTEGER,
            \\    keys BLOB
            \\)
        );
    }

    /// The role terminal_user: connecting to nodes with tgterm.
    fn seedTerminalRole(db: *Db) Error!void {
        try db.exec("insert or ignore into role(name, description) values('terminal_user', 'Connects to nodes with tgterm; which nodes and as whom is set per user.')");
        try db.exec("insert or ignore into roleRight(roleId, module, action) select roleId, 'terminal', 'connect' from role where name = 'terminal_user'");
    }

    /// Does the query give a row.
    fn has(db: *Db, sql: [:0]const u8) Error!bool {
        var st = try Stmt.prepare(db, sql);
        defer st.finalize();
        return try st.step();
    }

    /// The roles a new database starts with; an admin can change them.
    fn seedRoles(db: *Db) Error!void {
        try db.exec("insert or ignore into role(roleId, name, description) values(1, 'admin', 'Everything in the panel.')");
        try db.exec("insert or ignore into role(roleId, name, description) values(2, 'auditor', 'Reads only: nodes, sessions and their logs, audit.')");
        // admin: every right but connecting to nodes (an admin who does that
        // gets the role terminal_user too)
        inline for (rights.modules) |m| {
            if (comptime std.mem.eql(u8, m.name, "terminal")) continue;
            inline for (m.actions) |ac|
                try db.exec("insert or ignore into roleRight(roleId, module, action) values(1, '" ++ m.name ++ "', '" ++ ac.name ++ "')");
        }
        try db.seedTerminalRole();
        inline for (.{ "panel:login", "node:browse", "session:browse", "session:watch", "session:log", "audit:browse", "user:browse", "config:browse", "profile:browse", "profile:update_password", "help:browse" }) |r| {
            const p = comptime rights.parse(r).?;
            try db.exec("insert or ignore into roleRight(roleId, module, action) values(2, '" ++ p.module ++ "', '" ++ p.action ++ "')");
        }
    }

    fn begin(db: *Db) Error!void {
        try db.exec("BEGIN IMMEDIATE");
    }

    fn commit(db: *Db) Error!void {
        try db.exec("COMMIT");
    }

    fn rollback(db: *Db) void {
        db.exec("ROLLBACK") catch {};
    }

    // --- users -----------------------------------------------------------

    pub const UserError = error{ InvalidName, Duplicate, NotFound, Protected } || Error;
    pub const RoleError = error{ InvalidName, Duplicate, NotFound, InvalidRight, InUse } || Error;

    /// Lowercase letters, digits, "_", "." and "-"; 2 to 32 characters,
    /// starting with a letter.
    pub fn validUserName(name: []const u8) bool {
        if (name.len < 2 or name.len > 32 or !std.ascii.isLower(name[0])) return false;
        for (name) |ch| if (!std.ascii.isLower(ch) and !std.ascii.isDigit(ch) and ch != '_' and ch != '.' and ch != '-') return false;
        return true;
    }

    pub fn userCreate(db: *Db, name: []const u8, superuser: bool, password_hash: []const u8, now: i64) UserError!i64 {
        if (!validUserName(name)) return error.InvalidName;
        var st = try Stmt.prepare(db, "insert into user(name, isSuperuser, passwordHash, created) values(?, ?, ?, ?)");
        defer st.finalize();
        try st.bindText(1, name);
        try st.bindInt(2, @intFromBool(superuser));
        try st.bindText(3, password_hash);
        try st.bindInt(4, now);
        st.done() catch |e| return db.mapUnique(e);
        return c.sqlite3_last_insert_rowid(db.handle);
    }

    const user_select = "select userId, name, isSuperuser, passwordHash, totpConfirmed, totpLastStep, failCount, lockedUntil, disabled, created, nodes from user";

    fn userRow(st: *Stmt, a: std.mem.Allocator) !User {
        return .{
            .id = st.int(0),
            .name = try st.text(a, 1),
            .is_superuser = st.int(2) != 0,
            .password_hash = try st.text(a, 3),
            .totp_confirmed = st.int(4) != 0,
            .totp_last_step = st.int(5),
            .fail_count = st.int(6),
            .locked_until = st.int(7),
            .disabled = st.int(8) != 0,
            .created = st.int(9),
            .nodes = try st.text(a, 10),
        };
    }

    /// The nodes a user may reach with tgterm: name patterns, comma
    /// separated ("ist_*,pump??"); empty: none.
    pub fn userSetNodes(db: *Db, id: i64, nodes: []const u8) (error{InvalidSpec} || UserError)!void {
        if (nodes.len > 0) {
            var it = std.mem.splitScalar(u8, nodes, ',');
            while (it.next()) |p| if (!core.node.isValidPattern(p)) return error.InvalidSpec;
        }
        var st = try Stmt.prepare(db, "update user set nodes = ? where userId = ?");
        defer st.finalize();
        try st.bindText(1, nodes);
        try st.bindInt(2, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    pub fn userByName(db: *Db, a: std.mem.Allocator, name: []const u8) !?User {
        var st = try Stmt.prepare(db, user_select ++ " where name = ?");
        defer st.finalize();
        try st.bindText(1, name);
        if (!try st.step()) return null;
        return try userRow(&st, a);
    }

    pub fn userGet(db: *Db, a: std.mem.Allocator, id: i64) !?User {
        var st = try Stmt.prepare(db, user_select ++ " where userId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        if (!try st.step()) return null;
        return try userRow(&st, a);
    }

    pub fn userList(db: *Db, a: std.mem.Allocator) ![]User {
        var st = try Stmt.prepare(db, user_select ++ " order by name");
        defer st.finalize();
        var list: std.ArrayList(User) = .empty;
        while (try st.step()) try list.append(a, try userRow(&st, a));
        return list.toOwnedSlice(a);
    }

    pub fn userCount(db: *Db) Error!i64 {
        var st = try Stmt.prepare(db, "select count(*) from user");
        defer st.finalize();
        _ = try st.step();
        return st.int(0);
    }

    pub fn userSetName(db: *Db, id: i64, name: []const u8) UserError!void {
        if (!validUserName(name)) return error.InvalidName;
        var st = try Stmt.prepare(db, "update user set name = ? where userId = ?");
        defer st.finalize();
        try st.bindText(1, name);
        try st.bindInt(2, id);
        st.done() catch |e| return db.mapUnique(e);
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// The superuser cannot be deleted.
    pub fn userDelete(db: *Db, id: i64) UserError!void {
        var st = try Stmt.prepare(db, "delete from user where userId = ? and isSuperuser = 0");
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) > 0) return;
        var q = try Stmt.prepare(db, "select 1 from user where userId = ?");
        defer q.finalize();
        try q.bindInt(1, id);
        return if (try q.step()) error.Protected else error.NotFound;
    }

    /// The rights the user's roles give, each as "module:action".
    pub fn userRights(db: *Db, a: std.mem.Allocator, id: i64) ![]const []const u8 {
        var st = try Stmt.prepare(db,
            \\select distinct rr.module || ':' || rr.action from userRole ur
            \\join roleRight rr on rr.roleId = ur.roleId where ur.userId = ?
        );
        defer st.finalize();
        try st.bindInt(1, id);
        var list: std.ArrayList([]const u8) = .empty;
        while (try st.step()) try list.append(a, try st.text(a, 0));
        return list.toOwnedSlice(a);
    }

    pub fn userRoles(db: *Db, a: std.mem.Allocator, id: i64) ![]RoleRef {
        var st = try Stmt.prepare(db, "select r.roleId, r.name from userRole ur join role r on r.roleId = ur.roleId where ur.userId = ? order by r.name");
        defer st.finalize();
        try st.bindInt(1, id);
        var list: std.ArrayList(RoleRef) = .empty;
        while (try st.step()) try list.append(a, .{ .id = st.int(0), .name = try st.text(a, 1) });
        return list.toOwnedSlice(a);
    }

    /// Gives a role to a user. Duplicate: the user has it already.
    pub fn userGrant(db: *Db, user_id: i64, role_id: i64) UserError!void {
        {
            var q = try Stmt.prepare(db, "select (select count(*) from user where userId = ?) + (select count(*) from role where roleId = ?)");
            defer q.finalize();
            try q.bindInt(1, user_id);
            try q.bindInt(2, role_id);
            _ = try q.step();
            if (q.int(0) != 2) return error.NotFound;
        }
        var st = try Stmt.prepare(db, "insert into userRole(userId, roleId) values(?, ?)");
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.bindInt(2, role_id);
        st.done() catch |e| return db.mapUnique(e);
    }

    pub fn userRevoke(db: *Db, user_id: i64, role_id: i64) UserError!void {
        var st = try Stmt.prepare(db, "delete from userRole where userId = ? and roleId = ?");
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.bindInt(2, role_id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    // --- roles -----------------------------------------------------------

    /// Letters, digits, "_" and "-"; 1 to 32 characters, starting with a
    /// letter.
    pub fn validRoleName(name: []const u8) bool {
        if (name.len < 1 or name.len > 32 or !std.ascii.isAlphabetic(name[0])) return false;
        for (name) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '_' and ch != '-') return false;
        return true;
    }

    const role_select = "select r.roleId, r.name, r.description, (select count(*) from userRole where roleId = r.roleId) from role r";

    fn roleRow(st: *Stmt, a: std.mem.Allocator) !Role {
        return .{ .id = st.int(0), .name = try st.text(a, 1), .description = try st.text(a, 2), .user_count = st.int(3) };
    }

    pub fn roleList(db: *Db, a: std.mem.Allocator) ![]Role {
        var st = try Stmt.prepare(db, role_select ++ " order by r.name");
        defer st.finalize();
        var list: std.ArrayList(Role) = .empty;
        while (try st.step()) try list.append(a, try roleRow(&st, a));
        return list.toOwnedSlice(a);
    }

    pub fn roleGet(db: *Db, a: std.mem.Allocator, id: i64) !?Role {
        var st = try Stmt.prepare(db, role_select ++ " where r.roleId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        if (!try st.step()) return null;
        return try roleRow(&st, a);
    }

    /// The rights of a role, each as "module:action".
    pub fn roleRights(db: *Db, a: std.mem.Allocator, id: i64) ![]const []const u8 {
        var st = try Stmt.prepare(db, "select module || ':' || action from roleRight where roleId = ? order by module, action");
        defer st.finalize();
        try st.bindInt(1, id);
        var list: std.ArrayList([]const u8) = .empty;
        while (try st.step()) try list.append(a, try st.text(a, 0));
        return list.toOwnedSlice(a);
    }

    /// Replaces the rights of a role (inside the caller's transaction).
    fn roleWriteRights(db: *Db, id: i64, list: []const []const u8) RoleError!void {
        for (list) |r| if (rights.parse(r) == null) return error.InvalidRight;
        {
            var st = try Stmt.prepare(db, "delete from roleRight where roleId = ?");
            defer st.finalize();
            try st.bindInt(1, id);
            try st.done();
        }
        for (list) |r| {
            const p = rights.parse(r).?;
            var st = try Stmt.prepare(db, "insert or ignore into roleRight(roleId, module, action) values(?, ?, ?)");
            defer st.finalize();
            try st.bindInt(1, id);
            try st.bindText(2, p.module);
            try st.bindText(3, p.action);
            try st.done();
        }
    }

    pub fn roleInsert(db: *Db, name: []const u8, description: []const u8, list: []const []const u8) RoleError!i64 {
        if (!validRoleName(name)) return error.InvalidName;
        try db.begin();
        errdefer db.rollback();
        {
            var st = try Stmt.prepare(db, "insert into role(name, description) values(?, ?)");
            defer st.finalize();
            try st.bindText(1, name);
            try st.bindText(2, description);
            st.done() catch |e| return db.mapUnique(e);
        }
        const id = c.sqlite3_last_insert_rowid(db.handle);
        try db.roleWriteRights(id, list);
        try db.commit();
        return id;
    }

    /// `list`: the role's rights; null leaves them as they are.
    pub fn roleUpdate(db: *Db, id: i64, name: []const u8, description: []const u8, list: ?[]const []const u8) RoleError!void {
        if (!validRoleName(name)) return error.InvalidName;
        try db.begin();
        errdefer db.rollback();
        {
            var st = try Stmt.prepare(db, "update role set name = ?, description = ? where roleId = ?");
            defer st.finalize();
            try st.bindText(1, name);
            try st.bindText(2, description);
            try st.bindInt(3, id);
            st.done() catch |e| return db.mapUnique(e);
            if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
        }
        if (list) |l| try db.roleWriteRights(id, l);
        try db.commit();
    }

    /// How many users have the role named `name` (the last admin is kept).
    pub fn usersWithRole(db: *Db, name: []const u8) Error!i64 {
        var st = try Stmt.prepare(db, "select count(*) from userRole ur join role r on r.roleId = ur.roleId where r.name = ?");
        defer st.finalize();
        try st.bindText(1, name);
        _ = try st.step();
        return st.int(0);
    }

    /// Whether the user has the role named `name`.
    pub fn userHasRole(db: *Db, user_id: i64, name: []const u8) Error!bool {
        var st = try Stmt.prepare(db, "select 1 from userRole ur join role r on r.roleId = ur.roleId where ur.userId = ? and r.name = ?");
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.bindText(2, name);
        return try st.step();
    }

    /// A role given to users cannot be deleted.
    pub fn roleDelete(db: *Db, id: i64) RoleError!void {
        const role = (db.roleGet(std.heap.page_allocator, id) catch return error.SqliteError) orelse return error.NotFound;
        std.heap.page_allocator.free(role.name);
        std.heap.page_allocator.free(role.description);
        if (role.user_count > 0) return error.InUse;
        var st = try Stmt.prepare(db, "delete from role where roleId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
    }

    /// A new password: the second step is set up again and every browser
    /// session of the user ends.
    pub fn userSetPassword(db: *Db, id: i64, password_hash: []const u8) UserError!void {
        try db.begin();
        errdefer db.rollback();
        {
            var st = try Stmt.prepare(db, "update user set passwordHash = ?, totpSecret = null, totpConfirmed = 0, totpLastStep = 0, failCount = 0, lockedUntil = 0 where userId = ?");
            defer st.finalize();
            try st.bindText(1, password_hash);
            try st.bindInt(2, id);
            try st.done();
            if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
        }
        try db.webSessionsDeleteFor(id);
        try db.commit();
    }

    /// The user changed its own password (profile): its second step and
    /// its other browser sessions stay.
    pub fn userSetOwnPassword(db: *Db, id: i64, password_hash: []const u8) UserError!void {
        var st = try Stmt.prepare(db, "update user set passwordHash = ?, failCount = 0 where userId = ?");
        defer st.finalize();
        try st.bindText(1, password_hash);
        try st.bindInt(2, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// A blocked user cannot sign in. The superuser cannot be blocked.
    pub fn userSetDisabled(db: *Db, id: i64, disabled: bool) UserError!void {
        if (disabled) {
            var q = try Stmt.prepare(db, "select 1 from user where userId = ? and isSuperuser = 1");
            defer q.finalize();
            try q.bindInt(1, id);
            if (try q.step()) return error.Protected;
        }
        var st = try Stmt.prepare(db, "update user set disabled = ? where userId = ?");
        defer st.finalize();
        try st.bindInt(1, @intFromBool(disabled));
        try st.bindInt(2, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
        if (disabled) try db.webSessionsDeleteFor(id);
    }

    /// The user's TOTP secret, stored encrypted with the log key.
    pub fn userSetTotpSecret(db: *Db, id: i64, secret: [20]u8) LogError!void {
        const key = db.log_key orelse return error.NoLogKey;
        const gpa = std.heap.smp_allocator;
        const sealed = try sealLog(gpa, db.io.?, key, "user", id, "totp", &secret);
        defer gpa.free(sealed);
        var st = try Stmt.prepare(db, "update user set totpSecret = ?, totpConfirmed = 0, totpLastStep = 0 where userId = ?");
        defer st.finalize();
        try st.bindBlob(1, sealed);
        try st.bindInt(2, id);
        try st.done();
    }

    pub fn userTotpSecret(db: *Db, id: i64) !?[20]u8 {
        const key = db.log_key orelse return error.NoLogKey;
        var st = try Stmt.prepare(db, "select totpSecret from user where userId = ? and totpSecret is not null");
        defer st.finalize();
        try st.bindInt(1, id);
        if (!try st.step()) return null;
        var buf: [128]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const plain = openLog(fba.allocator(), key, "user", id, "totp", st.rawText(0)) catch return null;
        if (plain.len != 20) return null;
        return plain[0..20].*;
    }

    /// A code was accepted for time step `step`.
    pub fn userTotpUsed(db: *Db, id: i64, step: i64) Error!void {
        var st = try Stmt.prepare(db, "update user set totpConfirmed = 1, totpLastStep = ?, failCount = 0, lockedUntil = 0 where userId = ?");
        defer st.finalize();
        try st.bindInt(1, step);
        try st.bindInt(2, id);
        try st.done();
    }

    /// A wrong password or code. From the fifth in a row, sign-in is refused
    /// for a time that doubles: 1, 2, 4 ... minutes, at most an hour.
    pub fn userFailed(db: *Db, id: i64, now: i64) Error!void {
        var st = try Stmt.prepare(db,
            \\update user set failCount = failCount + 1,
            \\  lockedUntil = case when failCount + 1 >= 5
            \\    then ? + min(3600, 60 * (1 << min(failCount + 1 - 5, 6))) else lockedUntil end
            \\where userId = ?
        );
        defer st.finalize();
        try st.bindInt(1, now);
        try st.bindInt(2, id);
        try st.done();
    }

    pub fn userPasswordOk(db: *Db, id: i64) Error!void {
        var st = try Stmt.prepare(db, "update user set failCount = 0, lockedUntil = 0 where userId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
    }

    // --- browser sessions -----------------------------------------------------

    pub fn webSessionCreate(db: *Db, token_hash: []const u8, user_id: i64, now: i64, expires: i64) Error!void {
        var st = try Stmt.prepare(db, "insert into webSession(tokenHash, userId, full, created, expires) values(?, ?, 0, ?, ?)");
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.bindInt(2, user_id);
        try st.bindInt(3, now);
        try st.bindInt(4, expires);
        try st.done();
    }

    /// The session of a token, if it has not expired and its user may
    /// still sign in.
    pub fn webSessionGet(db: *Db, token_hash: []const u8, now: i64) Error!?WebSession {
        var st = try Stmt.prepare(db,
            \\select s.userId, s.full, e.userId from webSession s join user a on a.userId = s.userId
            \\left join user e on e.userId = s.effectiveUserId and e.disabled = 0
            \\where s.tokenHash = ? and s.expires > ? and a.disabled = 0
        );
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.bindInt(2, now);
        if (!try st.step()) return null;
        return .{ .user_id = st.int(0), .full = st.int(1) != 0, .effective_user_id = st.optInt(2) };
    }

    /// The session's user acts as `user_id` from now on (null: as itself).
    pub fn webSessionSetEffective(db: *Db, token_hash: []const u8, user_id: ?i64) Error!void {
        var st = try Stmt.prepare(db, "update webSession set effectiveUserId = ? where tokenHash = ?");
        defer st.finalize();
        try st.bindOptInt(1, user_id);
        try st.bindText(2, token_hash);
        try st.done();
    }

    /// The second step is done: the session is full until `expires`.
    pub fn webSessionPromote(db: *Db, token_hash: []const u8, expires: i64) Error!void {
        var st = try Stmt.prepare(db, "update webSession set full = 1, expires = ? where tokenHash = ?");
        defer st.finalize();
        try st.bindInt(1, expires);
        try st.bindText(2, token_hash);
        try st.done();
    }

    pub fn webSessionDelete(db: *Db, token_hash: []const u8) Error!void {
        var st = try Stmt.prepare(db, "delete from webSession where tokenHash = ?");
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.done();
    }

    pub fn webSessionsDeleteFor(db: *Db, user_id: i64) Error!void {
        var st = try Stmt.prepare(db, "delete from webSession where userId = ?");
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.done();
    }

    pub fn webSessionsPrune(db: *Db, now: i64) Error!void {
        var st = try Stmt.prepare(db, "delete from webSession where expires <= ?");
        defer st.finalize();
        try st.bindInt(1, now);
        try st.done();
    }

    // --- what panel users did -------------------------------------------------

    pub fn actionAdd(db: *Db, at: i64, user: []const u8, call: []const u8, detail: []const u8, ok: bool) Error!void {
        var st = try Stmt.prepare(db, "insert into action(at, user, call, detail, ok) values(?, ?, ?, ?, ?)");
        defer st.finalize();
        try st.bindInt(1, at);
        try st.bindText(2, user);
        try st.bindText(3, call);
        try st.bindText(4, detail);
        try st.bindInt(5, @intFromBool(ok));
        try st.done();
    }

    /// The latest actions, newest first.
    pub fn actionsRecent(db: *Db, a: std.mem.Allocator, limit: i64) ![]Action {
        var st = try Stmt.prepare(db, "select actionId, at, user, call, detail, ok from action order by actionId desc limit ?");
        defer st.finalize();
        try st.bindInt(1, limit);
        var list: std.ArrayList(Action) = .empty;
        while (try st.step()) try list.append(a, .{
            .id = st.int(0),
            .at = st.int(1),
            .user = try st.text(a, 2),
            .call = try st.text(a, 3),
            .detail = try st.text(a, 4),
            .ok = st.int(5) != 0,
        });
        return list.toOwnedSlice(a);
    }

    /// The panel's actions, newest first, a page at a time; `key` (may be
    /// empty) is looked for in who, the call and what it was about.
    pub fn actionsSearch(db: *Db, a: std.mem.Allocator, key: []const u8, page: i64) !Page(Action) {
        const cond = " where (?1 = '' or instr(lower(user), lower(?1)) > 0 or instr(lower(call), lower(?1)) > 0 or instr(lower(detail), lower(?1)) > 0)";
        const p = try db.pageOf("select count(*) from action" ++ cond, key, page);
        var st = try Stmt.prepare(db, "select actionId, at, user, call, detail, ok from action" ++ cond ++ " order by actionId desc limit ?2 offset ?3");
        defer st.finalize();
        try st.bindText(1, key);
        try st.bindInt(2, page_len);
        try st.bindInt(3, p.offset);
        var list: std.ArrayList(Action) = .empty;
        while (try st.step()) try list.append(a, .{
            .id = st.int(0),
            .at = st.int(1),
            .user = try st.text(a, 2),
            .call = try st.text(a, 3),
            .detail = try st.text(a, 4),
            .ok = st.int(5) != 0,
        });
        return .{ .rows = try list.toOwnedSlice(a), .total = p.total, .page = p.page, .pages = p.pages };
    }

    // --- pages of a list ------------------------------------------------------

    /// Rows a page of a list shows
    pub const page_len: i64 = 20;

    /// A page of a list: its rows, how many there are in all, which page it
    /// is (from 1) and how many pages there are.
    pub fn Page(comptime T: type) type {
        return struct { rows: []T, total: i64, page: i64, pages: i64 };
    }

    /// Counts the rows (`count_sql` takes the key as ?1) and fits `page`
    /// to them: the first page below 1, the last above the end.
    fn pageOf(db: *Db, count_sql: [:0]const u8, key: []const u8, page: i64) Error!struct { total: i64, page: i64, pages: i64, offset: i64 } {
        var st = try Stmt.prepare(db, count_sql);
        defer st.finalize();
        try st.bindText(1, key);
        _ = try st.step();
        const total = st.int(0);
        const pages = @max(1, @divFloor(total + page_len - 1, page_len));
        const p = std.math.clamp(page, 1, pages);
        return .{ .total = total, .page = p, .pages = pages, .offset = (p - 1) * page_len };
    }

    // --- settings -----------------------------------------------------------

    pub fn settingsGet(db: *Db) Error!Settings {
        var out: Settings = .{};
        var st = try Stmt.prepare(db, "select name, value from setting");
        defer st.finalize();
        while (try st.step()) {
            const name = st.rawText(0);
            inline for (@typeInfo(Settings).@"struct".field_names) |fname| {
                if (std.mem.eql(u8, name, fname)) @field(out, fname) = st.int(1);
            }
        }
        return out;
    }

    pub fn settingsSet(db: *Db, v: Settings) (error{InvalidSpec} || Error)!void {
        if (v.ruler_len < 2 or v.ruler_len > 10) return error.InvalidSpec;
        try db.begin();
        errdefer db.rollback();
        inline for (@typeInfo(Settings).@"struct".field_names) |fname| {
            var st = try Stmt.prepare(db, "insert into setting(name, value) values(?, ?) on conflict(name) do update set value = excluded.value");
            defer st.finalize();
            try st.bindText(1, fname);
            try st.bindInt(2, @field(v, fname));
            try st.done();
        }
        try db.commit();
    }

    // --- session logs ---------------------------------------------------------

    /// Stores one command; what was typed and the output are encrypted
    /// (sealLog), the rest (session, order, time, length) is not.
    pub fn commandAdd(db: *Db, sid: []const u8, cmd: Command) LogError!void {
        const key = db.log_key orelse return error.NoLogKey;
        const gpa = std.heap.smp_allocator;
        const line = try sealLog(gpa, db.io.?, key, sid, cmd.seq, "line", cmd.line);
        defer gpa.free(line);
        const output = try sealLog(gpa, db.io.?, key, sid, cmd.seq, "output", cmd.output);
        defer gpa.free(output);
        var st = try Stmt.prepare(db, "insert or replace into sessionCommand(sid, seq, at, line, output, outputChars) values(?, ?, ?, ?, ?, ?)");
        defer st.finalize();
        try st.bindText(1, sid);
        try st.bindInt(2, cmd.seq);
        try st.bindInt(3, cmd.at);
        try st.bindBlob(4, line);
        try st.bindBlob(5, output);
        try st.bindInt(6, cmd.output_chars);
        try st.done();
    }

    /// A session's commands in order, decrypted. A command that does not
    /// decrypt (changed in the database, or another key) comes back with
    /// `intact` false and empty text.
    pub fn commandsOf(db: *Db, a: std.mem.Allocator, sid: []const u8) ![]Command {
        const key = db.log_key orelse return error.NoLogKey;
        var st = try Stmt.prepare(db, "select seq, at, line, output, outputChars from sessionCommand where sid = ? order by seq");
        defer st.finalize();
        try st.bindText(1, sid);
        var list: std.ArrayList(Command) = .empty;
        while (try st.step()) {
            const seq = st.int(0);
            const line = openLog(a, key, sid, seq, "line", st.rawText(2));
            const output = openLog(a, key, sid, seq, "output", st.rawText(3));
            const intact = if (line) |_| (if (output) |_| true else |_| false) else |_| false;
            try list.append(a, .{
                .seq = seq,
                .at = st.int(1),
                .line = line catch "",
                .output = output catch "",
                .output_chars = st.int(4),
                .intact = intact,
            });
        }
        return list.toOwnedSlice(a);
    }

    pub const LogError = error{NoLogKey} || Error;

    /// Deletes commands logged before `before`; returns how many.
    pub fn commandsPrune(db: *Db, before: i64) Error!usize {
        var st = try Stmt.prepare(db, "delete from sessionCommand where at < ?");
        defer st.finalize();
        try st.bindInt(1, before);
        try st.done();
        return @intCast(c.sqlite3_changes(db.handle));
    }

    // --- nodes --------------------------------------------------------------

    pub const NodeError = types.NodeError;

    /// The admin creates a node; `token_hash` is the hash of its node key's
    /// token, valid until `token_expires`.
    pub fn nodeCreate(db: *Db, name: []const u8, description: []const u8, token_hash: []const u8, token_expires: i64, now: i64) NodeError!i64 {
        if (!core.node.isValidName(name)) return error.InvalidName;
        var st = try Stmt.prepare(db,
            \\insert into node(name, description, state, tokenHash, tokenExpires, created)
            \\values(?, ?, 'waiting', ?, ?, ?)
        );
        defer st.finalize();
        try st.bindText(1, name);
        try st.bindText(2, description);
        try st.bindText(3, token_hash);
        try st.bindInt(4, token_expires);
        try st.bindInt(5, now);
        st.done() catch |e| return db.mapUnique(e);
        return c.sqlite3_last_insert_rowid(db.handle);
    }

    /// A new node key for an existing node (e.g. the hardware was replaced).
    /// The node keeps working with its current key until the new one is
    /// approved.
    pub fn nodeNewToken(db: *Db, id: i64, token_hash: []const u8, token_expires: i64) NodeError!void {
        var st = try Stmt.prepare(db,
            \\update node set tokenHash = ?, tokenExpires = ?, requestKey = null,
            \\  state = case when hardwareKey is null then 'waiting' else state end
            \\where nodeId = ?
        );
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.bindInt(2, token_expires);
        try st.bindInt(3, id);
        st.done() catch |e| return db.mapUnique(e);
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// The node whose unexpired node key has this token id (subject
    /// register.<id>).
    pub fn nodeByTokenId(db: *Db, a: std.mem.Allocator, token_id: []const u8, now: i64) !?Node {
        var st = try Stmt.prepare(db, node_select ++ " where substr(tokenHash, 1, 16) = ? and tokenExpires > ? and state != 'disabled'");
        defer st.finalize();
        try st.bindText(1, token_id);
        try st.bindInt(2, now);
        if (!try st.step()) return null;
        return try st.node(a);
    }

    /// The node whose unexpired node key has this token hash.
    pub fn nodeByToken(db: *Db, a: std.mem.Allocator, token_hash: []const u8, now: i64) !?Node {
        var st = try Stmt.prepare(db, node_select ++ " where tokenHash = ? and tokenExpires > ? and state != 'disabled'");
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.bindInt(2, now);
        if (!try st.step()) return null;
        return try st.node(a);
    }

    /// The approved node with this hardware key.
    pub fn nodeByKey(db: *Db, a: std.mem.Allocator, hardware_key: []const u8) !?Node {
        var st = try Stmt.prepare(db, node_select ++ " where hardwareKey = ? and state = 'approved'");
        defer st.finalize();
        try st.bindText(1, hardware_key);
        if (!try st.step()) return null;
        return try st.node(a);
    }

    pub fn nodeGet(db: *Db, a: std.mem.Allocator, id: i64) !?Node {
        var st = try Stmt.prepare(db, node_select ++ " where nodeId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        if (!try st.step()) return null;
        return try st.node(a);
    }

    /// All nodes by name.
    /// Nodes by name, a page at a time; `key` (may be empty) is looked for
    /// in the name and the description.
    pub fn nodeSearch(db: *Db, a: std.mem.Allocator, key: []const u8, page: i64) !Page(Node) {
        const cond = " where (?1 = '' or instr(lower(name), lower(?1)) > 0 or instr(lower(description), lower(?1)) > 0)";
        const p = try db.pageOf("select count(*) from node" ++ cond, key, page);
        var st = try Stmt.prepare(db, node_select ++ cond ++ " order by name limit ?2 offset ?3");
        defer st.finalize();
        try st.bindText(1, key);
        try st.bindInt(2, page_len);
        try st.bindInt(3, p.offset);
        var list: std.ArrayList(Node) = .empty;
        while (try st.step()) try list.append(a, try st.node(a));
        return .{ .rows = try list.toOwnedSlice(a), .total = p.total, .page = p.page, .pages = p.pages };
    }

    /// How many nodes there are, are online and wait for approval.
    pub fn nodeSummary(db: *Db) Error!struct { total: i64, online: i64, pending: i64 } {
        var st = try Stmt.prepare(db, "select count(*), coalesce(sum(online), 0), coalesce(sum(state = 'pending'), 0) from node");
        defer st.finalize();
        _ = try st.step();
        return .{ .total = st.int(0), .online = st.int(1), .pending = st.int(2) };
    }

    pub fn nodeList(db: *Db, a: std.mem.Allocator) ![]Node {
        var st = try Stmt.prepare(db, node_select ++ " order by name");
        defer st.finalize();
        var list: std.ArrayList(Node) = .empty;
        while (try st.step()) try list.append(a, try st.node(a));
        return list.toOwnedSlice(a);
    }

    /// A registration request arrived with a node key: remember the key and
    /// the system info until the admin decides.
    pub fn nodeRecordRequest(db: *Db, id: i64, request_key: []const u8, status_json: []const u8, now: i64) NodeError!void {
        var st = try Stmt.prepare(db,
            \\update node set requestKey = ?, status = ?, lastSeen = ?,
            \\  state = case when state = 'waiting' then 'pending' else state end
            \\where nodeId = ?
        );
        defer st.finalize();
        try st.bindText(1, request_key);
        try st.bindText(2, status_json);
        try st.bindInt(3, now);
        try st.bindInt(4, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// The admin approves the pending request: its key becomes the node's
    /// hardware key. The node key stays valid until the node has been told
    /// (nodeFinishRegistration), since tgnode learns about the approval with
    /// its next registration request.
    pub fn nodeApprove(db: *Db, id: i64) NodeError!void {
        var st = try Stmt.prepare(db,
            \\update node set hardwareKey = requestKey, requestKey = null, state = 'approved'
            \\where nodeId = ? and requestKey is not null
        );
        defer st.finalize();
        try st.bindInt(1, id);
        st.done() catch |e| return db.mapUnique(e);
        if (c.sqlite3_changes(db.handle) == 0) return error.WrongState;
    }

    /// The node has received its approval: the node key is used up.
    pub fn nodeFinishRegistration(db: *Db, id: i64) NodeError!void {
        var st = try Stmt.prepare(db, "update node set tokenHash = null, tokenExpires = null where nodeId = ? and state = 'approved'");
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.WrongState;
    }

    /// The admin rejects the pending request; the node key stays usable.
    pub fn nodeReject(db: *Db, id: i64) NodeError!void {
        var st = try Stmt.prepare(db,
            \\update node set requestKey = null,
            \\  state = case when hardwareKey is null then 'waiting' else state end
            \\where nodeId = ?
        );
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    pub fn nodeSetDisabled(db: *Db, id: i64, disabled: bool) NodeError!void {
        var st = try Stmt.prepare(db,
            \\update node set state = case
            \\  when ? then 'disabled'
            \\  when hardwareKey is not null then 'approved'
            \\  when requestKey is not null then 'pending'
            \\  else 'waiting' end
            \\where nodeId = ?
        );
        defer st.finalize();
        try st.bindInt(1, @intFromBool(disabled));
        try st.bindInt(2, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// The nodes connected to the relay now (by name); every other node is
    /// offline. Nodes that go offline keep `now` as their last seen time.
    pub fn nodeSetOnline(db: *Db, names: []const []const u8, now: i64) Error!void {
        try db.begin();
        errdefer db.rollback();
        {
            var st = try Stmt.prepare(db, "update node set online = 0, lastSeen = ? where online = 1");
            defer st.finalize();
            try st.bindInt(1, now);
            try st.done();
        }
        for (names) |name| {
            var st = try Stmt.prepare(db, "update node set online = 1, lastSeen = ? where name = ? and state = 'approved'");
            defer st.finalize();
            try st.bindInt(1, now);
            try st.bindText(2, name);
            try st.done();
        }
        try db.commit();
    }

    /// System info (status.<node>) from an approved node.
    pub fn nodeRecordStatus(db: *Db, name: []const u8, status_json: []const u8, now: i64) Error!void {
        var st = try Stmt.prepare(db, "update node set status = ?, lastSeen = ? where name = ? and state = 'approved'");
        defer st.finalize();
        try st.bindText(1, status_json);
        try st.bindInt(2, now);
        try st.bindText(3, name);
        try st.done();
    }

    pub fn nodeDelete(db: *Db, id: i64) NodeError!void {
        var st = try Stmt.prepare(db, "delete from node where nodeId = ?");
        defer st.finalize();
        try st.bindInt(1, id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    // --- terminal access --------------------------------------------------

    pub const TerminalError = types.TerminalError;
    pub const TerminalSpec = types.TerminalSpec;

    /// Who may connect: a user not blocked, its access not revoked, with
    /// terminal:connect from a role (or the superuser). For a query over
    /// terminal t joined with user u.
    const may_connect =
        \\t.revoked = 0 and u.disabled = 0 and (u.isSuperuser = 1 or exists (
        \\  select 1 from userRole ur join roleRight rr on rr.roleId = ur.roleId
        \\  where ur.userId = u.userId and rr.module = 'terminal' and rr.action = 'connect'))
    ;

    /// An admin gives `user_id` terminal access: a new invitation with
    /// this token hash, usable until `token_expires`, with its limits. The
    /// access the user had before (its key, its sessions count) ends.
    pub fn terminalInvite(db: *Db, user_id: i64, spec: TerminalSpec, token_hash: []const u8, token_expires: i64, now: i64) TerminalError!void {
        if (spec.max_uses == null and spec.expires == null) return error.InvalidSpec;
        if (spec.max_uses) |m| if (m == 0) return error.InvalidSpec;
        if (!try db.hasId("select 1 from user where userId = ?", user_id)) return error.NotFound;
        var st = try Stmt.prepare(db,
            \\insert or replace into terminal(userId, kind, userKey, tokenHash, tokenExpires, maxUses, expires, uses, revoked, created)
            \\values(?, ?, null, ?, ?, ?, ?, 0, 0, ?)
        );
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.bindText(2, @tagName(spec.kind));
        try st.bindText(3, token_hash);
        try st.bindInt(4, token_expires);
        try st.bindOptInt(5, if (spec.max_uses) |m| m else null);
        try st.bindOptInt(6, spec.expires);
        try st.bindInt(7, now);
        st.done() catch |e| return db.mapUnique(e);
    }

    fn hasId(db: *Db, sql: [:0]const u8, id: i64) Error!bool {
        var st = try Stmt.prepare(db, sql);
        defer st.finalize();
        try st.bindInt(1, id);
        return try st.step();
    }

    /// The access whose unused, unexpired invitation has this token id
    /// (subject invite.<id>).
    pub fn terminalByTokenId(db: *Db, a: std.mem.Allocator, token_id: []const u8, now: i64) !?Terminal {
        var st = try Stmt.prepare(db, terminal_select ++ " where substr(t.tokenHash, 1, 16) = ? and t.tokenExpires > ? and t.userKey is null and " ++ may_connect);
        defer st.finalize();
        try st.bindText(1, token_id);
        try st.bindInt(2, now);
        if (!try st.step()) return null;
        return try st.terminal(a);
    }

    /// The access whose unused, unexpired invitation has this token hash.
    pub fn terminalByToken(db: *Db, a: std.mem.Allocator, token_hash: []const u8, now: i64) !?Terminal {
        var st = try Stmt.prepare(db, terminal_select ++ " where t.tokenHash = ? and t.tokenExpires > ? and t.userKey is null and " ++ may_connect);
        defer st.finalize();
        try st.bindText(1, token_hash);
        try st.bindInt(2, now);
        if (!try st.step()) return null;
        return try st.terminal(a);
    }

    /// The access with this user key, if the user may connect now.
    pub fn terminalByKey(db: *Db, a: std.mem.Allocator, user_key: []const u8) !?Terminal {
        var st = try Stmt.prepare(db, terminal_select ++ " where t.userKey = ? and " ++ may_connect);
        defer st.finalize();
        try st.bindText(1, user_key);
        if (!try st.step()) return null;
        return try st.terminal(a);
    }

    /// A user's terminal access, whatever its state; null: none given.
    pub fn terminalGet(db: *Db, a: std.mem.Allocator, user_id: i64) !?Terminal {
        var st = try Stmt.prepare(db, terminal_select ++ " where t.userId = ?");
        defer st.finalize();
        try st.bindInt(1, user_id);
        if (!try st.step()) return null;
        return try st.terminal(a);
    }

    /// The keys of users who have used their invitation but may not
    /// connect any more (revoked, blocked, or no terminal:connect): their
    /// connections are to be closed.
    pub fn terminalKeysDenied(db: *Db, a: std.mem.Allocator) ![]const []const u8 {
        var st = try Stmt.prepare(db, "select t.userKey from terminal t join user u on u.userId = t.userId where t.userKey is not null and not (" ++ may_connect ++ ")");
        defer st.finalize();
        var list: std.ArrayList([]const u8) = .empty;
        while (try st.step()) try list.append(a, try st.text(a, 0));
        return list.toOwnedSlice(a);
    }

    /// The invitation is used: bind the key and use up the token.
    pub fn terminalRedeem(db: *Db, user_id: i64, user_key: []const u8) TerminalError!void {
        var st = try Stmt.prepare(db, "update terminal set userKey = ?, tokenHash = null, tokenExpires = null where userId = ? and userKey is null");
        defer st.finalize();
        try st.bindText(1, user_key);
        try st.bindInt(2, user_id);
        st.done() catch |e| return db.mapUnique(e);
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    /// Revoking ends a user's terminal access: its connections are refused
    /// (callout) and no session opens any more.
    pub fn terminalRevoke(db: *Db, user_id: i64) TerminalError!void {
        var st = try Stmt.prepare(db, "update terminal set revoked = 1 where userId = ?");
        defer st.finalize();
        try st.bindInt(1, user_id);
        try st.done();
        if (c.sqlite3_changes(db.handle) == 0) return error.NotFound;
    }

    // --- sessions ---------------------------------------------------------

    pub const UseResult = union(enum) {
        allowed,
        denied: []const u8,
    };

    /// A node asks to open a session for the user with this key. Decided
    /// here, from the database: the user may connect (not blocked, access
    /// not revoked, terminal:connect from a role), the node matches one of
    /// the user's node patterns, the invitation has not ended and has uses
    /// left. On success counts the use and records the session start. One
    /// transaction, so concurrent requests cannot exceed the uses.
    pub fn terminalUse(db: *Db, user_key: []const u8, node: []const u8, sid: []const u8, now: i64) Error!UseResult {
        try db.begin();
        var committed = false;
        defer if (!committed) db.rollback();

        var name_buf: [128]u8 = undefined;
        var name: []const u8 = "";
        {
            var st = try Stmt.prepare(db, "select t.maxUses, t.uses, t.expires, case when " ++ may_connect ++ " then 0 else 1 end, u.name, u.nodes " ++
                "from terminal t join user u on u.userId = t.userId where t.userKey = ?");
            defer st.finalize();
            try st.bindText(1, user_key);
            if (!try st.step()) return .{ .denied = "unknown key" };
            const max_uses = st.optInt(0);
            const uses = st.int(1);
            const expires = st.optInt(2);
            const raw = st.rawText(4);
            name = name_buf[0..@min(raw.len, name_buf.len)];
            @memcpy(@constCast(name), raw[0..name.len]);
            if (st.int(3) != 0) return .{ .denied = "access revoked" };
            if (expires) |e| if (now >= e) return .{ .denied = "access expired" };
            if (max_uses) |m| if (uses >= m) return .{ .denied = "no uses left" };
            var allowed = false;
            var it = std.mem.splitScalar(u8, st.rawText(5), ',');
            while (it.next()) |pattern| {
                if (pattern.len > 0 and core.node.globMatch(pattern, node)) allowed = true;
            }
            if (!allowed) return .{ .denied = "this node is not among the user's nodes" };
        }
        {
            var up = try Stmt.prepare(db, "update terminal set uses = uses + 1 where userKey = ?");
            defer up.finalize();
            try up.bindText(1, user_key);
            try up.done();
        }
        {
            var ins = try Stmt.prepare(db, "insert into session(sid, node, userKey, userName, started) values(?, ?, ?, ?, ?)");
            defer ins.finalize();
            try ins.bindText(1, sid);
            try ins.bindText(2, node);
            try ins.bindText(3, user_key);
            try ins.bindText(4, name);
            try ins.bindInt(5, now);
            try ins.done();
        }
        try db.commit();
        committed = true;
        return .allowed;
    }

    /// The node reported the end of a session (audit.<node>). Repeated reports
    /// (retries) change nothing.
    pub fn sessionEnd(db: *Db, sid: []const u8, at: i64, exit_status: i64) Error!void {
        var st = try Stmt.prepare(db, "update session set ended = ?, exitStatus = ? where sid = ? and ended is null");
        defer st.finalize();
        try st.bindInt(1, at);
        try st.bindInt(2, exit_status);
        try st.bindText(3, sid);
        try st.done();
    }

    /// Marks every open session on `node` ended (the node was cut off and
    /// cannot report them); exit status unknown.
    pub fn sessionsEndNode(db: *Db, node: []const u8, at: i64) Error!void {
        var st = try Stmt.prepare(db, "update session set ended = ? where node = ? and ended is null");
        defer st.finalize();
        try st.bindInt(1, at);
        try st.bindText(2, node);
        try st.done();
    }

    /// The session's end-to-end keys (termgate reads the session for its log
    /// and for watching). Stored encrypted with the log key.
    pub fn sessionSetKeys(db: *Db, sid: []const u8, keys: core.e2e.Keys) LogError!void {
        const key = db.log_key orelse return error.NoLogKey;
        const gpa = std.heap.smp_allocator;
        var plain: [64]u8 = undefined;
        plain[0..32].* = keys.up;
        plain[32..].* = keys.down;
        defer std.crypto.secureZero(u8, &plain);
        const sealed = try sealLog(gpa, db.io.?, key, sid, 0, "session-keys", &plain);
        defer gpa.free(sealed);
        var st = try Stmt.prepare(db, "update session set keys = ? where sid = ?");
        defer st.finalize();
        try st.bindBlob(1, sealed);
        try st.bindText(2, sid);
        try st.done();
    }

    pub fn sessionKeys(db: *Db, sid: []const u8) !?core.e2e.Keys {
        const key = db.log_key orelse return error.NoLogKey;
        var st = try Stmt.prepare(db, "select keys from session where sid = ? and keys is not null");
        defer st.finalize();
        try st.bindText(1, sid);
        if (!try st.step()) return null;
        var buf: [256]u8 = undefined;
        var fba: std.heap.FixedBufferAllocator = .init(&buf);
        const plain = openLog(fba.allocator(), key, sid, 0, "session-keys", st.rawText(0)) catch return null;
        if (plain.len != 64) return null;
        defer std.crypto.secureZero(u8, plain);
        return .{ .up = plain[0..32].*, .down = plain[32..64].* };
    }

    /// Sessions that have not ended, newest first.
    pub fn sessionsActive(db: *Db, a: std.mem.Allocator) ![]Session {
        return db.sessionQuery(a, session_select ++ " where ended is null order by started desc, sessionId desc", null);
    }

    /// The latest sessions (audit view), newest first.
    pub fn sessionsRecent(db: *Db, a: std.mem.Allocator, limit: i64) ![]Session {
        return db.sessionQuery(a, session_select ++ " order by started desc, sessionId desc limit ?", limit);
    }

    /// Sessions, newest first, a page at a time; `key` (may be empty) is
    /// looked for in the node's and the user's name.
    pub fn sessionsSearch(db: *Db, a: std.mem.Allocator, key: []const u8, page: i64) !Page(Session) {
        const cond = " where (?1 = '' or instr(lower(node), lower(?1)) > 0 or instr(lower(userName), lower(?1)) > 0)";
        const p = try db.pageOf("select count(*) from session" ++ cond, key, page);
        var st = try Stmt.prepare(db, session_select ++ cond ++ " order by started desc, sessionId desc limit ?2 offset ?3");
        defer st.finalize();
        try st.bindText(1, key);
        try st.bindInt(2, page_len);
        try st.bindInt(3, p.offset);
        var list: std.ArrayList(Session) = .empty;
        while (try st.step()) try list.append(a, try sessionRow(&st, a));
        return .{ .rows = try list.toOwnedSlice(a), .total = p.total, .page = p.page, .pages = p.pages };
    }

    fn sessionRow(st: *Stmt, a: std.mem.Allocator) !Session {
        return .{
            .sid = try st.text(a, 0),
            .node = try st.text(a, 1),
            .user_key = try st.text(a, 2),
            .user = try st.text(a, 3),
            .started = st.int(4),
            .ended = st.optInt(5),
            .exit_status = st.optInt(6),
        };
    }

    /// The latest sessions on one node, newest first.
    pub fn sessionsOfNode(db: *Db, a: std.mem.Allocator, node: []const u8, limit: i64) ![]Session {
        return db.sessionQueryNode(a, session_select ++ " where node = ? order by started desc, sessionId desc limit ?", node, limit);
    }

    fn sessionQuery(db: *Db, a: std.mem.Allocator, sql: [:0]const u8, limit: ?i64) ![]Session {
        return db.sessionQueryNode(a, sql, null, limit);
    }

    fn sessionQueryNode(db: *Db, a: std.mem.Allocator, sql: [:0]const u8, node: ?[]const u8, limit: ?i64) ![]Session {
        var st = try Stmt.prepare(db, sql);
        defer st.finalize();
        var i: c_int = 1;
        if (node) |n| {
            try st.bindText(i, n);
            i += 1;
        }
        if (limit) |l| try st.bindInt(i, l);
        var list: std.ArrayList(Session) = .empty;
        while (try st.step()) try list.append(a, .{
            .sid = try st.text(a, 0),
            .node = try st.text(a, 1),
            .user_key = try st.text(a, 2),
            .user = try st.text(a, 3),
            .started = st.int(4),
            .ended = st.optInt(5),
            .exit_status = st.optInt(6),
        });
        return list.toOwnedSlice(a);
    }

    const session_select = "select sid, node, userKey, userName, started, ended, exitStatus from session";
    const terminal_select = "select t.userId, u.name, t.kind, t.userKey, u.nodes, t.maxUses, t.expires, t.revoked, t.created, t.tokenExpires, t.uses " ++
        "from terminal t join user u on u.userId = t.userId";

    const node_select = "select nodeId, name, description, state, hardwareKey, requestKey, status, created, lastSeen, tokenExpires, online from node";

    fn mapUnique(db: *Db, e: Error) error{ Duplicate, SqliteError, OutOfMemory } {
        if (e == error.SqliteError) {
            const code = c.sqlite3_extended_errcode(db.handle);
            if (code == c.SQLITE_CONSTRAINT_UNIQUE or code == c.SQLITE_CONSTRAINT_PRIMARYKEY) return error.Duplicate;
        }
        return e;
    }
};

const Stmt = struct {
    db: *Db,
    handle: *c.sqlite3_stmt,

    fn prepare(db: *Db, sql: [:0]const u8) Error!Stmt {
        var h: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db.handle, sql.ptr, @intCast(sql.len + 1), &h, null) != c.SQLITE_OK)
            return error.SqliteError;
        return .{ .db = db, .handle = h.? };
    }

    fn finalize(st: *Stmt) void {
        _ = c.sqlite3_finalize(st.handle);
    }

    fn bindInt(st: *Stmt, idx: c_int, v: i64) Error!void {
        if (c.sqlite3_bind_int64(st.handle, idx, v) != c.SQLITE_OK) return error.SqliteError;
    }

    fn bindText(st: *Stmt, idx: c_int, v: []const u8) Error!void {
        if (c.sqlite3_bind_text(st.handle, idx, v.ptr, @intCast(v.len), termgate_sqlite_transient()) != c.SQLITE_OK)
            return error.SqliteError;
    }

    /// true while there is a row, false when done.
    fn step(st: *Stmt) Error!bool {
        return switch (c.sqlite3_step(st.handle)) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => error.SqliteError,
        };
    }

    fn done(st: *Stmt) Error!void {
        if (try st.step()) return error.SqliteError;
    }

    fn int(st: *Stmt, col: c_int) i64 {
        return c.sqlite3_column_int64(st.handle, col);
    }

    fn optInt(st: *Stmt, col: c_int) ?i64 {
        if (c.sqlite3_column_type(st.handle, col) == c.SQLITE_NULL) return null;
        return st.int(col);
    }

    fn text(st: *Stmt, a: std.mem.Allocator, col: c_int) ![]const u8 {
        const p = c.sqlite3_column_text(st.handle, col);
        const n: usize = @intCast(c.sqlite3_column_bytes(st.handle, col));
        if (p == null) return "";
        return a.dupe(u8, p[0..n]);
    }

    fn bindOptInt(st: *Stmt, idx: c_int, v: ?i64) Error!void {
        if (v) |x| return st.bindInt(idx, x);
        if (c.sqlite3_bind_null(st.handle, idx) != c.SQLITE_OK) return error.SqliteError;
    }

    /// Column text without copying; valid until the next step.
    fn bindBlob(st: *Stmt, idx: c_int, v: []const u8) Error!void {
        if (c.sqlite3_bind_blob(st.handle, idx, v.ptr, @intCast(v.len), termgate_sqlite_transient()) != c.SQLITE_OK)
            return error.SqliteError;
    }

    fn rawText(st: *Stmt, col: c_int) []const u8 {
        const p = c.sqlite3_column_text(st.handle, col);
        if (p == null) return "";
        return p[0..@intCast(c.sqlite3_column_bytes(st.handle, col))];
    }

    fn terminal(st: *Stmt, a: std.mem.Allocator) !Terminal {
        return .{
            .id = st.int(0),
            .name = try st.text(a, 1),
            .kind = std.meta.stringToEnum(types.TerminalKind, st.rawText(2)) orelse return error.SqliteError,
            .user_key = try st.optText(a, 3),
            .nodes = try st.text(a, 4),
            .max_uses = st.optInt(5),
            .expires = st.optInt(6),
            .revoked = st.int(7) != 0,
            .created = st.int(8),
            .token_expires = st.optInt(9),
            .uses = st.int(10),
        };
    }

    fn optText(st: *Stmt, a: std.mem.Allocator, col: c_int) !?[]const u8 {
        if (c.sqlite3_column_type(st.handle, col) == c.SQLITE_NULL) return null;
        return try st.text(a, col);
    }

    fn node(st: *Stmt, a: std.mem.Allocator) !Node {
        const state_text = try st.text(a, 3);
        return .{
            .id = st.int(0),
            .name = try st.text(a, 1),
            .description = try st.text(a, 2),
            .state = std.meta.stringToEnum(NodeState, state_text) orelse return error.SqliteError,
            .hardware_key = try st.optText(a, 4),
            .request_key = try st.optText(a, 5),
            .status = try st.optText(a, 6),
            .created = st.int(7),
            .last_seen = st.optInt(8),
            .token_expires = st.optInt(9),
            .online = st.int(10) != 0,
        };
    }
};

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const t0: i64 = 1794289057;

fn testDb() !Db {
    var db = try Db.open(":memory:");
    db.setLogKey(testing.io, @splat(7));
    return db;
}

test "node registration: waiting, pending, approved" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const th = tokenHash("TOKEN1");
    const id = try db.nodeCreate("ist_kadikoy_gw01", "Kadikoy pump station", &th, t0 + 86400, t0);
    try testing.expectEqual(NodeState.waiting, (try db.nodeGet(a, id)).?.state);

    // The node key works until it expires
    try testing.expect((try db.nodeByToken(a, &th, t0)) != null);
    try testing.expect((try db.nodeByToken(a, &th, t0 + 86400)) == null);
    const other = tokenHash("OTHER");
    try testing.expect((try db.nodeByToken(a, &other, t0)) == null);

    // Registration request, then the admin approves
    try db.nodeRecordRequest(id, "UHWKEY", "{\"hostname\":\"box\"}", t0 + 10);
    const pending = (try db.nodeGet(a, id)).?;
    try testing.expectEqual(NodeState.pending, pending.state);
    try testing.expectEqualStrings("UHWKEY", pending.request_key.?);
    try testing.expect((try db.nodeByKey(a, "UHWKEY")) == null);

    try db.nodeApprove(id);
    const n = (try db.nodeByKey(a, "UHWKEY")).?;
    try testing.expectEqual(NodeState.approved, n.state);
    try testing.expectEqualStrings("ist_kadikoy_gw01", n.name);
    // The node key works until the node has been told, then it is used up
    const tid = core.code.tokenId("TOKEN1");
    try testing.expect((try db.nodeByTokenId(a, &tid, t0)) != null);
    try db.nodeFinishRegistration(id);
    try testing.expect((try db.nodeByToken(a, &th, t0)) == null);
    try testing.expect((try db.nodeByTokenId(a, &tid, t0)) == null);
    try testing.expectError(error.WrongState, db.nodeApprove(id));
}

test "node names are unique and valid; a hardware key belongs to one node" {
    var db = try testDb();
    defer db.close();
    const t1 = tokenHash("T1");
    const t2 = tokenHash("T2");
    const id1 = try db.nodeCreate("gw1", "", &t1, t0 + 100, t0);
    try testing.expectError(error.Duplicate, db.nodeCreate("gw1", "", &t2, t0 + 100, t0));
    try testing.expectError(error.InvalidName, db.nodeCreate("GW-2", "", &t2, t0 + 100, t0));
    const id2 = try db.nodeCreate("gw2", "", &t2, t0 + 100, t0);

    try db.nodeRecordRequest(id1, "UKEY", "{}", t0);
    try db.nodeApprove(id1);
    // The same hardware cannot be approved as a second node
    try db.nodeRecordRequest(id2, "UKEY", "{}", t0);
    try testing.expectError(error.Duplicate, db.nodeApprove(id2));
}

test "reject, disable, new node key, status, online, list, delete" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const th = tokenHash("T");
    const id = try db.nodeCreate("pump07", "", &th, t0 + 100, t0);
    try db.nodeRecordRequest(id, "UWRONG", "{}", t0);
    try db.nodeReject(id);
    try testing.expectEqual(NodeState.waiting, (try db.nodeGet(a, id)).?.state);
    try db.nodeRecordRequest(id, "URIGHT", "{}", t0);
    try db.nodeApprove(id);

    try db.nodeRecordStatus("pump07", "{\"cpus\":4}", t0 + 50);
    const n = (try db.nodeGet(a, id)).?;
    try testing.expectEqualStrings("{\"cpus\":4}", n.status.?);
    try testing.expectEqual(@as(?i64, t0 + 50), n.last_seen);
    try testing.expect(!n.online);

    try db.nodeSetOnline(&.{ "pump07", "unknown" }, t0 + 60);
    try testing.expect((try db.nodeGet(a, id)).?.online);
    try db.nodeSetOnline(&.{}, t0 + 70);
    const off = (try db.nodeGet(a, id)).?;
    try testing.expect(!off.online);
    try testing.expectEqual(@as(?i64, t0 + 70), off.last_seen);

    try db.nodeSetDisabled(id, true);
    try testing.expect((try db.nodeByKey(a, "URIGHT")) == null);
    try db.nodeSetDisabled(id, false);
    try testing.expect((try db.nodeByKey(a, "URIGHT")) != null);

    // Hardware replaced: a new node key; the old key keeps working until approval
    const th2 = tokenHash("T2");
    try db.nodeNewToken(id, &th2, t0 + 200);
    try testing.expect((try db.nodeByKey(a, "URIGHT")) != null);
    try db.nodeRecordRequest(id, "UNEWHW", "{}", t0 + 60);
    try db.nodeApprove(id);
    try testing.expect((try db.nodeByKey(a, "URIGHT")) == null);
    try testing.expect((try db.nodeByKey(a, "UNEWHW")) != null);

    try testing.expectEqual(@as(usize, 1), (try db.nodeList(a)).len);
    try db.nodeDelete(id);
    try testing.expectEqual(@as(usize, 0), (try db.nodeList(a)).len);
    try testing.expectError(error.NotFound, db.nodeDelete(id));
}

/// A user with the role terminal_user, for the terminal tests.
fn testTerminalUser(db: *Db, name: []const u8) !i64 {
    const id = try db.userCreate(name, false, "!", t0);
    var st = try Stmt.prepare(db, "insert into userRole(userId, roleId) select ?, roleId from role where name = 'terminal_user'");
    defer st.finalize();
    try st.bindInt(1, id);
    try st.done();
    return id;
}

test "terminal access: invitation, redemption, uses, the user's nodes and sessions" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const th = tokenHash("INV");
    const id = try testTerminalUser(&db, "ali");
    try db.userSetNodes(id, "ist_*,pump??");
    try db.terminalInvite(id, .{ .max_uses = 2 }, &th, t0 + 3600, t0);
    const p = (try db.terminalByToken(a, &th, t0)).?;
    try testing.expectEqualStrings("ali", p.name);
    try testing.expectEqualStrings("ist_*,pump??", p.nodes);
    const tid = core.code.tokenId("INV");
    try testing.expectEqual(id, (try db.terminalByTokenId(a, &tid, t0)).?.id);
    try testing.expectEqual(@as(?[]const u8, null), p.user_key);

    try db.terminalRedeem(id, "UALI");
    // The invitation is used up; the key now identifies ali
    try testing.expect((try db.terminalByToken(a, &th, t0)) == null);
    try testing.expectEqualStrings("ali", (try db.terminalByKey(a, "UALI")).?.name);
    try testing.expectError(error.NotFound, db.terminalRedeem(id, "UOTHER"));

    // Only the user's nodes
    try testing.expectEqualStrings("this node is not among the user's nodes", (try db.terminalUse("UALI", "ank_gw1", "S0", t0 + 5)).denied);
    // Two uses allowed, the third is refused
    try testing.expectEqual(Db.UseResult.allowed, try db.terminalUse("UALI", "ist_gw1", "S1", t0 + 10));
    try testing.expectEqual(Db.UseResult.allowed, try db.terminalUse("UALI", "pump07", "S2", t0 + 20));
    try testing.expectEqualStrings("no uses left", (try db.terminalUse("UALI", "ist_gw1", "S3", t0 + 30)).denied);
    try testing.expectEqual(@as(i64, 2), (try db.terminalGet(a, id)).?.uses);
    // A key nobody has
    try testing.expectEqualStrings("unknown key", (try db.terminalUse("UMALLORY", "ist_gw1", "S4", t0)).denied);
    // The user's nodes change: they apply at once
    try db.userSetNodes(id, "");
    try db.terminalInvite(id, .{ .max_uses = 5 }, &tokenHash("INV1B"), t0 + 3600, t0);
    try db.terminalRedeem(id, "UALI2");
    try testing.expectEqualStrings("this node is not among the user's nodes", (try db.terminalUse("UALI2", "ist_gw1", "S5", t0)).denied);
    try db.userSetNodes(id, "*");
    try testing.expectEqual(Db.UseResult.allowed, try db.terminalUse("UALI2", "ank_gw1", "S6", t0));
    // The key of the invitation before does not work any more
    try testing.expectEqualStrings("unknown key", (try db.terminalUse("UALI", "ist_gw1", "S7", t0)).denied);
    try testing.expectError(error.InvalidSpec, db.userSetNodes(id, "ist-*"));

    // Sessions: active until ended; end reports are idempotent
    try testing.expectEqual(@as(usize, 3), (try db.sessionsActive(a)).len);
    try db.sessionEnd("S1", t0 + 100, 0);
    try db.sessionEnd("S1", t0 + 999, 1);
    const recent = try db.sessionsRecent(a, 10);
    try testing.expectEqual(@as(usize, 3), recent.len);
    const s1 = for (recent) |r| (if (std.mem.eql(u8, r.sid, "S1")) break r) else unreachable;
    try testing.expectEqual(@as(?i64, t0 + 100), s1.ended);
    try testing.expectEqual(@as(?i64, 0), s1.exit_status);
    try testing.expectEqualStrings("ali", s1.user);
    try testing.expectEqual(@as(usize, 2), (try db.sessionsActive(a)).len);
}

test "terminal access: expiry, revocation, and the right to connect" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const th = tokenHash("INV2");
    const id = try testTerminalUser(&db, "bot1");
    try db.userSetNodes(id, "*");
    try db.terminalInvite(id, .{ .kind = .bot, .expires = t0 + 60 }, &th, t0 + 10, t0);
    // An invitation that is not used in time expires
    try testing.expect((try db.terminalByToken(a, &th, t0 + 10)) == null);
    try db.terminalRedeem(id, "UBOT");
    try testing.expectEqual(Db.UseResult.allowed, try db.terminalUse("UBOT", "gw1", "B1", t0 + 59));
    try testing.expectEqualStrings("access expired", (try db.terminalUse("UBOT", "gw1", "B2", t0 + 60)).denied);

    // Without terminal:connect (the role taken), or blocked: no connecting
    try db.userRevoke(id, (try db.roleList(a))[2].id);
    try testing.expect((try db.terminalByKey(a, "UBOT")) == null);
    try testing.expectEqualStrings("access revoked", (try db.terminalUse("UBOT", "gw1", "B3", t0)).denied);
    try testing.expectEqualStrings("UBOT", (try db.terminalKeysDenied(a))[0]);
    try db.userGrant(id, (try db.roleList(a))[2].id);
    try testing.expect((try db.terminalByKey(a, "UBOT")) != null);
    try db.userSetDisabled(id, true);
    try testing.expect((try db.terminalByKey(a, "UBOT")) == null);
    try db.userSetDisabled(id, false);

    try db.terminalRevoke(id);
    try testing.expect((try db.terminalByKey(a, "UBOT")) == null);
    try testing.expectEqualStrings("access revoked", (try db.terminalUse("UBOT", "gw1", "B3", t0)).denied);
    // A new invitation gives access again, with a new key
    try db.terminalInvite(id, .{ .max_uses = 1 }, &tokenHash("INV3"), t0 + 10, t0);
    try testing.expect((try db.terminalByToken(a, &tokenHash("INV3"), t0)) != null);
}

test "an invitation needs a limit" {
    var db = try testDb();
    defer db.close();
    const th = tokenHash("X");
    const id = try testTerminalUser(&db, "xx");
    try testing.expectError(error.InvalidSpec, db.terminalInvite(id, .{}, &th, t0 + 1, t0));
    try testing.expectError(error.InvalidSpec, db.terminalInvite(id, .{ .max_uses = 0 }, &th, t0 + 1, t0));
    try testing.expectError(error.NotFound, db.terminalInvite(999, .{ .max_uses = 1 }, &th, t0 + 1, t0));
}

test "settings and session logs" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqual(@as(i64, 10_000), (try db.settingsGet()).max_command_output);
    try db.settingsSet(.{ .max_command_output = 500, .max_session_minutes = 0, .log_days = 7 });
    const st = try db.settingsGet();
    try testing.expectEqual(@as(i64, 500), st.max_command_output);
    try testing.expectEqual(@as(i64, 0), st.max_session_minutes);
    try testing.expectEqual(@as(i64, 7), st.log_days);
    try testing.expectEqual(@as(i64, 4), st.ruler_len);
    try testing.expectError(error.InvalidSpec, db.settingsSet(.{ .ruler_len = 1 }));
    try testing.expectError(error.InvalidSpec, db.settingsSet(.{ .ruler_len = 11 }));

    try db.commandAdd("S1", .{ .seq = 1, .at = t0, .line = "$ ls", .output = "a b", .output_chars = 3 });
    try db.commandAdd("S1", .{ .seq = 2, .at = t0 + 10, .line = "$ pwd", .output = "/root", .output_chars = 5 });
    try db.commandAdd("S2", .{ .seq = 1, .at = t0 + 100, .line = "$ id", .output = "", .output_chars = 0 });
    const cmds = try db.commandsOf(a, "S1");
    try testing.expectEqual(@as(usize, 2), cmds.len);
    try testing.expectEqualStrings("$ pwd", cmds[1].line);
    try testing.expectEqual(@as(usize, 2), try db.commandsPrune(t0 + 50));
    try testing.expectEqual(@as(usize, 0), (try db.commandsOf(a, "S1")).len);
    try testing.expectEqual(@as(usize, 1), (try db.commandsOf(a, "S2")).len);

    // Stored encrypted: the text is not in the database file
    try db.commandAdd("S3", .{ .seq = 1, .at = t0, .line = "cat secret\r", .output = "TOP-SECRET-VALUE", .output_chars = 16 });
    {
        var q = try Stmt.prepare(&db, "select line, output from sessionCommand where sid = 'S3'");
        defer q.finalize();
        try testing.expect(try q.step());
        try testing.expect(std.mem.indexOf(u8, q.rawText(0), "secret") == null);
        try testing.expect(std.mem.indexOf(u8, q.rawText(1), "TOP-SECRET") == null);
    }
    try testing.expectEqualStrings("TOP-SECRET-VALUE", (try db.commandsOf(a, "S3"))[0].output);
    // Moved to another session: does not decrypt
    try db.exec("update sessionCommand set sid = 'S4' where sid = 'S3'");
    const moved = (try db.commandsOf(a, "S4"))[0];
    try testing.expect(!moved.intact);
    try testing.expectEqualStrings("", moved.output);
    // Another key: does not decrypt
    db.setLogKey(testing.io, @splat(8));
    try testing.expect(!(try db.commandsOf(a, "S2"))[0].intact);
    // No key: nothing written
    db.log_key = null;
    try testing.expectError(error.NoLogKey, db.commandAdd("S5", .{ .seq = 0, .at = t0, .line = "", .output = "x", .output_chars = 1 }));
}

test {
    _ = rights;
}

test "users, lockout and browser sessions" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectError(error.InvalidName, db.userCreate("Root", true, "h", t0));
    const id = try db.userCreate("erdem", true, "hash1", t0);
    try testing.expectError(error.Duplicate, db.userCreate("erdem", false, "h", t0));
    const aud = try db.userCreate("auditor-1", false, "hash2", t0);
    try testing.expectEqual(@as(i64, 2), try db.userCount());
    try testing.expectEqual(@as(usize, 2), (try db.userList(a)).len);
    try testing.expect(!(try db.userByName(a, "auditor-1")).?.is_superuser);

    // The TOTP secret is stored encrypted and comes back
    const secret: [20]u8 = "12345678901234567890".*;
    try testing.expect(try db.userTotpSecret(id) == null);
    try db.userSetTotpSecret(id, secret);
    try testing.expectEqualSlices(u8, &secret, &(try db.userTotpSecret(id)).?);
    try testing.expect(!(try db.userGet(a, id)).?.totp_confirmed);
    try db.userTotpUsed(id, 555);
    const acc = (try db.userGet(a, id)).?;
    try testing.expect(acc.totp_confirmed);
    try testing.expectEqual(@as(i64, 555), acc.totp_last_step);

    // Four failures do nothing; the fifth locks for a minute, the sixth for two
    for (0..4) |_| try db.userFailed(id, t0);
    try testing.expectEqual(@as(i64, 0), (try db.userGet(a, id)).?.locked_until);
    try db.userFailed(id, t0);
    try testing.expectEqual(t0 + 60, (try db.userGet(a, id)).?.locked_until);
    try db.userFailed(id, t0);
    try testing.expectEqual(t0 + 120, (try db.userGet(a, id)).?.locked_until);
    try db.userPasswordOk(id);
    try testing.expectEqual(@as(i64, 0), (try db.userGet(a, id)).?.fail_count);

    // Sessions: pending, promoted, expired, ended by a new password or disabling
    try db.webSessionCreate("TOK1", id, t0, t0 + 300);
    try testing.expect(!(try db.webSessionGet("TOK1", t0)).?.full);
    try db.webSessionPromote("TOK1", t0 + 3600);
    try testing.expect((try db.webSessionGet("TOK1", t0 + 1000)).?.full);
    try testing.expect(try db.webSessionGet("TOK1", t0 + 3600) == null);
    try testing.expect(try db.webSessionGet("NOPE", t0) == null);
    try db.userSetPassword(id, "hash3");
    try testing.expect(try db.webSessionGet("TOK1", t0) == null);
    try testing.expect(!(try db.userGet(a, id)).?.totp_confirmed);
    try testing.expect(try db.userTotpSecret(id) == null);
    try db.webSessionCreate("TOK2", aud, t0, t0 + 300);
    try db.userSetDisabled(aud, true);
    try testing.expect(try db.webSessionGet("TOK2", t0) == null);
    try testing.expectError(error.NotFound, db.userSetPassword(999, "h"));
}

test "roles, their rights and the roles of users" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A new database has the roles admin (every right but connecting to
    // nodes), auditor (reading) and terminal_user (connecting)
    const seeded = try db.roleList(a);
    try testing.expectEqual(@as(usize, 3), seeded.len);
    try testing.expectEqualStrings("admin", seeded[0].name);
    try testing.expectEqualStrings("terminal_user", seeded[2].name);
    var all: usize = 0;
    for (rights.modules) |m| all += m.actions.len;
    try testing.expectEqual(all - 1, (try db.roleRights(a, 1)).len);
    try testing.expect(!rights.has(try db.roleRights(a, 1), "terminal", "connect"));
    try testing.expect(!rights.has(try db.roleRights(a, 2), "node", "insert"));
    try testing.expect(rights.has(try db.roleRights(a, 2), "panel", "login"));
    try testing.expectEqualStrings("terminal:connect", (try db.roleRights(a, seeded[2].id))[0]);

    try testing.expectError(error.InvalidName, db.roleInsert("1x", "", &.{}));
    try testing.expectError(error.Duplicate, db.roleInsert("admin", "", &.{}));
    try testing.expectError(error.InvalidRight, db.roleInsert("clerk", "", &.{"user:fly"}));
    try testing.expect(try db.roleGet(a, 4) == null);
    const clerk = try db.roleInsert("clerk", "Looks at users", &.{"user:browse"});
    try db.roleUpdate(clerk, "clerk", "Users and roles", &.{ "user:browse", "role:browse" });
    try testing.expectEqual(@as(usize, 2), (try db.roleRights(a, clerk)).len);
    try testing.expectError(error.NotFound, db.roleUpdate(999, "x", "", &.{}));

    // Users get their rights from their roles
    const su = try db.userCreate("erdem", true, "h", t0);
    const u = try db.userCreate("veli", false, "h", t0);
    try testing.expectEqual(@as(usize, 0), (try db.userRights(a, u)).len);
    try db.userGrant(u, clerk);
    try db.userGrant(u, 2);
    try testing.expectError(error.Duplicate, db.userGrant(u, clerk));
    try testing.expectError(error.NotFound, db.userGrant(u, 999));
    const have = try db.userRights(a, u);
    try testing.expect(rights.has(have, "role", "browse"));
    try testing.expect(rights.has(have, "session", "watch"));
    try testing.expect(!rights.has(have, "node", "delete"));
    try testing.expectEqual(@as(usize, 2), (try db.userRoles(a, u)).len);
    try testing.expectEqual(@as(i64, 1), (try db.roleGet(a, clerk)).?.user_count);

    // A role in use stays; the superuser stays and cannot be blocked
    try testing.expectError(error.InUse, db.roleDelete(clerk));
    try db.userRevoke(u, clerk);
    try testing.expectError(error.NotFound, db.userRevoke(u, clerk));
    try db.roleDelete(clerk);
    try testing.expectError(error.NotFound, db.roleDelete(clerk));
    try testing.expectError(error.Protected, db.userDelete(su));
    try testing.expectError(error.Protected, db.userSetDisabled(su, true));
    try db.userSetName(u, "veli2");
    try testing.expectError(error.Duplicate, db.userSetName(u, "erdem"));
    try db.userDelete(u);
    try testing.expectError(error.NotFound, db.userDelete(u));
    try testing.expectEqual(@as(i64, 0), (try db.roleGet(a, 2)).?.user_count);
}

test "acting as another user in a browser session" {
    var db = try testDb();
    defer db.close();
    const su = try db.userCreate("superuser", true, "h", 1);
    const other = try db.userCreate("veli", false, "h", 1);
    try db.webSessionCreate("T", su, 1, 100);
    try db.webSessionSetEffective("T", other);
    try testing.expectEqual(@as(?i64, other), (try db.webSessionGet("T", 2)).?.effective_user_id);
    // A blocked user is not acted as
    try db.userSetDisabled(other, true);
    try testing.expectEqual(@as(?i64, null), (try db.webSessionGet("T", 2)).?.effective_user_id);
}

test "lists a page at a time, with a search" {
    var db = try testDb();
    defer db.close();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // 45 nodes: 30 in Istanbul, 15 pumps
    for (0..45) |i| {
        const name = try std.fmt.allocPrint(a, "{s}{d:0>2}", .{ if (i < 30) "ist_gw" else "pump", i });
        _ = try db.nodeCreate(name, if (i == 44) "Ankara station" else "", &tokenHash(name), t0 + 10, t0);
    }
    const first = try db.nodeSearch(a, "", 1);
    try testing.expectEqual(@as(i64, 45), first.total);
    try testing.expectEqual(@as(i64, 3), first.pages);
    try testing.expectEqual(@as(usize, 20), first.rows.len);
    try testing.expectEqualStrings("ist_gw00", first.rows[0].name);
    // Past the end: the last page
    const last = try db.nodeSearch(a, "", 9);
    try testing.expectEqual(@as(i64, 3), last.page);
    try testing.expectEqual(@as(usize, 5), last.rows.len);
    // A search in names and descriptions, without regard to case
    try testing.expectEqual(@as(i64, 15), (try db.nodeSearch(a, "PUMP", 1)).total);
    const ankara = try db.nodeSearch(a, "ankara", 1);
    try testing.expectEqual(@as(usize, 1), ankara.rows.len);
    try testing.expectEqualStrings("pump44", ankara.rows[0].name);
    // A search with no rows: one empty page
    const none = try db.nodeSearch(a, "x%_", 1);
    try testing.expectEqual(@as(i64, 0), none.total);
    try testing.expectEqual(@as(i64, 1), none.pages);
    try testing.expectEqual(@as(i64, 45), (try db.nodeSummary()).total);
    // Actions likewise
    for (0..25) |i| try db.actionAdd(t0 + @as(i64, @intCast(i)), if (i % 5 == 0) "veli" else "superuser", "db.nodeCreate", "x", true);
    try testing.expectEqual(@as(i64, 5), (try db.actionsSearch(a, "veli", 1)).total);
    try testing.expectEqual(@as(i64, 2), (try db.actionsSearch(a, "", 1)).pages);
}
