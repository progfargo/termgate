//! The panel's sign-in and user calls (POST /api/<name>, JSON).
//!
//! Signing in takes two steps: `login` (name and password) gives a pending
//! session, `login2` (a code from the authenticator app) makes it full.
//! A user that has not set up its second step yet gets a new secret
//! from `login` and confirms it with its first code. Wrong passwords and
//! codes count together; from the fifth in a row the user is locked for
//! a growing time (db.userFailed).
//!
//! Users are made by users who may (`users.create` returns a password to
//! hand over); there is no sign-up and no password recovery, and termgate
//! sends no e-mail. `users.reset` gives a user a new password and
//! makes it set up its second step again; `profile.password` changes
//! one's own.
//!
//! What a user may do comes from its roles: a role is a set of rights
//! (rights.zig), made and changed with `roles.*` and given to users with
//! `users.grant`. The rules are our earlier project's:
//! - The superuser (the first user, made by `termgate init`) has every
//!   right; nobody can change, block, delete it, reset its password or
//!   give or take its roles. It changes its own password in its profile.
//! - The role admin cannot be deleted; only the superuser changes it.
//! - The last user with the role admin cannot be deleted, nor lose it.
//! - `users.select` lets the superuser act as another user (to see the
//!   panel as that user does): the other's rights apply until
//!   `users.unselect`. Only the superuser may do it; it is no right a
//!   role gives.

const std = @import("std");
const Io = std.Io;
const dbm = @import("db");
const users = @import("users");
const qr = @import("qr.zig");

/// A pending session (password given, code not yet) lives this long.
const pending_s = 5 * 60;
/// A full session lives this long, whatever its use.
const session_s = 12 * 3600;

pub const Auth = struct {
    gpa: std.mem.Allocator,
    io: Io,
    db: *dbm.Db,
    lock: *Io.Mutex,
    cost: users.Cost = users.default_cost,
    /// Signing in asks for the authenticator code too: on in a release
    /// build, off in a debug build (build.zig)
    second_step: bool = @import("build_options").second_step,
};

pub const Reply = struct {
    status: std.http.Status = .ok,
    /// JSON, in the call's arena
    body: []const u8,
    /// A new session token to set as the cookie
    set_token: ?[]const u8 = null,
    token_max_age: i64 = 0,
    /// The cookie is to be removed
    clear_token: bool = false,
};

/// Who is calling: the user of a full session, with its rights; when it
/// acts as another user (users.select), that user.
pub const Caller = struct {
    id: i64,
    name: []const u8,
    is_superuser: bool = false,
    /// "module:action", from the user's roles
    rights: []const []const u8 = &.{},
    /// The signed-in user, when it acts as the user above
    real: ?Real = null,

    pub const Real = struct { id: i64, name: []const u8, is_superuser: bool, rights: []const []const u8 };

    pub fn can(c: *const Caller, module: []const u8, action: []const u8) bool {
        return c.is_superuser or dbm.rights.has(c.rights, module, action);
    }

    /// A right of the signed-in user itself, not of the one it acts as.
    pub fn realCan(c: *const Caller, module: []const u8, action: []const u8) bool {
        const r = c.real orelse return c.can(module, action);
        return r.is_superuser or dbm.rights.has(r.rights, module, action);
    }

    /// Whether the signed-in user itself (not the one it acts as) is the
    /// superuser.
    pub fn realIsSuperuser(c: *const Caller) bool {
        return if (c.real) |r| r.is_superuser else c.is_superuser;
    }

    /// The signed-in user's own id.
    pub fn realId(c: *const Caller) i64 {
        return if (c.real) |r| r.id else c.id;
    }

    /// Who did it, for the audit: "erdem" or "erdem as veli".
    pub fn auditName(c: *const Caller, a: std.mem.Allocator) []const u8 {
        const r = c.real orelse return c.name;
        return std.fmt.allocPrint(a, "{s} as {s}", .{ r.name, c.name }) catch c.name;
    }
};

fn json(a: std.mem.Allocator, v: anytype) ![]const u8 {
    return std.json.Stringify.valueAlloc(a, v, .{});
}

fn fail(a: std.mem.Allocator, status: std.http.Status, comptime code: []const u8) !Reply {
    return .{ .status = status, .body = try json(a, .{ .@"error" = code }) };
}

/// The user of `token`'s full session, if any.
pub fn caller(auth: *Auth, a: std.mem.Allocator, token: ?[]const u8, now: i64) !?Caller {
    const t = token orelse return null;
    const h = users.tokenHash(t);
    auth.lock.lockUncancelable(auth.io);
    defer auth.lock.unlock(auth.io);
    const s = (try auth.db.webSessionGet(&h, now)) orelse return null;
    if (!s.full) return null;
    const acc = (try auth.db.userGet(a, s.user_id)) orelse return null;
    const own: Caller = .{ .id = acc.id, .name = acc.name, .is_superuser = acc.is_superuser, .rights = try auth.db.userRights(a, acc.id) };
    // Without panel:login (a role taken since signing in) the session ends
    if (!own.can("panel", "login")) return null;
    const eid = s.effective_user_id orelse return own;
    if (eid == acc.id) return own;
    const eff = (try auth.db.userGet(a, eid)) orelse return own;
    return .{
        .id = eff.id,
        .name = eff.name,
        .is_superuser = eff.is_superuser,
        .rights = try auth.db.userRights(a, eff.id),
        .real = .{ .id = own.id, .name = own.name, .is_superuser = own.is_superuser, .rights = own.rights },
    };
}

/// Handles the sign-in and user calls; null if `name` is not one of them.
pub fn call(auth: *Auth, a: std.mem.Allocator, name: []const u8, body: []const u8, token: ?[]const u8, now: i64) !?Reply {
    if (std.mem.eql(u8, name, "login")) return try login(auth, a, body, now);
    if (std.mem.eql(u8, name, "login2")) return try login2(auth, a, body, token, now);
    if (std.mem.eql(u8, name, "logout")) {
        if (token) |t| {
            auth.lock.lockUncancelable(auth.io);
            defer auth.lock.unlock(auth.io);
            try auth.db.webSessionDelete(&users.tokenHash(t));
        }
        return .{ .body = "{\"ok\":true}", .clear_token = true };
    }
    if (std.mem.eql(u8, name, "me")) {
        const c = (try caller(auth, a, token, now)) orelse return try fail(a, .unauthorized, "not signed in");
        // `real`: the signed-in user's name while it acts as another;
        // whether it may act as another or stop (its own rights)
        return .{ .body = try json(a, .{
            .name = c.name,
            .superuser = c.is_superuser,
            .rights = c.rights,
            .real = if (c.real) |r| r.name else null,
            .can_select = c.realIsSuperuser(),
            .can_unselect = c.real != null,
        }) };
    }
    if (std.mem.eql(u8, name, "profile.password")) {
        const c = (try caller(auth, a, token, now)) orelse return try fail(a, .unauthorized, "not signed in");
        return try ownPassword(auth, a, body, &c);
    }
    const is_user = std.mem.startsWith(u8, name, "users.");
    if (is_user or std.mem.startsWith(u8, name, "roles.")) {
        const c = (try caller(auth, a, token, now)) orelse return try fail(a, .unauthorized, "not signed in");
        const what = name["users.".len..];
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        return if (is_user) try userCall(auth, a, what, body, &c, &users.tokenHash(token.?), now) else try roleCall(auth, a, what, body, &c);
    }
    return null;
}

fn login(auth: *Auth, a: std.mem.Allocator, body: []const u8, now: i64) !Reply {
    const Req = struct { name: []const u8, password: []const u8 };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return fail(a, .bad_request, "bad request");

    const found = blk: {
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        break :blk try auth.db.userByName(a, req.name);
    };
    // The password is hashed either way, so an unknown name takes as long
    // as a wrong password and both get the same answer
    const acc = found orelse {
        _ = users.checkPassword(a, auth.io, dummy_hash, req.password);
        return fail(a, .unauthorized, "wrong name or password");
    };
    if (acc.disabled) {
        _ = users.checkPassword(a, auth.io, dummy_hash, req.password);
        return fail(a, .unauthorized, "wrong name or password");
    }
    if (acc.locked_until > now) return .{ .status = .too_many_requests, .body = try json(a, .{ .@"error" = "locked", .retry_after = acc.locked_until - now }) };
    if (!users.checkPassword(a, auth.io, acc.password_hash, req.password)) {
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        try auth.db.userFailed(acc.id, now);
        return fail(a, .unauthorized, "wrong name or password");
    }
    // A password stored with an older cost is stored again with today's
    if (users.needsRehash(acc.password_hash, auth.cost)) {
        const hash = try users.hashPassword(a, auth.io, req.password, auth.cost);
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        try auth.db.userSetOwnPassword(acc.id, hash);
    }
    // Signing in to the panel is a right (panel:login); a terminal-only
    // user does not have it
    {
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        if (!acc.is_superuser and !dbm.rights.has(try auth.db.userRights(a, acc.id), "panel", "login"))
            return fail(a, .forbidden, "this user may not sign in to the panel");
    }

    const token = try a.dupe(u8, &users.newToken(auth.io));
    auth.lock.lockUncancelable(auth.io);
    defer auth.lock.unlock(auth.io);
    // Expired browser sessions go at each sign-in
    try auth.db.webSessionsPrune(now);
    try auth.db.webSessionCreate(&users.tokenHash(token), acc.id, now, now + pending_s);
    if (!auth.second_step) {
        // Built without the second step: signed in with the password
        try auth.db.userPasswordOk(acc.id);
        try auth.db.webSessionPromote(&users.tokenHash(token), now + session_s);
        return .{
            .body = try json(a, .{ .step = "done", .name = acc.name, .superuser = acc.is_superuser, .rights = try auth.db.userRights(a, acc.id) }),
            .set_token = token,
            .token_max_age = session_s,
        };
    }
    if (acc.totp_confirmed) return .{ .body = "{\"step\":\"code\"}", .set_token = token, .token_max_age = pending_s };

    // First sign-in (or after a reset): a new secret for the authenticator app
    const secret = users.newTotpSecret(auth.io);
    try auth.db.userSetTotpSecret(acc.id, secret);
    return .{
        .body = try json(a, .{
            .step = "setup",
            .secret = @as([]const u8, &users.totpSecretText(secret)),
            .uri = try users.totpUri(a, secret, acc.name),
            // The same as a QR code to scan
            .qr = qr.svg(a, try users.totpUri(a, secret, acc.name)) catch "",
        }),
        .set_token = token,
        .token_max_age = pending_s,
    };
}

fn login2(auth: *Auth, a: std.mem.Allocator, body: []const u8, token: ?[]const u8, now: i64) !Reply {
    const Req = struct { code: []const u8 };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return fail(a, .bad_request, "bad request");
    const t = token orelse return fail(a, .unauthorized, "sign in first");
    const h = users.tokenHash(t);

    auth.lock.lockUncancelable(auth.io);
    defer auth.lock.unlock(auth.io);
    const s = (try auth.db.webSessionGet(&h, now)) orelse return fail(a, .unauthorized, "sign in first");
    const acc = (try auth.db.userGet(a, s.user_id)) orelse return fail(a, .unauthorized, "sign in first");
    if (acc.locked_until > now) return .{ .status = .too_many_requests, .body = try json(a, .{ .@"error" = "locked", .retry_after = acc.locked_until - now }) };
    const secret = (try auth.db.userTotpSecret(acc.id)) orelse return fail(a, .unauthorized, "sign in first");
    const step = users.totpVerify(&secret, req.code, now, @intCast(acc.totp_last_step)) orelse {
        try auth.db.userFailed(acc.id, now);
        return fail(a, .unauthorized, "wrong code");
    };
    try auth.db.userTotpUsed(acc.id, @intCast(step));
    try auth.db.webSessionPromote(&h, now + session_s);
    return .{
        .body = try json(a, .{ .ok = true, .name = acc.name, .superuser = acc.is_superuser, .rights = try auth.db.userRights(a, acc.id) }),
        .set_token = t,
        .token_max_age = session_s,
    };
}

const no_right = "you do not have the right to do this";

/// users.*; the caller holds the lock. `token_hash`: the caller's session.
fn userCall(auth: *Auth, a: std.mem.Allocator, name: []const u8, body: []const u8, c: *const Caller, token_hash: []const u8, now: i64) !Reply {
    const db = auth.db;
    // nodes: the nodes the user may reach with tgterm (name patterns,
    // comma separated); null: unchanged
    const Req = struct { id: i64 = 0, name: []const u8 = "", disabled: bool = false, role: i64 = 0, nodes: ?[]const u8 = null };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return fail(a, .bad_request, "bad request");

    if (std.mem.eql(u8, name, "list")) {
        if (!c.can("user", "browse")) return fail(a, .forbidden, no_right);
        // A page of the users, by a search in the name, a role and a
        // status (active, new: not signed in yet, blocked), as our earlier project's
        // `id`: that user only (a page about one user)
        const Filter = struct { id: i64 = 0, key: []const u8 = "", rid: i64 = 0, stat: []const u8 = "", pn: i64 = 1 };
        const f = std.json.parseFromSliceLeaky(Filter, a, body, .{ .ignore_unknown_fields = true }) catch Filter{};
        const Row = struct { id: i64, name: []const u8, superuser: bool, disabled: bool, second_step: bool, created: i64, nodes: []const u8, roles: []const dbm.RoleRef, terminal: ?dbm.Terminal };
        var rows: std.ArrayList(Row) = .empty;
        // A user's roles are shown to who may see them
        const see_roles = c.can("user", "role_browse");
        for (try db.userList(a)) |x| {
            if (f.id != 0 and x.id != f.id) continue;
            if (f.key.len > 0 and std.ascii.findIgnoreCase(x.name, f.key) == null) continue;
            if (std.mem.eql(u8, f.stat, "active") and (x.disabled or (auth.second_step and !x.totp_confirmed))) continue;
            if (std.mem.eql(u8, f.stat, "new") and (x.disabled or x.totp_confirmed)) continue;
            if (std.mem.eql(u8, f.stat, "blocked") and !x.disabled) continue;
            const roles = try db.userRoles(a, x.id);
            if (f.rid != 0) {
                var has = false;
                for (roles) |r| has = has or r.id == f.rid;
                if (!has) continue;
            }
            try rows.append(a, .{
                .id = x.id,
                .name = x.name,
                .superuser = x.is_superuser,
                .disabled = x.disabled,
                .second_step = x.totp_confirmed,
                .created = x.created,
                .nodes = x.nodes,
                .roles = if (see_roles) roles else &.{},
                // Its terminal access, if one was given
                .terminal = try db.terminalGet(a, x.id),
            });
        }
        const total: i64 = @intCast(rows.items.len);
        const pages = @max(1, @divFloor(total + dbm.Db.page_len - 1, dbm.Db.page_len));
        const page = std.math.clamp(f.pn, 1, pages);
        const from: usize = @intCast((page - 1) * dbm.Db.page_len);
        const to = @min(rows.items.len, from + @as(usize, @intCast(dbm.Db.page_len)));
        return .{ .body = try json(a, .{ .users = rows.items[from..to], .total = total, .page = page, .pages = pages }) };
    }
    if (std.mem.eql(u8, name, "create")) {
        if (!c.can("user", "insert")) return fail(a, .forbidden, no_right);
        const password = users.randomPassword(auth.io);
        const hash = try users.hashPassword(a, auth.io, &password, auth.cost);
        const id = db.userCreate(req.name, false, hash, now) catch |e| return userError(a, e);
        // Shown once: handed over by whoever made the user
        return .{ .body = try json(a, .{ .ok = true, .id = id, .name = req.name, .password = @as([]const u8, &password) }) };
    }
    if (std.mem.eql(u8, name, "select")) {
        if (!c.realIsSuperuser()) return fail(a, .forbidden, "only the superuser may act as another user");
        const target = (try db.userGet(a, req.id)) orelse return fail(a, .not_found, "no such user");
        if (target.disabled) return fail(a, .conflict, "this user is blocked");
        try db.webSessionSetEffective(token_hash, if (target.id == c.realId()) null else target.id);
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "unselect")) {
        if (c.real == null) return fail(a, .conflict, "you are not acting as another user");
        try db.webSessionSetEffective(token_hash, null);
        return .{ .body = "{\"ok\":true}" };
    }

    // The rest changes a user: never the superuser (except deleting and
    // blocking, which the database refuses with its own answer)
    const target = (try db.userGet(a, req.id)) orelse return fail(a, .not_found, "no such user");
    const superuser_kept = "the superuser cannot be changed";
    if (std.mem.eql(u8, name, "update")) {
        if (!c.can("user", "update")) return fail(a, .forbidden, no_right);
        if (target.is_superuser) return fail(a, .conflict, superuser_kept);
        if (req.disabled and target.id == c.id) return fail(a, .conflict, "you cannot block your own user");
        if (req.nodes) |n| {
            const nodes = std.mem.trim(u8, n, " ");
            // A user's nodes are its terminal access: giving it is a right of
            // its own
            if (!std.mem.eql(u8, target.nodes, nodes) and !c.can("user", "access")) return fail(a, .forbidden, no_right);
            if (!std.mem.eql(u8, target.nodes, nodes)) db.userSetNodes(target.id, nodes) catch |e| switch (e) {
                error.InvalidSpec => return fail(a, .bad_request, "nodes: name patterns, comma separated: lowercase letters, digits, _, * (any run) and ? (one character)"),
                else => return userError(a, e),
            };
        }
        if (!std.mem.eql(u8, target.name, req.name)) db.userSetName(target.id, req.name) catch |e| return userError(a, e);
        if (target.disabled != req.disabled) db.userSetDisabled(target.id, req.disabled) catch |e| return userError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "reset")) {
        if (!c.can("user", "update_pass")) return fail(a, .forbidden, no_right);
        if (target.is_superuser) return fail(a, .conflict, superuser_kept);
        const password = users.randomPassword(auth.io);
        const hash = try users.hashPassword(a, auth.io, &password, auth.cost);
        try db.userSetPassword(target.id, hash);
        return .{ .body = try json(a, .{ .ok = true, .name = target.name, .password = @as([]const u8, &password) }) };
    }
    if (std.mem.eql(u8, name, "delete")) {
        if (!c.can("user", "delete")) return fail(a, .forbidden, no_right);
        if (target.id == c.id or target.id == c.realId()) return fail(a, .conflict, "you cannot delete your own user");
        if (try db.userHasRole(target.id, admin_role) and try db.usersWithRole(admin_role) < 2) return fail(a, .conflict, "the last admin cannot be deleted");
        db.userDelete(target.id) catch |e| return userError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "grant")) {
        if (!c.can("user", "role_grant")) return fail(a, .forbidden, no_right);
        if (target.is_superuser) return fail(a, .conflict, superuser_kept);
        db.userGrant(target.id, req.role) catch |e| return switch (e) {
            error.Duplicate => fail(a, .conflict, "the user has this role already"),
            else => userError(a, e),
        };
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "revoke")) {
        if (!c.can("user", "role_revoke")) return fail(a, .forbidden, no_right);
        if (target.is_superuser) return fail(a, .conflict, superuser_kept);
        const role = (try db.roleGet(a, req.role)) orelse return fail(a, .not_found, "no such role");
        if (std.mem.eql(u8, role.name, admin_role) and try db.userHasRole(target.id, admin_role) and try db.usersWithRole(admin_role) < 2)
            return fail(a, .conflict, "the last admin cannot lose the role admin");
        db.userRevoke(target.id, req.role) catch |e| return userError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    return fail(a, .not_found, "unknown call");
}

/// The role that is never deleted, changed only by the superuser, and
/// always kept by at least one user.
const admin_role = "admin";

fn userError(a: std.mem.Allocator, e: anyerror) !Reply {
    return switch (e) {
        error.InvalidName => fail(a, .bad_request, "name: lowercase letters, digits, _ . -, 2 to 32 characters, starting with a letter"),
        error.Duplicate => fail(a, .conflict, "this name is taken"),
        error.NotFound => fail(a, .not_found, "no such user or role"),
        error.Protected => fail(a, .conflict, "the superuser cannot be deleted or blocked"),
        else => e,
    };
}

/// profile.password: the signed-in user (or the one it acts as) changes
/// its own password, giving the current one.
fn ownPassword(auth: *Auth, a: std.mem.Allocator, body: []const u8, c: *const Caller) !Reply {
    if (!c.can("profile", "update_password")) return fail(a, .forbidden, no_right);
    const Req = struct { current: []const u8 = "", new: []const u8 = "", new2: []const u8 = "" };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return fail(a, .bad_request, "bad request");
    if (req.current.len == 0 or req.new.len == 0 or req.new2.len == 0) return fail(a, .bad_request, "fill in every field");
    const acc = blk: {
        auth.lock.lockUncancelable(auth.io);
        defer auth.lock.unlock(auth.io);
        break :blk (try auth.db.userGet(a, c.id)) orelse return fail(a, .not_found, "no such user");
    };
    if (!users.checkPassword(a, auth.io, acc.password_hash, req.current)) return fail(a, .conflict, "the current password is wrong");
    if (req.new.len < min_password) return fail(a, .bad_request, "the new password is too short: at least 8 characters");
    if (std.mem.eql(u8, req.new, req.current)) return fail(a, .bad_request, "the new password is the current one");
    if (!std.mem.eql(u8, req.new, req.new2)) return fail(a, .bad_request, "the new password and its repetition differ");
    const hash = try users.hashPassword(a, auth.io, req.new, auth.cost);
    auth.lock.lockUncancelable(auth.io);
    defer auth.lock.unlock(auth.io);
    auth.db.userSetOwnPassword(acc.id, hash) catch |e| return userError(a, e);
    return .{ .body = "{\"ok\":true}" };
}

/// The shortest password a user may choose.
const min_password = 8;

/// roles.*; the caller holds the lock.
fn roleCall(auth: *Auth, a: std.mem.Allocator, name: []const u8, body: []const u8, c: *const Caller) !Reply {
    const db = auth.db;
    // `rights` null: not sent, the role's rights stay as they are
    const Req = struct { id: i64 = 0, name: []const u8 = "", description: []const u8 = "", rights: ?[]const []const u8 = null };
    const req = std.json.parseFromSliceLeaky(Req, a, body, .{ .ignore_unknown_fields = true }) catch return fail(a, .bad_request, "bad request");
    const role_name = std.mem.trim(u8, req.name, " ");
    const description = std.mem.trim(u8, req.description, " ");

    if (std.mem.eql(u8, name, "list")) {
        // Also for the roles a user has and can be given
        if (!c.can("role", "browse") and !c.can("user", "role_browse") and !c.can("user", "role_grant")) return fail(a, .forbidden, no_right);
        return .{ .body = try json(a, .{ .roles = try db.roleList(a) }) };
    }
    if (std.mem.eql(u8, name, "get")) {
        if (!c.can("role", "browse")) return fail(a, .forbidden, no_right);
        const role = (try db.roleGet(a, req.id)) orelse return fail(a, .not_found, "no such role");
        return .{ .body = try json(a, .{ .role = role, .rights = try db.roleRights(a, req.id) }) };
    }
    if (std.mem.eql(u8, name, "insert")) {
        if (!c.can("role", "insert")) return fail(a, .forbidden, no_right);
        const list = req.rights orelse &.{};
        if (list.len > 0 and !c.can("role", "role_right")) return fail(a, .forbidden, no_right);
        const id = db.roleInsert(role_name, description, list) catch |e| return roleError(a, e);
        return .{ .body = try json(a, .{ .ok = true, .id = id }) };
    }
    if (std.mem.eql(u8, name, "update")) {
        if (!c.can("role", "update")) return fail(a, .forbidden, no_right);
        if (req.rights != null and !c.can("role", "role_right")) return fail(a, .forbidden, no_right);
        const old = (try db.roleGet(a, req.id)) orelse return fail(a, .not_found, "no such role");
        if (std.mem.eql(u8, old.name, admin_role) and !c.is_superuser) return fail(a, .forbidden, "only the superuser changes the role admin");
        db.roleUpdate(req.id, role_name, description, req.rights) catch |e| return roleError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "rights")) {
        // Only the rights, as our earlier project's role_right page: its own right
        if (!c.can("role", "role_right")) return fail(a, .forbidden, no_right);
        const old = (try db.roleGet(a, req.id)) orelse return fail(a, .not_found, "no such role");
        if (std.mem.eql(u8, old.name, admin_role) and !c.is_superuser) return fail(a, .forbidden, "only the superuser changes the role admin");
        db.roleUpdate(req.id, old.name, old.description, req.rights orelse &.{}) catch |e| return roleError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    if (std.mem.eql(u8, name, "delete")) {
        if (!c.can("role", "delete")) return fail(a, .forbidden, no_right);
        const old = (try db.roleGet(a, req.id)) orelse return fail(a, .not_found, "no such role");
        if (std.mem.eql(u8, old.name, admin_role)) return fail(a, .conflict, "the role admin cannot be deleted");
        db.roleDelete(req.id) catch |e| return roleError(a, e);
        return .{ .body = "{\"ok\":true}" };
    }
    return fail(a, .not_found, "unknown call");
}

fn roleError(a: std.mem.Allocator, e: anyerror) !Reply {
    return switch (e) {
        error.InvalidName => fail(a, .bad_request, "name: letters, digits, _ and -, at most 32 characters, starting with a letter"),
        error.Duplicate => fail(a, .conflict, "this name is taken"),
        error.NotFound => fail(a, .not_found, "no such role"),
        error.InvalidRight => fail(a, .bad_request, "unknown right"),
        error.InUse => fail(a, .conflict, "users have this role; take it from them first"),
        else => e,
    };
}

/// Hash of a password nobody has: what an unknown name is checked against.
const dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$dGVybWdhdGUtZHVtbXk$Zm9yLXRpbWluZy1vbmx5LW5vdC1hLXJlYWwtaGFzaA";

/// First start: the first user, the superuser, with a password to hand
/// over. Null if there are users already.
pub fn firstSuperuser(auth: *Auth, name: []const u8, now: i64) !?[20]u8 {
    auth.lock.lockUncancelable(auth.io);
    defer auth.lock.unlock(auth.io);
    if (try auth.db.userCount() > 0) return null;
    const password = users.randomPassword(auth.io);
    const hash = try users.hashPassword(auth.gpa, auth.io, &password, auth.cost);
    defer auth.gpa.free(hash);
    _ = try auth.db.userCreate(name, true, hash, now);
    return password;
}


// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;

/// Signs `name` in with both steps (its second step set up on the way);
/// returns the session token.
fn testSignIn(auth: *Auth, a: std.mem.Allocator, name: []const u8, password: []const u8, now: i64) ![]const u8 {
    const l1 = (try call(auth, a, "login", try std.fmt.allocPrint(a, "{{\"name\":\"{s}\",\"password\":\"{s}\"}}", .{ name, password }), null, now)).?;
    const t = l1.set_token.?;
    const id = (try auth.db.userByName(a, name)).?.id;
    const secret = (try auth.db.userTotpSecret(id)).?;
    const r = (try call(auth, a, "login2", try std.fmt.allocPrint(a, "{{\"code\":\"{d:0>6}\"}}", .{users.totpCode(&secret, @intCast(@divFloor(now, 30)))}), t, now)).?;
    try testing.expectEqual(std.http.Status.ok, r.status);
    return t;
}

fn field(a: std.mem.Allocator, body: []const u8, comptime name: []const u8) []const u8 {
    const v = std.json.parseFromSliceLeaky(std.json.Value, a, body, .{}) catch return "";
    const x = v.object.get(name) orelse return "";
    return if (x == .string) x.string else "";
}

test "sign in with two steps; users, roles and rights" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var db = try dbm.Db.open(":memory:");
    defer db.close();
    db.setLogKey(testing.io, @splat(7));
    var lock: Io.Mutex = .init;
    var auth: Auth = .{ .gpa = testing.allocator, .io = testing.io, .db = &db, .lock = &lock, .cost = users.test_cost, .second_step = true };
    var now: i64 = 1_794_000_000;

    const pw = (try firstSuperuser(&auth, "superuser", now)).?;
    try testing.expect(try firstSuperuser(&auth, "superuser2", now) == null);

    // Wrong password and unknown name: the same answer
    const bad = (try call(&auth, a, "login", "{\"name\":\"superuser\",\"password\":\"nope\"}", null, now)).?;
    const unknown = (try call(&auth, a, "login", "{\"name\":\"ghost\",\"password\":\"nope\"}", null, now)).?;
    try testing.expectEqual(std.http.Status.unauthorized, bad.status);
    try testing.expectEqualStrings(bad.body, unknown.body);

    // First sign-in: the second step is set up
    const body = try std.fmt.allocPrint(a, "{{\"name\":\"superuser\",\"password\":\"{s}\"}}", .{&pw});
    const l1 = (try call(&auth, a, "login", body, null, now)).?;
    try testing.expectEqualStrings("setup", field(a, l1.body, "step"));
    const token = l1.set_token.?;
    // A pending session is not signed in
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "me", "{}", token, now)).?.status);
    const secret = (try db.userTotpSecret(1)).?;
    try testing.expect(std.mem.indexOf(u8, field(a, l1.body, "uri"), "otpauth://totp/termgate:superuser?secret=") != null);
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "login2", "{\"code\":\"000000\"}", token, now)).?.status);
    const code = try std.fmt.allocPrint(a, "{{\"code\":\"{d:0>6}\"}}", .{users.totpCode(&secret, @intCast(@divFloor(now, 30)))});
    const l2 = (try call(&auth, a, "login2", code, token, now)).?;
    try testing.expectEqual(std.http.Status.ok, l2.status);
    try testing.expect(std.mem.indexOf(u8, (try call(&auth, a, "me", "{}", token, now)).?.body, "\"superuser\":true") != null);
    // The same code does not work a second time
    const again = (try call(&auth, a, "login", body, null, now)).?;
    try testing.expectEqualStrings("code", field(a, again.body, "step"));
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "login2", code, again.set_token.?, now)).?.status);

    // The superuser makes a user; without a role it cannot even sign in
    const made = (try call(&auth, a, "users.create", "{\"name\":\"denetci\"}", token, now)).?;
    const aud_pw = field(a, made.body, "password");
    try testing.expectEqual(@as(usize, 20), aud_pw.len);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.create", "{\"name\":\"denetci\"}", token, now)).?.status);
    const aud_login = try std.fmt.allocPrint(a, "{{\"name\":\"denetci\",\"password\":\"{s}\"}}", .{aud_pw});
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "login", aud_login, null, now)).?.status);
    // A role with only panel:login: it signs in and may do nothing
    try testing.expectEqualStrings("{\"ok\":true,\"id\":4}", (try call(&auth, a, "roles.insert", "{\"name\":\"viewer\",\"rights\":[\"panel:login\"]}", token, now)).?.body);
    _ = (try call(&auth, a, "users.grant", "{\"id\":2,\"role\":4}", token, now)).?;
    now += 60;
    const al1 = (try call(&auth, a, "login", try std.fmt.allocPrint(a, "{{\"name\":\"denetci\",\"password\":\"{s}\"}}", .{aud_pw}), null, now)).?;
    const aud_token = al1.set_token.?;
    const aud_secret = (try db.userTotpSecret(2)).?;
    _ = (try call(&auth, a, "login2", try std.fmt.allocPrint(a, "{{\"code\":\"{d:0>6}\"}}", .{users.totpCode(&aud_secret, @intCast(@divFloor(now, 30)))}), aud_token, now)).?;
    try testing.expect(std.mem.indexOf(u8, (try call(&auth, a, "me", "{}", aud_token, now)).?.body, "\"rights\":[\"panel:login\"]") != null);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.list", "{}", aud_token, now)).?.status);
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "users.list", "{}", null, now)).?.status);

    // A role with two rights, given to the user: the next call has them
    const role = (try call(&auth, a, "roles.insert", "{\"name\":\"clerk\",\"description\":\"Looks\",\"rights\":[\"user:browse\",\"user:role_browse\",\"role:browse\"]}", token, now)).?;
    try testing.expectEqualStrings("{\"ok\":true,\"id\":5}", role.body);
    try testing.expectEqual(std.http.Status.bad_request, (try call(&auth, a, "roles.insert", "{\"name\":\"x\",\"rights\":[\"user:fly\"]}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.grant", "{\"id\":2,\"role\":1}", aud_token, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.grant", "{\"id\":2,\"role\":5}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.grant", "{\"id\":2,\"role\":5}", token, now)).?.status);
    const listed = (try call(&auth, a, "users.list", "{}", aud_token, now)).?;
    try testing.expectEqual(std.http.Status.ok, listed.status);
    try testing.expect(std.mem.indexOf(u8, listed.body, "\"roles\":[{\"id\":5,\"name\":\"clerk\"},{\"id\":4,\"name\":\"viewer\"}]") != null);
    try testing.expect(std.mem.indexOf(u8, (try call(&auth, a, "roles.get", "{\"id\":5}", aud_token, now)).?.body, "\"rights\":[\"role:browse\",\"user:browse\",\"user:role_browse\"]") != null);
    // Browsing is not changing
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.create", "{\"name\":\"x1\"}", aud_token, now)).?.status);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "roles.update", "{\"id\":5,\"name\":\"clerk\",\"rights\":[\"user:delete\"]}", aud_token, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "roles.delete", "{\"id\":5}", token, now)).?.status);

    // The superuser stays; nobody blocks or deletes themselves
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.update", "{\"id\":1,\"name\":\"superuser\",\"disabled\":true}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.delete", "{\"id\":1}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.update", "{\"id\":2,\"name\":\"okuyan\",\"disabled\":false}", token, now)).?.status);
    try testing.expectEqualStrings("okuyan", field(a, (try call(&auth, a, "me", "{}", aud_token, now)).?.body, "name"));
    // Blocking ends the user's session
    _ = (try call(&auth, a, "users.update", "{\"id\":2,\"name\":\"okuyan\",\"disabled\":true}", token, now)).?;
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "me", "{}", aud_token, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.delete", "{\"id\":2}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "roles.delete", "{\"id\":5}", token, now)).?.status);

    // our earlier project's rules. erdem has the role admin (every right), but is
    // not the superuser.
    _ = (try call(&auth, a, "users.create", "{\"name\":\"erdem\"}", token, now)).?;
    const erdem = (try db.userByName(a, "erdem")).?.id;
    _ = (try call(&auth, a, "users.grant", try std.fmt.allocPrint(a, "{{\"id\":{d},\"role\":1}}", .{erdem}), token, now)).?;
    const erdem_pw = "ankara12";
    try db.userSetOwnPassword(erdem, try users.hashPassword(a, auth.io, erdem_pw, auth.cost));
    const et = try testSignIn(&auth, a, "erdem", erdem_pw, now);
    // Nobody changes the superuser: not its name, password or roles
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.update", "{\"id\":1,\"name\":\"boss\",\"disabled\":false}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.reset", "{\"id\":1}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.grant", "{\"id\":1,\"role\":2}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.revoke", "{\"id\":1,\"role\":1}", et, now)).?.status);
    // The role admin: never deleted, changed by the superuser only
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "roles.delete", "{\"id\":1}", token, now)).?.status);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "roles.update", "{\"id\":1,\"name\":\"admin\",\"description\":\"x\",\"rights\":[]}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "roles.update", "{\"id\":1,\"name\":\"admin\",\"description\":\"Everything.\"}", token, now)).?.status);
    try testing.expect((try db.roleRights(a, 1)).len > 20);
    // The last admin is kept
    const eid = try std.fmt.allocPrint(a, "{{\"id\":{d},\"role\":1}}", .{erdem});
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.delete", eid, token, now)).?.status);
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.revoke", eid, token, now)).?.status);
    // Changing a role's rights is a right of its own
    _ = (try call(&auth, a, "users.create", "{\"name\":\"veli\"}", token, now)).?;
    const veli = (try db.userByName(a, "veli")).?.id;
    try db.userSetOwnPassword(veli, try users.hashPassword(a, auth.io, "trabzon61", auth.cost));
    const editor = try db.roleInsert("editor", "Names roles", &.{ "panel:login", "role:browse", "role:update" });
    try db.userGrant(veli, editor);
    const vt = try testSignIn(&auth, a, "veli", "trabzon61", now);
    // Rights alone: role:role_right, which veli does not have
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "roles.rights", try std.fmt.allocPrint(a, "{{\"id\":{d},\"rights\":[]}}", .{editor}), vt, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "roles.rights", try std.fmt.allocPrint(a, "{{\"id\":{d},\"rights\":[\"panel:login\",\"role:browse\",\"role:update\"]}}", .{editor}), token, now)).?.status);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "roles.rights", "{\"id\":1,\"rights\":[]}", et, now)).?.status);
    const ed_body = try std.fmt.allocPrint(a, "{{\"id\":{d},\"name\":\"editor\",\"description\":\"Renamed\"", .{editor});
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "roles.update", try std.mem.concat(a, u8, &.{ ed_body, ",\"rights\":[]}" }), vt, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "roles.update", try std.mem.concat(a, u8, &.{ ed_body, "}" }), vt, now)).?.status);
    try testing.expectEqual(@as(usize, 3), (try db.roleRights(a, editor)).len);
    // A user's nodes are terminal access: user:update alone does not change them
    const clerk = try db.roleInsert("clerk", "Edits users", &.{ "panel:login", "user:browse", "user:update" });
    try db.userGrant(veli, clerk);
    const ali = try db.userCreate("ali", false, "!", 1);
    const ali_nodes = try std.fmt.allocPrint(a, "{{\"id\":{d},\"name\":\"ali\",\"disabled\":false,\"nodes\":\"ist_*\"}}", .{ali});
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.update", ali_nodes, vt, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.update", try std.fmt.allocPrint(a, "{{\"id\":{d},\"name\":\"ali\",\"disabled\":false}}", .{ali}), vt, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.update", ali_nodes, et, now)).?.status);
    try testing.expectEqualStrings("ist_*", (try db.userGet(a, ali)).?.nodes);
    try db.userRevoke(veli, clerk);

    // Acting as another user: veli's rights apply, the audit names both
    const vid = try std.fmt.allocPrint(a, "{{\"id\":{d}}}", .{veli});
    // Only the superuser, not an admin
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.select", vid, et, now)).?.status);
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.select", vid, vt, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.select", vid, token, now)).?.status);
    const as_veli = (try call(&auth, a, "me", "{}", token, now)).?.body;
    try testing.expectEqualStrings("veli", field(a, as_veli, "name"));
    try testing.expectEqualStrings("superuser", field(a, as_veli, "real"));
    try testing.expectEqual(std.http.Status.forbidden, (try call(&auth, a, "users.list", "{}", token, now)).?.status);
    try testing.expectEqualStrings("superuser as veli", (try caller(&auth, a, token, now)).?.auditName(a));
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.unselect", "{}", token, now)).?.status);
    try testing.expectEqualStrings("superuser", field(a, (try call(&auth, a, "me", "{}", token, now)).?.body, "name"));
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "users.unselect", "{}", token, now)).?.status);
    // Changing one's own password needs the current one
    try testing.expectEqual(std.http.Status.conflict, (try call(&auth, a, "profile.password", "{\"current\":\"wrong\",\"new\":\"izmir3535\",\"new2\":\"izmir3535\"}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.bad_request, (try call(&auth, a, "profile.password", "{\"current\":\"ankara12\",\"new\":\"short\",\"new2\":\"short\"}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.bad_request, (try call(&auth, a, "profile.password", "{\"current\":\"ankara12\",\"new\":\"izmir3535\",\"new2\":\"izmir3536\"}", et, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "profile.password", "{\"current\":\"ankara12\",\"new\":\"izmir3535\",\"new2\":\"izmir3535\"}", et, now)).?.status);
    try testing.expectEqualStrings("code", field(a, (try call(&auth, a, "login", "{\"name\":\"erdem\",\"password\":\"izmir3535\"}", null, now)).?.body, "step"));
    // With a second admin, the first may lose the role
    try db.userGrant(veli, 1);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "users.revoke", eid, token, now)).?.status);

    // Five wrong passwords lock the user, also for the right one
    for (0..5) |_| _ = (try call(&auth, a, "login", "{\"name\":\"superuser\",\"password\":\"nope\"}", null, now)).?;
    try testing.expectEqual(std.http.Status.too_many_requests, (try call(&auth, a, "login", body, null, now)).?.status);
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "login", body, null, now + 61)).?.status);

    // Signing out ends the session; a full session ends after 12 hours
    try testing.expectEqual(std.http.Status.ok, (try call(&auth, a, "me", "{}", token, now + session_s - 120)).?.status);
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "me", "{}", token, now + session_s)).?.status);
    _ = (try call(&auth, a, "logout", "{}", token, now)).?;
    try testing.expectEqual(std.http.Status.unauthorized, (try call(&auth, a, "me", "{}", token, now)).?.status);

    try testing.expect(try call(&auth, a, "nodes.list", "{}", token, now) == null);
}
