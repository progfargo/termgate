# termgate

termgate gives users (people and AI bots) terminal access to gateways that cannot accept inbound connections (NAT, CGNAT, cellular links, changing IPs). Access is time-limited or N-use, and every session is audited. Gateways and users only make outbound connections. There is no vendor-operated server; all keys stay with the customer.

termgate is a web application the customer runs on a server: the online authority that approves every session, counts uses, logs sessions and records audit and node status, and the panel where admins and auditors work, each as their own user, from any browser. When termgate is not running, no session can be opened and open ones are ended. The relay keeps no state.

## Features

- Terminal access to devices behind NAT/CGNAT, without static IPs, even while moving. No open port on the gateway.
- Access by invitation: time-limited (`exp`), N-use (`max_uses`), or both.
- Per-node authorization: the invitation fixes which nodes and which Unix user.
- Instant revocation; active sessions are cut as well.
- Hardware-bound node identity: a copied binary does not work on another device.
- Live monitoring of active sessions (read-only mirror) and killing them.
- Asset management: every node's status (online/offline), last seen time and system info (OS, memory, disk).
- AI bots are users too and access through the same model; they publish status and can ask the admin questions.
- Audit: session start/end, who, which node, which grant. Recorded by termgate.
- Session logs: every command of every session and its output (up to a set length), kept for a set number of days. Sessions have a maximum length.
- Each customer runs separate infrastructure. The vendor has no access.

## Components

| Binary | Runs on | Role | Secrets held |
|---|---|---|---|
| **termgate** | Customer server (with the relay, or a machine in the customer's own network) | Auth callout for every connection; node registration, invitations, grants, revocation; approves sessions and counts uses; session logs, audit and node status (SQLite); the web panel for admins and auditors (users, roles) | Issuer key, its NATS keys, CA key, log key |
| **tgterm** | User's terminal (CLI) | Like `ssh`: node list, session in the user's own terminal, headless mode for bots | Its own user key |
| **tgnode** | Gateway | Grant and proof verification, asks termgate for approval, PTY, audit events, system info | None (key derived from hardware) |

```
browsers ──HTTPS──► nginx ──► termgate ──┐
                               tgterm   ──┼──TLS──► relay (nats-server) ◄──TLS── tgnode × N
                               (bot)    ──┘
```

One program to install: termgate starts the relay (the official nats-server) itself from the kit in its home and keeps it running; when termgate stops, the relay stops, and with it every connection. A customer who does not want this on a hosted server installs it on a machine in their own office and opens the relay port (and, if they wish, the panel) from there.

The relay process still holds no access-granting key: on its own it can drop traffic but cannot open a session on any node, since grants and session approvals are signed by termgate's issuer key and nodes verify them themselves. Session data is end-to-end encrypted, so the relay does not see it either.

## Identity

The relay runs nats-server with a fixed configuration and **auth callout**: every client connection is put to termgate, which decides who it is and what it may do, and answers with a user JWT for that connection only. Nothing that grants access is stored on nodes or user machines except their own private keys; disabling or deleting a node, or a user losing its terminal access (revoked, blocked, or no role with terminal:connect any more), closes their open connection at once (termgate finds it in the relay's connection list and asks the relay to close it) and the callout refuses them from then on.

Identity is checked once per connection, not per message: after the callout, NATS checks every publish and subscribe against that connection's permissions, and TLS keeps anyone from injecting into the connection. Session requests and approvals are signed on top of that.

| Key | Held by | Used for |
|---|---|---|
| Issuer key (Ed25519 nkey) | termgate | Signs the per-connection user JWTs (callout answers), grants and session approvals |
| termgate's NATS keys | termgate | Three connections: callout user (AUTH account) and system user (SYS account) bypass the callout; the application key goes through it |
| Hardware key | Derived from the node's hardware | Signs the server nonce when the node connects |
| User key | The user's machine (tgterm) | Signs the server nonce; signs session requests |
| CA key (ECDSA P-256) | termgate | Signs the relay's TLS certificate |

- **Hardware key:** the node's identity. CPU info, DMI `board_serial`/`product_uuid`, persistent NIC MACs and root disk serial (or WWID) → SHA-256 with a domain prefix → Ed25519 seed. Never written to disk.
- **User key:** generated by tgterm when an invitation is used and kept in the OS key store (a file for headless bots). The private key never leaves the user's machine.
- **Callout:** a connecting client signs the server's nonce with its key; termgate verifies that signature and looks the key up: an approved node, a known user, or a key presenting a node key or invitation (sent as the connection's auth token).
- **TLS:** clients trust only termgate's CA; no domain needed. CA and relay keys are ECDSA P-256 (Zig's TLS client does not accept Ed25519 server keys). The relay uses `handshake_first`, so TLS starts with the first byte.

## Grant

A grant is a JWT in the same format as NATS JWTs, signed by termgate's issuer key. Its `nats` section has `type: "grant"`, so a grant is never accepted as a user JWT and vice versa.

```json
{
  "jti": "...", "iat": 1794289057, "iss": "<termgate issuer key>", "name": "ali",
  "sub": "U...user pub", "nbf": 1794289057, "exp": 1794292657,
  "nats": {
    "type": "grant", "version": 1, "kind": "human | bot",
    "nodes": ["gw17", "pump??", "ist_*"], "run_as": "root | tgbot", "max_uses": 3
  }
}
```

- `nodes` holds name patterns written by the admin: `*` matches any run of characters, `?` exactly one (e.g. `ist_*`, `pump??`).
- tgnode verifies offline: signature, `exp`/`nbf` (5 min leeway), `type`, that `iss` is termgate's issuer key, that `sub` is the requesting user, and that its own name matches a pattern in `nodes`.
- A grant is limited by `exp`, by `max_uses`, or by both; at least one is required.
- `max_uses` is counted by termgate (SQLite, keyed by the grant's `jti`) when it approves a session, so the limit holds across all matching nodes.
- Revocation: termgate marks the grant or user as revoked and stops approving; active sessions get `.end`, and the user's connections are closed (the callout refuses them from then on).

## Flows

termgate keeps everything it has in one folder: `./data` in the folder it is started in. No folder is asked for on the command line; the panel's files are found next to the binary. In `data/`: the database (`termgate.db`), `relay.json` (relay address and termgate's four keys), `ca.pem` (the CA certificate), `keys/ca.key` (the CA's private key) and `keys/log.key`, and `relay-kit/` with the relay's configuration and its TLS certificate and key (`server.pem`, `server.key`). Run from the source tree the data stays in the project, ignored by git; on a server termgate is started in e.g. `/var/lib/termgate` (`termgate service` writes that folder into the systemd unit). The folder can be moved as a whole.

**Setup** (`termgate init --relay HOST[:PORT]`, once, on the server)
1. Generate the issuer key, termgate's NATS keys, the CA and the session log key, and create the first admin user.
2. Write the relay kit into termgate's home: nats-server configuration (auth callout pointing at the issuer key, termgate's callout user in AUTH, its system user in SYS) and the relay's TLS certificate and key for HOST.
3. `termgate run` (or `termgate service` for systemd) starts the relay and termgate. The relay port must be reachable by gateways and users; the panel listens on localhost for nginx.

**Node enrollment**

The admin gives each node a name when enrolling it. Names are unique per customer (termgate enforces it) and look like identifiers whose parts are separated by `_`, like the labels of a subdomain: `ist_kadikoy_gw01`, `pump07`. Rules: 1 to 63 characters; lowercase letters, digits and `_`; starts with a letter; no trailing `_` and no `__`. Lowercase only, so `GW1` and `gw1` cannot be two nodes. A name is always a single NATS subject token.

1. In termgate the admin creates the node: name and description. termgate generates a **node key** for it and shows it:
   ```
   tg1-relay.example.com:4222-<CA fingerprint>-<token>
   ```
   It carries everything the node needs for its first contact: the relay address, the SHA-256 fingerprint of termgate's CA (base32) and a random token (32 bytes, base32) tied to this node record. termgate keeps only the token's SHA-256. The key expires after an hour if unused.
2. The admin copies the tgnode binary to the device and runs it once with the node key: `tgnode --node-key tg1-...`
3. tgnode derives its hardware key. The node key only carries the CA's fingerprint, so tgnode first connects without certificate verification, asks for termgate's CA (`ca.get`, allowed for anyone) and checks it against the fingerprint; nothing secret is sent on that connection. It then reconnects, verifying the relay against that CA, with the node key's token as auth token. The callout recognizes the token and lets the connection do one thing: send registration requests to `register.<token id>` (a short hash of the token) carrying the hardware key and the node's system info (hostname, OS, CPU, memory, disk). termgate stores it under the node record as "waiting for approval" and answers "pending".
4. The admin sees it in termgate (first contact, the node's hardware public key, its properties) and compares it with `tgnode id` on the device if needed, then approves. The hardware key is now bound to the node name.
5. tgnode repeats the request every 5 s. Once approved, termgate answers with the node name and its issuer key; tgnode writes its configuration (name, relay address, CA, issuer key) to `node.json` in the folder it was started in, and starts serving. From then on `tgnode run` needs no parameter and the callout recognizes the node by its hardware key.

If termgate is not running, registration waits: tgnode retries every 5 s until the node key expires.

**Invitation**

An invitation gives one user (a person or a bot) terminal access. The admin sets which nodes (name patterns), as which Unix user, how many sessions and/or until when; giving it again replaces what the user had. The user gets a single string:

```
tg1-relay.example.com:4222-<CA fingerprint>-<token>
```

- CA fingerprint: SHA-256 of the termgate CA certificate, base32. tgterm only accepts a relay whose TLS chain ends in this CA.
- Token: 32 random bytes, base32, single use. termgate stores only its SHA-256 together with the grant spec.

Using it: `tgterm --invite tg1-... ist_kadikoy_gw01`.
1. tgterm generates the user's key pair.
2. It connects to the relay with the invitation token as auth token, signing the server nonce with the new key.
3. The callout checks the token, marks it used and binds the public key to the user and its grant; the connection gets that user's permissions. termgate also sends tgterm the grant.
4. tgterm stores its key, the relay address, the CA and the grant. Later connections use only the key; the callout recognizes it.

If termgate is not running, the connection is refused ("termgate is offline"). The token is useless once used.

**Session**
1. tgterm sends a session request to `session.open.<node>`: the grant, the node name, a timestamp and a random nonce, signed with the user key named in the grant's `sub`. NATS does not tell the receiver who published a message, so this signature is the proof that the requester holds the grant's key.
2. tgnode verifies the grant, the signature, that the timestamp is within the 5 min leeway and that the nonce has not been used (replay cache).
3. tgnode asks termgate for approval with a request to `authorize.<node>` (grant, nonce, session id). termgate checks revocation and `max_uses`, counts the use, records the session start and replies with an approval signed by the issuer key that echoes the nonce. No responder means termgate is offline: the session is refused.
4. tgnode verifies the approval, opens a PTY as `run_as` and returns a `sid`.
5. Data flow (tgnode subscribes to `in.<node>.<user>.<sid>.*`):
   - `in.<node>.<user>.<sid>.data`: input
   - `out.<node>.<user>.<sid>.data`: output; `out.<node>.<user>.<sid>.end`: the shell has exited
   - `in.<node>.<user>.<sid>.resize`: window size (4 bytes big-endian: cols, rows)
   - `in.<node>.<user>.<sid>.end`: close
6. At the end tgnode sends the session end to `audit.<node>` as a request and repeats it until termgate acknowledges it (kept in memory, bounded).
7. termgate closed means the system is closed, also for open sessions: while it has open sessions, tgnode asks termgate every 10 s whether it is there (`audit.<node>`, event "alive"). With no answer for 60 s (a termgate restart or a short relay outage fits in that) it tells the users on their screens and ends the sessions; nobody would log, watch or time-limit them.

**End-to-end encryption of session data.** TLS protects each connection to the relay, but inside the relay messages are in clear. Session data (`in.<...>.data`, `out.<...>.data`) is therefore encrypted between tgterm and tgnode; the relay, and whoever runs or breaks into its server, sees only ciphertext.
- Key agreement, X25519 with one key pair per session on each side: tgterm's public key is in its signed session request; tgnode's goes to termgate in the approval request and comes back in termgate's signed approval, which tgnode passes to tgterm and tgterm verifies (signed by the issuer of its grant, for its user, nonce and key). The relay can replace neither key unnoticed.
- Both derive two keys with HKDF (bound to the session id and both public keys): one per direction. Each message is ChaCha20-Poly1305 with sender and counter as nonce; a receiver refuses a counter it has seen, and anything that does not decrypt is dropped (a relay cannot type into a session or write on the user's screen).
- termgate logs and watches sessions, so tgnode gives it the session keys in the approval request, sealed to termgate's issuer key (converted to X25519) and bound to the session id and both public keys. termgate refuses the session if they do not open, and stores them encrypted with the log key. Its own messages on the user's screen (session time limit) are encrypted with the session key as a third sender.
- Not encrypted: window sizes and the end of a session (no content), and subjects (who talks to which node, when, how much).

**Monitoring**
- The open sessions on the Sessions page come from termgate's own approvals and the end events.
- Watching a session (read-only): termgate subscribes to `out.<node>.<user>.<sid>.*` and `in.<node>.<user>.<sid>.resize`, decrypts them and keeps them for the watching page, which feeds them into a libghostty-vt screen in the browser. It shows what happens from the moment watching starts; nothing is sent to the node and nodes do nothing extra.

**Session logs**
- termgate subscribes to all session traffic (`out.*.*.*.*`, `in.*.*.*.data`) and stores it as it went through the relay, unchanged: a log that is changed is not a log. Nothing extra is asked of nodes or tgterm, and no screen is kept in memory.
- Split into commands at Enter: a command is what the user typed up to Enter (raw keys), its output what the node sent until the next Enter (raw, escape sequences included), cut at "max command output" characters; the full count is stored. Typed passwords are therefore in the log, which is why it is encrypted.
- Encrypted in the database: what was typed and the output, each with XChaCha20-Poly1305 under the log key (`keys/log.key`, 32 random bytes, 0600, made at setup), a random nonce per field, and the session id, command number and field name authenticated with it. A copy of the database alone cannot be read, and a part moved to another session or changed does not decrypt and is shown as such. Session, order, time and output length stay readable (searching, deleting old logs). Whoever has the log key can read the logs: it sits with termgate's other keys (see "Security boundary").
- A session's Log page lists each command with its output as text in the page; escape sequences are shown, never interpreted, so they cannot reach the admin's terminal, clipboard or files. An entry that does not decrypt is marked so.
- Stored in termgate's database (`sessionCommand`). Logs older than "keep session logs" days are deleted hourly; the session list (audit) is kept.
- Sessions longer than "max session length" are told so on the user's screen and ended like an admin's End.
- The three settings are on termgate's Configuration page (defaults: 10000 characters, 480 minutes, 30 days; 0 means no limit / kept).
- Sessions are recorded while termgate runs; one open before termgate started is recorded from then on.

**Node status (asset management)**
- No heartbeat: a node stays connected to the relay, so online means connected. termgate's system connection follows `$SYS.ACCOUNT.APP.CONNECT` / `DISCONNECT`; on any event (at most once a second) and at start it reads the account's connection list (`$SYS.REQ.ACCOUNT.APP.CONNZ`) and marks the nodes in it online. A node going offline keeps that moment as last seen. Without the relay connection termgate shows every node offline.
- The callout names connections `node:<name>` and `user:<key>` so a user never passes for a node in that list. termgate closes connections by these names (`$SYS.REQ.SERVER.<id>.KICK`).
- When a node is cut off its open sessions are marked ended in the audit, since it cannot report them; the sessions of a user who may not connect any more are ended on the nodes, which report them as usual.
- System info: tgnode publishes `status.<node>` once after connecting and whenever asked (`status.req.<node>`, `status.req.all`); termgate asks all nodes when the Nodes page is opened, at most every 30 s. termgate stores the latest in SQLite.
- Contents: tgnode version, hostname, OS, kernel, architecture, CPU count, uptime, load average, memory total/available, disk total/free for the root filesystem.

**AI bot**
- Invited with a `kind: bot` grant and runs as a restricted `run_as` user.
- Connects with `tgterm --headless`.
- Publishes a one-line status to `bot.status.<user>`.
- Asks questions over `bot.ask.<user>` (request/reply); the answer comes from termgate.

## NATS subjects

`<node>` is the node name, `<user>` the user's public key ("U..."), `<sid>` a random session id.

| Subject | Publisher | Subscriber |
|---|---|---|
| `$SYS.REQ.USER.AUTH` | nats-server (auth callout) | termgate |
| `ca.get` | anyone (request) | termgate: the CA certificate |
| `register.<token id>` | tgnode during registration (request) | termgate: pending / approved |
| `$SYS.ACCOUNT.APP.CONNECT`, `.DISCONNECT`, `$SYS.REQ.ACCOUNT.APP.CONNZ` | nats-server | termgate (system user): who is online |
| `status.<node>` | tgnode, after connecting and when asked: system info | termgate |
| `status.req.<node>`, `status.req.all` | termgate | tgnode |
| `session.open.<node>` | tgterm (request) | tgnode (reply to the requester's inbox) |
| `authorize.<node>` | tgnode (request) | termgate (signed approval) |
| `in.<node>.<user>.<sid>.data` | tgterm: keyboard input | tgnode |
| `in.<node>.<user>.<sid>.resize` | tgterm: window size, 4 bytes big-endian (cols, rows) | tgnode, termgate (watching) |
| `in.<node>.<user>.<sid>.end` | tgterm, termgate (kill) | tgnode |
| `out.<node>.<user>.<sid>.data`, `.end` | tgnode: terminal output, session closed | tgterm, termgate (mirror) |
| `audit.<node>` | tgnode (request, retried until acknowledged) | termgate |
| `bot.status.<user>` | bot | termgate |
| `bot.ask.<user>` | bot (request) | termgate (reply) |
| `_INBOX.<user>.>`, `_INBOX.<node>.>` | replies to requests | that user or node only |

Putting `<user>` into the session subjects lets NATS keep users apart: one user cannot read another user's output or type into their session. Node name patterns in grants cannot be expressed as NATS permissions (NATS wildcards match whole tokens), so tgnode enforces those; NATS enforces who may use which subjects.

Permissions termgate gives each connection (in its callout answer):

| Identity | Publish | Subscribe |
|---|---|---|
| tgnode `<node>` | `status.<node>`, `authorize.<node>`, `audit.<node>`, `out.<node>.>`; replies to requests | `session.open.<node>`, `status.req.<node>`, `status.req.all`, `in.<node>.>`, `_INBOX.<node>.>` |
| tgnode while registering | `register.<token id>` | `_INBOX.<key>.>` |
| anyone else with a valid key signature | `ca.get` | `_INBOX.<key>.>` |
| user / bot `<user>` | `session.open.*`, `in.*.<user>.>`, `bot.status.<user>`, `bot.ask.<user>` | `out.*.<user>.>`, `_INBOX.<user>.>` |
| termgate | everything | everything |

- A user may send `session.open` to any node; the node rejects it unless the grant's patterns match. Session ids are random, and `in`/`out` subjects carry the user key, so a user can only reach sessions opened with their own key.
- tgterm and tgnode use `_INBOX.<user>` / `_INBOX.<node>` as inbox prefix so replies cannot be read by others.
- System info goes to `status.<node>`, which only termgate may subscribe to; users do not see other nodes or users.

There is no JetStream: the relay keeps no state. Use counters, invitations, audit and node status live in termgate's SQLite database.

## Tooling

| Area | Choice |
|---|---|
| Language | Zig 0.17.1 for every binary |
| UI (termgate) | Web panel built like our earlier project: a single-page app in Zig, compiled to WASM (`wasm32-freestanding`), that builds the page in HTML through zig-js (a copy in the repo, made to build with Zig 0.17); our earlier project's style sheet and Font Awesome. Pages are addressed by the hash (`#/user`, `#/user/update?userId=3`); buttons carry `data-action` and one listener passes them to the WASM. The server's JSON API is our earlier project's: `/api/<page>/<function>`, the right checked being `page:function` (rights.zig). The session terminal is drawn by libghostty-vt in the same WASM, as HTML text (so it can be selected and copied). Served behind nginx, which terminates HTTPS. |
| tgterm | CLI. tty in raw mode; input/output relayed over NATS; resize on SIGWINCH |
| Terminal emulation | libghostty-vt (lib/core `vt` module), in the panel's WASM: a watched session's screen, drawn as HTML text with its colors, bold, underline and the cursor. |
| Crypto | `std.crypto.sign.Ed25519`, SHA-256, SHA-512/256. nkeys (base32 + CRC16), JWT and the auth callout are our own code. |
| TLS | Zig std TLS client, pinned CA |
| NATS client | Our own (`lib/core`): core protocol, request/reply |
| NATS server | Official `nats-server` binary, started and kept running by termgate itself (the relay); fixed configuration with auth callout, no JetStream |
| PTY (tgnode) | `openpty` + `fork` on Linux, ConPTY on Windows |
| Local data (termgate) | SQLite: nodes and their last status, invitations (token hashes), grants and use counts, audit. |
| Targets | termgate and tgterm: Linux, Windows, macOS. tgnode: linux amd64/arm64/arm5-7, windows amd64 |

## Layout

```
termgate/
  docs/        design
  lib/core/    shared Zig package: nats, nkeys, jwt, grant, tls (no UI)
  termgate/    the authority, its web panel and the relay: the server
               program and its API (src/server), the panel's single-page
               app (src/spa, one file per page under src/spa/pages) and
               the page around it (web/: index.html, the JS glue, style
               sheet, fonts)
  tgterm/      user and bot client (CLI)
  tgnode/      gateway agent
```

Each binary builds on its own with its own `build.zig` and `build.zig.zon`, and depends on `lib/core` through `.path = "../lib/core"`. External dependencies are pinned with `url` + `hash`.

## UI (termgate web panel)

- Built like our earlier project (its `spa/`), with its pieces translated to Zig: `main` wires the routes and actions; `dom` sets HTML and reads fields; `router` follows the hash; `layout` is the frame (header with the top menu and the search box, left menu with the signed-in user at its bottom, message area, `#main-content`, footer); `state` holds the signed-in user, its rights and the messages; `fetch` makes the API calls, asynchronously: each event of the page (a hash change, a click, a tick of a watched session) runs as a job; when it asks for an answer that has not come, the request goes out and the rest of that run changes nothing, and when the answer comes the job runs again from the start with the answers it has. A page's code thus reads from top to bottom, as our earlier project's inside a goroutine. From our earlier project as they are: `lib/tax` (a tree the menus are built on: an item per page, visible by the user's right), `lib/cargo` (a page's state as named variables: every address a page makes is written by it and every address it opens is read by it), the ruler (page numbers), the page title, combo boxes, and messages (Error:, Warning:, Info:, Success:, closed by hand or after 5 seconds). The look is our earlier project's style sheet, unchanged, light or dark.
- Each page is a file that writes its HTML into a buffer and sets `#main-content`: a list with filters and paging, a form for insert and one for update, delete asks first. A page reads its state from its address (`#/user?key=ali&pn=2`, `#/user/update?userId=3`) with cargo. As in our earlier project, searching, paging and filtering a list change its cargo and draw it again without changing the address; the page title's link button copies the list's address with its state.
- The API (`/api/<page>/<function>`, JSON in and out): `browse`, `get`, `insert`, `update`, `delete` and the page's own functions (e.g. `user/role_grant`, `user/select`, `role/right_update`, `node/approve`). `/api/init` tells the page who is signed in and its rights; `/api/login`, `/api/login/code`, `/api/logout`. Every answer may carry `messages` (name, type error/warning/info/success, lines, auto-clear, title): a refused rule is a warning with status 200, a missing right is 400, a missing record 404, as in our earlier project. Only calls with the header `x-termgate: spa` are answered.
- Lists are searched and paged on the server, as in our earlier project: a search box in the header, 20 rows a page, page numbers under the list, the search word marked in the rows (nodes, users, sessions, audit).
- Installable (PWA): a manifest and icons let phones and desktops install the panel as an app. Nothing is kept for offline use, so there is no service worker.

- Users, roles and rights, with our earlier project's rules. A right is a module and one of its actions (`termgate/src/rights.zig`): panel (sign in), nodes (browse, insert, update, delete), sessions (browse, watch, read logs, end), audit (browse), users (browse, insert, update, reset password, delete, act as another user, stop acting, see roles, give roles, take roles, give terminal access), roles (browse, insert, update, delete, change rights), profile (browse, change own password), configuration (browse, update), help (browse), terminal (connect). Rights are given to roles and roles to users; a user without a role has no right. Tables: `role`, `roleRight`, `userRole`. A new database has the roles `admin` (every right but terminal:connect), `auditor` (reading, and its own password) and `terminal_user` (terminal:connect). The server checks the right on every call; the panel shows only the pages and buttons the user has the right for. The rules:
  - The superuser is the first user, named `superuser` (`termgate init`): every right. Nobody can change it, block it, delete it, give it a new password, or give or take its roles; it changes its own password in its profile.
  - The role `admin` cannot be deleted, and only the superuser changes it. The last user with the role `admin` cannot be deleted or lose the role.
  - Acting as another user (users.select): a user with the right sees and uses the panel as another user does, with that user's rights, until it goes back (users.unselect); both are checked against its own rights, and only the superuser may act as the superuser. The audit names both ("erdem as veli"). Used to test what a role allows.
- One kind of user: admins, auditors, terminal users and bots are all users (table `user`), and what each may do comes from its roles. A user's terminal access (table `terminal`: nodes, Unix user, limits, its tgterm key) is given on the Users page; the relay lets a user connect only while it is not blocked, its access is not revoked and a role gives it terminal:connect. Taking that away closes its open connections.
- Menus: on the left Nodes, Sessions, Audit, and Admin with User Management (Users, Roles) and Configuration, then the signed-in user and the logo; at the top Profile, Help, Logout and the theme switch.
- Signing in: user name and password, then a 6-digit code from an authenticator app (TOTP, RFC 6238, as in Google Authenticator). The second step is set up at the user's first sign-in: the panel shows a new secret, as a QR code to scan (drawn by the server, nayuki's qrcodegen) and as text to type, and the first code confirms it. A debug build (local use, the tests) has no second step; a release build, the one for a server, always has it. A code is accepted once. Wrong passwords and codes count together: from the fifth in a row the user is locked for 1, 2, 4 ... minutes, at most an hour. An unknown name and a wrong password get the same answer after the same work. While the password is checked the form is disabled and its button shows a spinning wheel.
- Passwords are stored as Argon2id hashes (19 MiB, 2 passes, OWASP's recommendation; a hash made with other parameters is made again at the next sign-in), TOTP secrets encrypted with the log key. A browser session is a random token in an HttpOnly, Secure, SameSite=Strict cookie; the server stores only its hash. It lasts 12 hours; a new password or disabling the user ends its sessions.
- No sign-up page: users are created by a user with the right, who hands over the generated password (`termgate init` prints the superuser's). No "forgot password" either: an admin resets the user, which gets a new password and sets up its second step again; the reset is recorded in the audit. There is no reset on the server (no command for it), so a password never changes without a record: a customer keeps more than one admin.
- termgate sends no e-mail to anyone: no mail server to configure. Invitations and node keys are shown in the panel and handed over by the admin.
- Nodes page: a table of nodes with state (online/offline, waiting for approval, disabled), last seen and system info (OS, architecture, CPUs, memory, disk, tgnode version), and the counts on the right. A node's page: connection (online, last seen, hardware key, added), full system info with a Refresh button (`status.req.<node>`, also sent when the page opens), its open sessions (with End) and its last sessions, and Disable/Enable, New node key, Delete.
- Sessions page: the open sessions with Watch (read-only), Log and End, and all sessions, searched and paged. Watching a session shows its terminal; End ends it on the node, and the page stays with the last screen.
- Audit page: what users did in the panel: every changing call and every sign-in, failed ones included, with who, when, what (the node or user it was about) and whether it was done or denied. Recorded on the server for every changing call, whatever the page does.
- Configuration page: the relay (address, CA fingerprint), the session settings (max command output, max session length, keep session logs) and the ruler length (page numbers on each side of the current one, 2 to 10, our earlier project's rulerLen).

## Deployment and security boundary

**Deployment: single tenant, open source, no license.** Each customer runs its own termgate (on a server) and its own relay. termgate holds the customer's keys; the relay holds none. The vendor runs no part of the customer's system and has no access to it.

**Security boundary.** termgate protects access to the nodes: only termgate's decisions open sessions, the relay holds no key, NATS keeps every connection to its own subjects. It does not protect against someone who controls the server termgate runs on: termgate's keys sit in its folder, readable by its service account only (0600). Keeping that server safe is the customer's job. The web panel is the exposed part: a customer who finds that too risky installs termgate on a machine in their own office and decides themselves who can reach it. The same holds for a user: tgterm keeps the user's key in a file readable by that user only, like an SSH key; keeping it is the user's job. A stolen user key is limited by the grant (uses, expiry), can be revoked by the admin at once, and every session it opens is logged. Session logs are additionally encrypted in the database (log key in the folder), so a copy of the database alone cannot be read.

## Origin: the farlogin prototype

termgate builds on farlogin, a prototype designed and developed by progfargo. The following core ideas and solutions were introduced in farlogin and proven to work there:

- **Outbound meeting point.** Devices and operators both connect out to a central NATS broker, so NAT, CGNAT and changing IPs stop being a problem.
- **Hardware-bound node identity.** The key is derived from CPU, DMI, NIC and disk data and used as an Ed25519 nkey; no secret on disk, a copied binary does not work.
- **Short-lived, per-session authorization.** An Ed25519-signed JWT (`sid`, `jti`, `exp`) that the node verifies offline, with `jti` replay rejection and clock skew tolerance.
- **Per-node NATS permissions.** Each node can only talk on its own subjects.
- **Terminal protocol.** Separate input/output subjects, a 4-byte resize message, and an `.end` signal that sends SIGHUP to the shell so the session ends cleanly.
- **One-time install token.** Node enrollment with a single-use token and the hardware public key; termgate's node key and admin approval build on it.
- **Embedded NATS.** The idea of shipping the server side as a single binary.
- **Audit.** First-use reporting and session records.
- **Cross-compilation and distribution.** The gateway binary for linux amd64/arm64/arm5-7 and windows, with ConPTY on Windows.
- **Positioning.** A last-resort console for IoT fleets, and the screen-access vision (Farscreen).

The main decisions in this work were also made by progfargo:
- A web panel on a server, built like our earlier project: a JSON API and a single-page app in Zig.
- A separate relay per customer, run by the customer.
- One program for the authority, the panel and the relay.
- Time-limited and N-use invitations.
- AI bots accessing and being monitored as users, through the same model.
- Naming.
- Writing everything in Zig, following repeto's discipline.

## Open decisions

1. Can only termgate answer bot questions, or tgterm users too?
