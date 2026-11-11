# termgate

Terminal access to many gateways that sit behind NAT, CGNAT or cellular links, without static IPs.

## What it does, and for whom

termgate gives your team a shell on remote Linux devices: IoT gateways, embedded boards, field machines. The devices and the people both connect **out** to one relay that you run. Nothing has to reach a device from outside, so:

- **No static IP, no VPN, no port forwarding.** Devices can sit behind a carrier's CGNAT, change networks or move.
- **No SSH server** on the device, and no open port. A single small agent (`tgnode`) does the job.
- **Easy to install.** The server side is one program; it starts the relay itself. The agent is one static binary, registered with a one-time key.
- **A basic but complete permission system.** Users, roles and rights; the nodes each user may reach (by name or glob); access that ends after N sessions or N days; instant revocation; an audit of everything done in the panel; a log of every command typed and its output; read-only watching of live sessions.

It is meant for teams that look after tens or hundreds of gateways in the field and do not want to pay for static IPs or buy special gateway modems/routers only to get a console on them.

## Built with

- **[Zig](https://ziglang.org) 0.17.1** for everything: the server, the user client, the agent, and the web panel. The panel is compiled to WebAssembly.
- **[nats-server](https://nats.io)** as the relay, with auth callout. The NATS client, nkeys, JWT and auth callout code are our own Zig code.
- **[libghostty-vt](https://ghostty.org)** draws terminal screens in the panel (watching a session, reading its log).
- **[SQLite](https://sqlite.org)**, **zig-js**, nayuki's **qrcodegen**, and **Font Awesome**.
- The panel's look and structure come from one of our earlier projects.

Zig made this small: one language from the browser to an ARMv6 board. Cross-compiling is one flag, and the binaries are static, with no runtime to install on the device. The standard library brings the crypto we need (Ed25519, X25519, ChaCha20-Poly1305, SHA-2, Argon2, TLS), so there are very few dependencies. Zig also uses C libraries directly: it compiles their sources and imports their headers, with no bindings to write. SQLite and libghostty-vt come in this way. This matters when working with an AI: a missing piece rarely means writing it from scratch, because decades of mature C libraries offer more than one proven option, and the AI can wire one in quickly.

Many thanks to the people behind Zig, NATS, Ghostty and SQLite.

## Components

| Program | Runs on | What it does |
|---|---|---|
| `termgate` | Your server | The authority: decides every connection and every session, keeps users, nodes, the audit and session logs (SQLite), serves the web panel. It starts and watches the relay (`nats-server`). |
| `tgnode` | Each gateway | The agent: connects out to the relay, asks termgate to approve each session, runs the shell in a PTY. Its identity is derived from the hardware. |
| `tgterm` | The user's computer | The client, used like `ssh`: `tgterm <node>`. |

```
browser ──HTTPS──► nginx ──► termgate ──┐
                     tgterm ────TLS─────┴──► relay (nats-server) ◄──TLS── tgnode × N
```

Only two things must be reachable on the server: the relay port (default 4222), for gateways and users, and the panel, through nginx.

## Install

Requirements: Zig 0.17.1 to build, and `nats-server` 2.10 or later on the server (tested with 2.15.2).

### Build

```sh
cd termgate && zig build -Doptimize=ReleaseSafe     # zig-out/bin/termgate, zig-out/web
cd tgterm   && zig build -Doptimize=ReleaseSafe     # zig-out/bin/tgterm
cd tgnode   && zig build -Doptimize=ReleaseSafe     # zig-out/bin/tgnode
# a gateway with another CPU, e.g. ARMv6 (Raspberry Pi Zero):
cd tgnode   && zig build -Doptimize=ReleaseSafe -Dtarget=arm-linux-musleabi -Dcpu=arm1176jzf_s
```

A release build asks for an authenticator code at sign-in (set up with a QR code at the first sign-in). A debug build does not ask, and listens on localhost only.

### Server

1. Copy `termgate/zig-out/` to the server, e.g. as `/opt/termgate` (`bin/termgate` and `web/` must stay side by side). Put `nats-server` on the PATH or next to `termgate`.
2. Choose the folder termgate will run in, and set it up once from there. termgate keeps everything it has (database, keys, relay configuration) in a `data` folder inside it, here `/var/lib/termgate/data`. `--relay` is the address gateways and users will use to reach the relay:
   ```sh
   mkdir -p /var/lib/termgate && cd /var/lib/termgate
   /opt/termgate/bin/termgate init --relay relay.example.com
   ```
   It prints the `superuser` password. Write it down.
3. Install it as a systemd service, from the same folder (as root):
   ```sh
   /opt/termgate/bin/termgate service
   ```
   The panel listens on 127.0.0.1:8080, and the relay on port 4222.
4. Put nginx in front of the panel for HTTPS: `termgate/deploy/nginx-site.conf`. Open port 4222 in the firewall.
5. Sign in as `superuser`, then create your admins: give them the `admin` role. Keep more than one admin, because there is no password reset on the server.

### A gateway (node)

1. In the panel: **Nodes → New**, give it a name (e.g. `ist_kadikoy_gw01`). termgate shows a **node key**, valid for one hour.
2. Copy `tgnode` to the device and, in the folder it should live in, register it:
   ```sh
   ./tgnode --node-key tg1-...
   ```
   It keeps retrying until the relay and termgate can be reached.
3. In the panel, open the node and **Approve** it. If you want to check, `./tgnode id` on the device prints the same hardware key the panel shows.
4. Make it a service (as root). With `--user U`, sessions run as U and can do only what U can. U must be the user who registered the node.
   ```sh
   ./tgnode service [--user U]
   ```

### A user

1. In the panel: **Users → New**. Give the user the `terminal_user` role and, under **Edit → Nodes**, the nodes they may reach (names or globs: `ist_*`, `pump??`).
2. On the user's page: **Access Key**. Set how many sessions, how many days, or both. Hand the key to the user.
3. On the user's computer:
   ```sh
   tgterm --access-key tg1-...       # once: creates the user's key, stored in ~/.config/tgterm/
   tgterm ist_kadikoy_gw01           # then, like ssh; "~." closes the session
   ```

### A local test loop

Everything on one machine, from the source tree (debug build, panel on http://127.0.0.1:8080):

1. `cd termgate && zig build && ./zig-out/bin/termgate init --relay 127.0.0.1`. This prints the superuser's password.
2. `./zig-out/bin/termgate run`
3. In the panel, sign in as `superuser`. Go to **Nodes → New** `test_gw`, and copy the node key.
4. `cd tgnode && zig build && mkdir -p /tmp/tgtest && cd /tmp/tgtest && <repo>/tgnode/zig-out/bin/tgnode --node-key tg1-...`
5. In the panel, approve `test_gw`. It shows as online.
6. In the panel, go to **Users → New** `alice`, then **Roles**: `terminal_user`, then **Edit → Nodes**: `test_*`, then **Access Key**: 5 sessions.
7. `cd tgterm && zig build && ./zig-out/bin/tgterm --access-key tg1-... test_gw`. You get a shell on the "gateway".
8. In the panel, under **Sessions**, check that the session is open. Try **Watch** and **Log**, then **End**.

Automated tests: `zig build test` in each folder; `zig build web-test` in `termgate` drives the panel in headless Chrome. The tests against a real nats-server are described in `CLAUDE.md`.

## Security

- **Outbound only.** Gateways open no port and run no SSH server. The relay is the only meeting point.
- **TLS with a pinned CA.** termgate creates its own CA (ECDSA P-256). Node keys and access keys carry its fingerprint, and clients trust nothing else. No domain or public certificate is needed for the relay.
- **Every connection is decided by termgate** (NATS auth callout). Each connection gets permissions for its own subjects only. When termgate is down, nobody connects and open sessions end.
- **Hardware-bound node identity.** The node's key is derived from CPU, board, NIC and disk data and never written to disk. A copied binary does not work on another device. Registration needs a single-use node key that expires in an hour, plus an admin's approval.
- **Users hold their own key.** An access key is single-use and only binds the user's new key; its limits (sessions, days) and the user's nodes live in termgate's database and are checked at every session. The private key never leaves the user's machine.
- **Every session is approved.** The session request is signed by the user's key (with a timestamp and a nonce against replay). termgate checks its database and answers with a signed approval, which the node verifies. A compromised relay cannot open a session.
- **End-to-end encryption.** Session data is encrypted between tgterm and tgnode (X25519, HKDF, ChaCha20-Poly1305), so the relay sees ciphertext only. termgate receives the session keys sealed to it, to log and watch sessions.
- **Instant revocation.** Disabling a node or taking a user's access closes their connections at once.
- **Audit and logs.** Every changing call in the panel and every sign-in is recorded. Session logs (commands and output) are encrypted at rest with a separate key.
- **Panel.** Passwords are Argon2id hashes, sign-in has a TOTP second step, and repeated failures lock the account with a growing delay. Browser sessions use HttpOnly, Secure, SameSite=Strict cookies. Rights are given to roles only, never to a user directly. There is no back door: no server-side password reset.
- **Data folder.** termgate's data folder is 0700 and its files are 0600.

What it does not protect against: someone who controls the server termgate runs on, or a user's computer. Keep those as you would keep an SSH server and an SSH key.

More detail: `docs/architecture.md`.

## Support

Need termgate adapted to your fleet, extended, or installed and run for you? [ionova.net](https://ionova.net) provides support and custom development.

## Origin

termgate is the rewrite of [farlogin](https://github.com/progfargo/farlogin), a prototype. The idea came from this article: [Linux terminals, tty, pty and shell](https://dev.to/napicella/linux-terminals-tty-pty-and-shell-192e).

---

Built with [Claude Code](https://claude.com/claude-code). I defined the features and requirements, chose the tools (Zig, NATS, libghostty-vt, SQLite), reviewed the results and tested the app; Claude wrote most of the code.

## License

MIT (see `LICENSE`). Bundled: Font Awesome Free (`termgate/web/asset/fontawesome/LICENSE.txt`), the Ubuntu font (Ubuntu Font Licence), zig-js (`termgate/vendor/zig-js/LICENSE`) and nayuki's QR Code generator (MIT, in its source).
