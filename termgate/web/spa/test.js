// The panel's browser test (zig build web-test, src/webtest.zig): loaded
// by boot.js only when the address has ?test. It uses the panel as an
// admin would, through the page itself (fields, buttons, links), and
// writes the result into the page's title: "test: ok (scenario)" or
// "test: FAILED (<step>: <why>)". The server's database is checked
// afterwards by webtest.zig.
//
// ?test&password=<superuser's password>: a fresh termgate (from
// `termgate init`); the superuser's first sign-in sets up its second step.
"use strict";
(async () => {
  const q = new URLSearchParams(location.search);
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const $ = sel => document.querySelector(sel);
  const text = sel => ($(sel) ? $(sel).textContent : "");
  let step = "start";

  async function wait(what, cond, ms = 5000) {
    for (let t = 0; t < ms; t += 50) {
      if (cond()) return;
      await sleep(50);
    }
    throw new Error("waited for " + what);
  }
  const must = (ok, why) => { if (!ok) throw new Error(why); };
  function fill(id, value) {
    const el = document.getElementById(id);
    must(el, "no field " + id);
    el.value = value;
  }
  async function click(sel) {
    await wait(sel, () => $(sel));
    $(sel).click();
    await sleep(100);
  }
  async function go(hash) {
    location.hash = hash;
    await sleep(150);
  }
  const titled = t => () => text(".page-title h3").startsWith(t);
  const said = t => () => text("#site-message").includes(t);

  // TOTP (RFC 6238) of a base32 setup key, as an authenticator app
  async function totp(key) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const c of key.replace(/ /g, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
    const raw = new Uint8Array(bits.length >> 3).map((_, i) => parseInt(bits.substr(i * 8, 8), 2));
    const msg = new Uint8Array(8);
    new DataView(msg.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 30000)));
    const k = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
    const o = mac[19] & 15;
    return ((new DataView(mac.buffer).getUint32(o) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
  }

  // The id in a link such as #/user/role?userId=3
  const idIn = (sel, name) => +new URLSearchParams(($(sel).getAttribute("href") || "").split("?")[1]).get(name);
  // The value of the option shown as `label` in a select
  function option(id, label) {
    for (const o of document.getElementById(id).options) if (o.textContent === label) return o.value;
    throw new Error("no option " + label + " in " + id);
  }

  try {
    step = "sign-in page";
    await wait("the sign-in page", () => $("#login-input"));
    fill("login-input", "superuser");
    fill("password-input", "wrong-password");
    await click("[data-action=login]");
    await wait("the refusal", said("Wrong name or password"));

    step = "first sign-in";
    fill("login-input", "superuser");
    fill("password-input", q.get("password"));
    await click("[data-action=login]");
    // A release build asks for the second step (its setup at the first
    // sign-in, with the QR code); a debug build signs in at once
    await wait("the second step or the first page", () => $("#code-input") || titled("Nodes")());
    if ($("#code-input")) {
      const key = text(".panel-body strong");
      must(key.length >= 32, "no setup key shown");
      must($(".setup-qr svg"), "no QR code shown");
      fill("code-input", await totp(key));
      await click("[data-action=loginCode]");
    }
    await wait("the first page", titled("Nodes"));

    step = "pages";
    for (const [hash, title] of [["#/session", "Sessions"], ["#/audit", "Audit"], ["#/user", "Users"], ["#/role", "Roles"], ["#/config", "Configuration"], ["#/help", "Help"], ["#/profile", "Profile"], ["#/node", "Nodes"]]) {
      await go(hash);
      await wait(title, titled(title));
    }

    step = "node";
    await go("#/node/insert");
    fill("node-name-input", "web_gw01");
    await click("[data-action=nodeInsert]");
    await wait("the node key", () => text("pre").startsWith("tgnode --registration tg1-"));

    step = "search";
    await go("#/node?key=GW0&pn=1");
    await wait("the node found", () => text(".find") === "gw0" && text("td a").startsWith("web_gw01"));
    await go("#/node?key=nothing-like-it&pn=1");
    await wait("nothing found", () => text("td").includes("Empty list."));

    step = "user";
    await go("#/user/insert");
    fill("user-name-input", "veli");
    await click("[data-action=userInsert]");
    await wait("the password", () => text("#user-password").length === 20);
    const veli = idIn("a.button-primary[href^='#/user/role']", "userId");
    must(veli > 1, "no id for veli");

    step = "roles of veli";
    await go("#/user/role?userId=" + veli);
    await wait("the roles page", titled("Users"));
    fill("user-role-select", option("user-role-select", "admin"));
    await click("[data-action=userRoleGrant]");
    await wait("the grant", said("Role has been granted."));
    fill("user-role-select", option("user-role-select", "terminal_user"));
    await click("[data-action=userRoleGrant]");
    await wait("the second grant", said("Role has been granted."));

    step = "role";
    await go("#/role/insert");
    fill("role-name-input", "operator");
    fill("role-exp-input", "Watches sessions");
    await click("[data-action=roleInsert]");
    await wait("the rights page", () => $("input[value='node:browse']"));
    $("input[value='node:browse']").checked = true;
    $("input[value='session:watch']").checked = true;
    await click("[data-action=roleRightUpdate]");
    await wait("the rights saved", said("Role rights have been changed."));

    step = "configuration";
    await go("#/config");
    await wait("the settings", () => $("#config-minutes-input"));
    fill("config-minutes-input", "90");
    await click("[data-action=configUpdate]");
    await wait("the settings saved", said("Record has been changed."));

    step = "terminal access";
    await go("#/user/terminal?userId=" + veli);
    await wait("the terminal page", () => $("#term-nodes-input"));
    fill("term-nodes-input", "web_*");
    fill("term-runas-input", "root");
    fill("term-uses-input", "2");
    await click("[data-action=userTerminalInvite]");
    await wait("the invitation", () => text("pre").startsWith("tgterm --invite tg1-"));

    step = "acting as veli";
    await go("#/user");
    await wait("the users", titled("Users"));
    await click(`[data-action=userSelect][data-id='${veli}']`);
    await wait("acting as veli", () => text("#user-info").includes("Signed in as superuser"));
    await click("a.unselect-user");
    await wait("back to myself", () => !text("#user-info").includes("Signed in as"));

    step = "last admin";
    await go("#/user/delete?userId=" + veli);
    await click("[data-action=userDelete]");
    await wait("the refusal", said("The last admin cannot be deleted."));

    step = "sign out";
    await click("a[href='#/logout']");
    await wait("the sign-in page", () => $("#login-input"));

    document.title = "test: ok (scenario)";
  } catch (e) {
    document.title = "test: FAILED (" + step + ": " + e.message + ")";
  }
})();
