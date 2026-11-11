// The page around termgate's panel (src/spa, WASM). Nothing of the panel
// is here: this loads the WASM, makes its calls to the server, and passes
// it the page's events: the hash, and clicks on [data-action] with the
// fields of their form (as our earlier project's event delegation). Only what is
// plain page behavior (closing a message, opening a sub-menu, the menu on
// a phone) is done here directly.
"use strict";
(async () => {
  const enc = new TextEncoder();
  const zjs = new ZigJS();
  let x = null;
  let clearTimer = 0;

  const env = {
    // POST /api/<path>, JSON, without waiting: the answer goes to the
    // panel's tg_answer with the request's id (status 0: the server
    // cannot be reached). The session cookie goes along by itself.
    tg_post(id, pathPtr, pathLen, bodyPtr, bodyLen) {
      const path = zjs.loadString(pathPtr, pathLen), body = zjs.loadString(bodyPtr, bodyLen);
      fetch("/api/" + path, {
        method: "POST",
        headers: { "x-termgate": "spa", "content-type": "application/json" },
        body,
      }).then(async r => [r.status, await r.text()], () => [0, ""])
        .then(([status, text]) => {
          const b = enc.encode(text);
          const p = x.tg_alloc(b.length || 1);
          new Uint8Array(zjs.memory.buffer, p, b.length).set(b);
          try { x.tg_answer(id, status, p, b.length); } finally { x.tg_free(p, b.length || 1); }
        });
    },
    tg_log(ptr, len) { console.log(zjs.loadString(ptr, len)); },
    tg_now() { return Date.now(); },
    // A new frame (layout.zig): its header is watched (our earlier project's
    // setupHeaderWatch)
    tg_layout_ready() { setupHeaderWatch(); },
  };

  window.tg = {
    // The first text field of the page's content gets the focus, without
    // scrolling the page to it
    focusFirst() {
      const f = document.querySelector("#main-content input[type=text], #main-content input[type=password], #main-content textarea");
      if (f) f.focus({ preventScroll: true });
    },
    // The messages marked auto-clear go after 5 seconds (our earlier project's
    // Msg.Render); an empty message area is emptied
    autoClear() {
      clearTimeout(clearTimer);
      clearTimer = setTimeout(() => {
        const box = document.getElementById("site-message");
        if (!box) return;
        for (const m of box.querySelectorAll(".auto-clear")) m.remove();
        if (!box.querySelector(".alert")) box.innerHTML = "";
      }, 5000);
    },
    // The page title's link button: the page's full address (our earlier project's
    // copyUrl), the button blinks
    copyUrl(url) {
      tg.copy(location.origin + "/#" + url);
      const el = document.querySelector("[data-action='copyUrl']");
      if (el) { el.style.opacity = "0"; setTimeout(() => { el.style.opacity = "1"; }, 100); }
    },
    // Clipboard, for the panel's Copy buttons
    copy(text) {
      if (navigator.clipboard) { navigator.clipboard.writeText(text).catch(() => {}); return; }
      // Not a secure page (plain http on a local name): the old way
      const t = document.createElement("textarea");
      t.value = text; t.style.position = "fixed"; t.style.opacity = "0";
      document.body.appendChild(t); t.select();
      try { document.execCommand("copy"); } catch (e) {}
      t.remove();
    },
  };

  const imports = Object.assign(zjs.importObject(), { env });
  const { instance } = await WebAssembly.instantiateStreaming(fetch("/spa/termgate.wasm"), imports);
  x = instance.exports;
  zjs.memory = x.memory;

  // Strings into the WASM: each call gets its own copies, freed after
  function call(fn, ...strings) {
    const held = strings.map(s => {
      const b = enc.encode(s);
      const p = x.tg_alloc(b.length || 1);
      new Uint8Array(zjs.memory.buffer, p, b.length).set(b);
      return [p, b.length || 1, b.length];
    });
    try { fn(...held.flatMap(h => [h[0], h[2]])); }
    finally { for (const h of held) x.tg_free(h[0], h[1]); }
  }

  const hashPath = () => location.hash.length > 1 ? location.hash.slice(1) : "/";
  window.addEventListener("hashchange", () => {
    closeSidebar();
    call(x.tg_route, hashPath());
  });

  // The fields of a form by id (checkboxes "1" or ""), as our earlier project's
  // CollectFormData, and the element's data-* attributes
  function formData(el) {
    const data = {};
    const form = el.closest("form");
    if (form) {
      for (const f of form.querySelectorAll("input[id], select[id], textarea[id]")) {
        data[f.id] = f.type === "checkbox" ? (f.checked ? "1" : "") : f.value;
      }
      // Checkboxes with a name and no id (e.g. name="right"): the checked
      // values as a list
      for (const f of form.querySelectorAll("input[type=checkbox][name]:not([id])")) {
        (data[f.name] ||= []);
        if (f.checked) data[f.name].push(f.value);
      }
    }
    for (const [k, v] of Object.entries(el.dataset)) if (k !== "action") data[k] = v;
    return data;
  }

  // The left menu on a phone, its button moving along with it
  function openSidebar() {
    const m = document.getElementById("left-menu-div"), b = document.getElementById("left-menu-btn");
    if (m) m.classList.add("left-menu-show");
    if (b) b.classList.add("left-menu-button-move");
  }
  function closeSidebar() {
    const m = document.getElementById("left-menu-div"), b = document.getElementById("left-menu-btn");
    if (m) m.classList.remove("left-menu-show");
    if (b) b.classList.remove("left-menu-button-move");
  }
  function toggleSidebar() {
    const m = document.getElementById("left-menu-div");
    if (m && m.classList.contains("left-menu-show")) closeSidebar(); else openSidebar();
  }

  // Light or dark, remembered by the browser
  function toggleTheme() {
    const root = document.documentElement;
    const dark = root.classList.toggle("dark");
    try { localStorage.setItem("theme", dark ? "dark" : "light"); } catch (e) {}
  }
  try { if (localStorage.getItem("theme") === "dark") document.documentElement.classList.add("dark"); } catch (e) {}

  // The header on a narrow screen (our earlier project's checkHeaderLayout): when
  // the top menu or the search box drops under the title, they hide
  // behind a menu button; the menus and the page start under the header
  function updateHeaderHeight() {
    const header = document.querySelector("header");
    if (!header) return;
    const px = header.offsetHeight + "px";
    for (const id of ["top-menu-btn", "left-menu-btn", "left-menu-div"]) {
      const el = document.getElementById(id);
      if (el) el.style.top = px;
    }
    const main = document.querySelector("main");
    if (main) main.style.paddingTop = px;
  }
  function checkHeaderLayout() {
    const title = document.querySelector(".site-title"), btn = document.getElementById("top-menu-btn"), header = document.querySelector("header");
    if (!title || !btn || !header) return;
    const bottom = title.offsetTop + title.offsetHeight;
    const top = document.getElementById("top-menu"), search = document.getElementById("search");
    const topDropped = top && top.offsetTop >= bottom;
    const searchDropped = search && search.offsetTop >= bottom;
    const dropped = topDropped || searchDropped;
    if (top) top.style.marginTop = topDropped ? "1.456rem" : "";
    if (search) {
      search.style.marginTop = searchDropped ? "1.456rem" : "";
      search.style.marginBottom = dropped ? "0.9rem" : "";
    }
    if (dropped) btn.style.display = "block";
    else { btn.style.display = "none"; header.classList.remove("auto-height"); }
    updateHeaderHeight();
  }
  function setupHeaderWatch() {
    checkHeaderLayout();
    const top = document.getElementById("top-menu");
    if (top) new MutationObserver(checkHeaderLayout).observe(top, { childList: true, subtree: true });
  }
  window.addEventListener("resize", checkHeaderLayout);
  function toggleMobileMenu() {
    const header = document.querySelector("header");
    if (header) header.classList.toggle("auto-height");
    updateHeaderHeight();
  }

  document.addEventListener("click", e => {
    const t = e.target;
    // A message's close button
    const close = t.closest(".button-close");
    if (close) { const a = close.closest(".alert"); if (a) a.remove(); return; }
    // All, None, Reverse for the checkboxes of a table (role rights)
    const pick = t.closest(".select-all, .select-none, .select-reverse");
    if (pick) {
      for (const c of pick.closest("table").querySelectorAll("input[type=checkbox]"))
        c.checked = pick.classList.contains("select-all") ? true : pick.classList.contains("select-none") ? false : !c.checked;
      return;
    }
    // A sub-menu's +/- button
    const sub = t.closest(".sub-menu-button");
    if (sub) {
      e.preventDefault();
      const ul = sub.closest("li.sub-menu").querySelector("ul");
      ul.classList.toggle("sub-menu-show");
      sub.classList.toggle("fa-plus"); sub.classList.toggle("fa-minus");
      return;
    }
    // The menu on a phone closes on a click elsewhere
    const menu = document.getElementById("left-menu-div");
    if (menu && menu.classList.contains("left-menu-show") && !t.closest("#left-menu-div") && !t.closest("#left-menu-btn")) closeSidebar();
    // The top menu on a phone closes on a click elsewhere
    const header = document.querySelector("header");
    if (header && header.classList.contains("auto-height") && !t.closest("header")) { header.classList.remove("auto-height"); updateHeaderHeight(); }
    const btn = t.closest("[data-action]");
    if (!btn) return;
    e.preventDefault();
    if (btn.dataset.action === "toggleSidebar") { toggleSidebar(); return; }
    if (btn.dataset.action === "toggleMobileMenu") { toggleMobileMenu(); return; }
    if (btn.dataset.action === "toggleTheme") { toggleTheme(); return; }
    if (btn.dataset.wait) { waitFor(btn); return; }
    call(x.tg_action, btn.dataset.action, JSON.stringify(formData(btn)));
  });

  // A button whose call takes a while (data-wait: signing in): its form
  // is disabled and the button gets a spinning wheel until the panel
  // draws the page again with the answer
  function waitFor(btn) {
    const data = JSON.stringify(formData(btn));
    const form = btn.closest("form") || btn;
    for (const f of form.querySelectorAll("input, select, textarea, button")) f.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ' + btn.innerHTML;
    call(x.tg_action, btn.dataset.action, data);
  }

  // A list's filter changed (data-change on a select): its action, with
  // the fields of its form
  document.addEventListener("change", e => {
    const el = e.target.closest && e.target.closest("[data-change]");
    if (el) call(x.tg_action, el.dataset.change, JSON.stringify(formData(el)));
  });

  // Enter in a field presses its form's main button
  document.addEventListener("keydown", e => {
    if (e.key !== "Enter" || e.target.tagName === "TEXTAREA") return;
    const form = e.target.closest && e.target.closest("form");
    if (!form) return;
    const main = form.querySelector("[data-action].button-primary");
    if (!main) return;
    e.preventDefault();
    main.click();
  });

  x.tg_start();
  // A watched session is fetched four times a second
  setInterval(() => x.tg_tick(), 250);
  // ?test: the browser test (test.js, zig build web-test)
  if (new URLSearchParams(location.search).has("test")) {
    const t = document.createElement("script");
    t.src = "/spa/test.js";
    document.body.appendChild(t);
  }
})();
