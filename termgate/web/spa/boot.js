// The page around termgate's panel (src/spa, WASM). Nothing of the panel
// is here: this loads the WASM, makes its calls to the server, and passes
// it the page's events: the hash, and clicks on [data-action] with the
// fields of their form (as our earlier project's event delegation). Only what is
// plain page behavior (closing a message, opening a sub-menu, the menu on
// a phone) is done here directly.
"use strict";
(async () => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const zjs = new ZigJS();
  let x = null;
  let answer = new Uint8Array(0);

  const env = {
    // POST /api/<path>, JSON. The panel waits for the answer (a
    // synchronous request); the session cookie goes along by itself.
    tg_post(pathPtr, pathLen, bodyPtr, bodyLen) {
      const req = new XMLHttpRequest();
      try {
        req.open("POST", "/api/" + zjs.loadString(pathPtr, pathLen), false);
        req.setRequestHeader("x-termgate", "spa");
        req.setRequestHeader("content-type", "application/json");
        req.send(zjs.loadString(bodyPtr, bodyLen));
      } catch (e) { answer = new Uint8Array(0); return 0; }
      answer = enc.encode(req.responseText);
      return req.status;
    },
    tg_answer_len() { return answer.length; },
    tg_answer_read(out) { new Uint8Array(zjs.memory.buffer, out, answer.length).set(answer); },
    tg_log(ptr, len) { console.log(zjs.loadString(ptr, len)); },
  };

  // Clipboard, for the panel's Copy buttons
  window.tg = {
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
    }
    for (const [k, v] of Object.entries(el.dataset)) if (k !== "action") data[k] = v;
    return data;
  }

  function closeSidebar() {
    const m = document.getElementById("left-menu-div");
    if (m) m.classList.remove("left-menu-show");
  }

  document.addEventListener("click", e => {
    const t = e.target;
    // A message's close button
    const close = t.closest(".button-close");
    if (close) { const a = close.closest(".alert"); if (a) a.remove(); return; }
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
    const btn = t.closest("[data-action]");
    if (!btn) return;
    e.preventDefault();
    if (btn.dataset.action === "toggleSidebar") { menu.classList.toggle("left-menu-show"); return; }
    call(x.tg_action, btn.dataset.action, JSON.stringify(formData(btn)));
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
})();
