// What the panel's WASM (src/web/main.zig, src/web/rpc.zig) calls in the
// page; linked in by emcc (--js-library). Each passes on to the page's
// own code in web/loader.js.
addToLibrary({
  // POST /api/<name> with a JSON body; the answer is kept for the two below
  tg_call__deps: ['$UTF8ToString'],
  tg_call: (name, nameLen, body, bodyLen) => window.tgPage.call(UTF8ToString(name, nameLen), HEAPU8.slice(body, body + bodyLen)),
  tg_call_len: () => window.tgPage.answer.length,
  tg_call_read: (out) => HEAPU8.set(window.tgPage.answer, out),
  tg_keyboard: (show) => window.tgPage.keyboard(show),
  tg_copy__deps: ['$UTF8ToString'],
  tg_copy: (p, len) => window.tgPage.copy(UTF8ToString(p, len)),
  tg_can_paste: () => window.tgPage.canPaste(),
  tg_paste: () => window.tgPage.paste(),
  tg_theme: (dark) => window.tgPage.theme(dark),
  tg_test_mode: () => window.tgPage.test ? 1 : 0,
});
