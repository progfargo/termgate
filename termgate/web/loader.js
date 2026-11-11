// The page around termgate's panel. The panel is WASM (src/web/main.zig,
// built with Emscripten into termgate.js and termgate.wasm); SDL3 inside it
// draws on the canvas and takes the pointer and the keyboard. What SDL does
// not do in a browser is here, called through web/library.js: the panel's
// calls to the server, a phone's keyboard, the clipboard, the remembered
// theme, and the self-test.
window.addEventListener('unhandledrejection', e => console.log('termgate: ' + (e.reason && e.reason.stack || e.reason)));
(() => {
  const canvas = document.getElementById('canvas');
  const field = document.getElementById('k'); // see index.html
  const enc = new TextEncoder(), dec = new TextDecoder();
  const q = new URLSearchParams(location.search);
  const test = q.has('test');
  // The panel's exported functions by their names (x.tg_frame, ...)
  const x = new Proxy({}, { get: (_, name) => Module['_' + name] });
  const bytes = (p, n) => Module.HEAPU8.subarray(p, p + n);

  const page = window.tgPage = {
    test,
    answer: new Uint8Array(0),
    // The panel's calls to termgate: POST /api/<name>, JSON. The call waits
    // for the answer (the screens read data as they draw), so it is a
    // synchronous request. The session cookie goes along by itself.
    call(name, body) {
      const req = new XMLHttpRequest();
      try {
        req.open('POST', '/api/' + name, false);
        req.setRequestHeader('x-termgate', '1');
        req.setRequestHeader('content-type', 'application/json');
        req.send(body);
      } catch (e) { page.answer = new Uint8Array(0); return 0; }
      page.answer = enc.encode(req.responseText);
      return req.status;
    },
    // A text field of the panel has the focus (or lost it). On a phone the
    // page's hidden field takes it, which makes the phone show its
    // keyboard; elsewhere the canvas keeps it and SDL reads the keys.
    // Called inside the tap's own event, as phones require.
    keyboard(show) {
      if (show && touch) { field.value = ' '; field.focus({ preventScroll: true }); }
      else if (document.activeElement === field) { field.blur(); canvas.focus({ preventScroll: true }); }
    },
    copy(text) {
      if (test) { window.tgCopied = text; return; }
      if (navigator.clipboard) { navigator.clipboard.writeText(text).catch(() => {}); return; }
      // Not a secure page (plain http on a name of the local network): the
      // old way, which works inside the key or tap that asked for the copy
      const t = document.createElement('textarea');
      t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
      document.body.appendChild(t); t.select();
      try { document.execCommand('copy'); } catch (e) {}
      t.remove();
      canvas.focus({ preventScroll: true });
    },
    canPaste() { return navigator.clipboard && navigator.clipboard.readText ? 1 : 0; },
    paste() { navigator.clipboard.readText().then(t => { if (t) type(t); }).catch(() => {}); },
    theme(dark) {
      try { localStorage.setItem('tg_dark', dark ? '1' : '0'); } catch (e) {}
      pageColor(dark);
    },
  };

  // Whether the last tap was a finger (then a text field opens the phone's
  // keyboard)
  let touch = false;
  canvas.addEventListener('pointerdown', e => { touch = e.pointerType === 'touch'; }, { capture: true });

  // The page around and behind the canvas, and the browser's own bars
  function pageColor(dark) {
    document.documentElement.style.background = document.body.style.background = dark ? '#15171A' : '#F2F4F7';
    const m = document.querySelector('meta[name="theme-color"]');
    if (m) m.content = dark ? '#282B30' : '#FFFFFF';
  }

  // The panel covers the visible part of the window: on a phone the
  // keyboard takes its share. SDL sizes the canvas (tg_resize).
  // (&width=N in the self-test: a phone's width in a wider test browser)
  let started = false;
  function fit() {
    const vv = window.visualViewport;
    const forced = test && +q.get('width');
    const w = Math.round(forced || (vv ? vv.width : window.innerWidth)), h = Math.round(vv ? vv.height : window.innerHeight);
    canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
    if (started) x.tg_resize(w, h);
  }
  fit();
  if (window.visualViewport) window.visualViewport.addEventListener('resize', fit);
  window.addEventListener('resize', fit);

  // Text into the panel's focused field (a phone's keyboard, the clipboard)
  function type(text) {
    const cap = x.tg_text_cap();
    let b = enc.encode(text);
    while (b.length > 0) {
      // Not in the middle of a character
      let n = Math.min(b.length, cap);
      while (n < b.length && n > 0 && (b[n] & 0xC0) === 0x80) n--;
      bytes(x.tg_text_buf(), n).set(b.subarray(0, n));
      x.tg_text(n);
      b = b.subarray(n);
    }
  }
  // The hidden field always holds one space: what is added is typed, and a
  // field that got shorter means backspace
  field.addEventListener('input', e => {
    if (e.inputType === 'insertLineBreak') x.tg_key(3);
    else if (field.value.length < 1) x.tg_key(1);
    else if (field.value.length > 1) type(field.value.slice(1));
    field.value = ' ';
  });
  // A keyboard attached to a phone or tablet: its control keys
  const keys = { Backspace: 1, Delete: 2, Enter: 3, ArrowLeft: 4, ArrowRight: 5, ArrowUp: 6, ArrowDown: 7, Home: 8, End: 9, Escape: 10 };
  field.addEventListener('keydown', e => {
    if (e.key === 'Tab') { e.preventDefault(); x.tg_key(e.shiftKey ? 12 : 11); return; }
    if (e.key !== 'Backspace' && keys[e.key]) { e.preventDefault(); x.tg_key(keys[e.key]); }
  });

  const frame = t => x.tg_frame(t >>> 0);

  window.Module = {
    canvas,
    // main runs once the theme is set and, in the self-test, after signing in
    noInitialRun: true,
    print: t => console.log(t),
    printErr: t => console.log(t),
    async onRuntimeInitialized() {
      // The theme chosen earlier in this browser (light unless dark was
      // chosen); &dark in a test URL chooses it for that run
      let dark = false;
      try { dark = localStorage.getItem('tg_dark') === '1'; } catch (e) {}
      if (test) dark = q.has('dark');
      x.tg_set_dark(dark ? 1 : 0);
      pageColor(dark);
      if (test) await testSignIn();
      let rc;
      try { rc = Module.callMain([]); } catch (e) { console.log('termgate: start failed: ' + (e.stack || e)); document.title = 'start failed'; return; }
      if (rc) { document.title = 'start failed: ' + rc; return; }
      started = true; fit();
      canvas.focus({ preventScroll: true });
      if (test) runTest();
    },
  };

  // --- self-test (index.html?test&name=...&password=..., run headless; see
  // CLAUDE.md). With name and password it signs in first (a fresh user:
  // the second step is set up with the secret the server gives), so the
  // panel starts signed in; without, it checks the sign-in screen.
  async function testSignIn() {
    // &setup: the name and password are typed on the screen instead
    if (!q.has('name') || q.has('setup')) return;
    const post = (name, body) => fetch('/api/' + name, { method: 'POST', headers: { 'x-termgate': '1' }, body: JSON.stringify(body) }).then(r => r.json());
    const l = await post('login', { name: q.get('name'), password: q.get('password') });
    if (!l.secret) return;
    // TOTP (RFC 6238) for the secret
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    for (const c of l.secret.replace(/ /g, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
    const key = new Uint8Array(bits.length >> 3).map((_, i) => parseInt(bits.substr(i * 8, 8), 2));
    const msg = new Uint8Array(8);
    new DataView(msg.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 30000)));
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
    const o = mac[19] & 15;
    const code = ((new DataView(mac.buffer).getUint32(o) & 0x7fffffff) % 1000000).toString().padStart(6, '0');
    await post('login2', { code });
  }

  function runTest() {
    let t = 0;
    const step = n => { for (let i = 0; i < n; i++) { t += 33; frame(t); } };
    step(10);
    if (q.has('scenario')) { document.title = scenario(); return; }
    if (q.has('setup')) {
      // &setup&name=..&password=..: a user's first sign-in, typed on the
      // screen: the setup key is shown, as a QR code too
      let ok = tapAt(2); type(q.get('name'));
      ok = ok && tapAt(3); type(q.get('password'));
      ok = ok && tapAt(1); step(20);
      ok = ok && x.tg_test_tap(27) === 1 && x.tg_test_tap(4) === 1;
      document.title = ok ? 'test: ok (setup screen)' : 'test: FAILED (setup screen)';
      return;
    }
    if (q.has('name') || x.tg_test_signed_in() === 1) {
      // Signed in before the panel started (or the browser still had its
      // session): the Nodes page is shown.
      // &page=N goes to another page, &tap=a,b taps things there (see
      // tg_test_tap), for screenshots
      step(20);
      let ok = x.tg_test_signed_in() === 1, taps = '';
      if (q.has('page')) { x.tg_test_goto(+q.get('page')); step(10); }
      for (const t of (q.get('tap') || '').split(',').filter(Boolean)) {
        const hit = tapAt(+t); taps += (hit ? ' tap ' : ' MISSING ') + t; ok = ok && hit; step(20);
      }
      step(+(q.get('frames') || 0));
      document.title = ok ? 'test: ok (signed in' + (x.tg_test_has_node() ? ', node listed' : '') + (x.tg_test_dark() ? ', dark' : '') + ')' + taps : 'test: FAILED' + taps;
      return;
    }
    // Not signed in: a wrong password is typed and refused
    let ok = x.tg_test_signed_in() === 0;
    // The settings are not there before signing in
    ok = ok && !tapAt(7);
    // Text boxes: select all, type over the selection, cut it with the bar
    const value = what => dec.decode(bytes(x.tg_text_buf(), x.tg_test_value(what)).slice());
    ok = ok && tapAt(2); type('hello'); step(4);
    ok = ok && x.tg_edit(1) === 1; step(4);
    type('ghost'); step(4);
    ok = ok && value(2) === 'ghost';
    ok = ok && x.tg_edit(1) === 1; step(4);
    ok = ok && tapAt(46); step(8);
    ok = ok && value(2) === '' && window.tgCopied === 'ghost';
    type('ghost'); step(4);
    ok = ok && tapAt(3); type('wrong-password');
    ok = ok && tapAt(1);
    step(10);
    document.title = ok && x.tg_test_signed_in() === 0 ? 'test: ok (sign-in screen)' : 'test: FAILED (sign-in screen)';

    // &scenario: what an admin does with forms, start to end (signed in):
    // a node, an invitation, roles, a user with a role, a setting, signing out. The server's
    // database is checked afterwards (CLAUDE.md).
    function scenario() {
      const label = what => dec.decode(bytes(x.tg_text_buf(), x.tg_test_text(what)).slice());
      const fill = (what, text) => { if (!tapAt(what)) return false; type(text); step(4); return true; };
      const must = (ok, what) => { if (!ok) throw new Error(what); };
      try {
        must(x.tg_test_signed_in() === 1, 'not signed in');
        // A node: its key is shown with the command for the device
        x.tg_test_goto(0); step(10);
        must(tapAt(11), 'New node'); step(4);
        // Typed without tapping the field: a form's first field has the focus
        type('web_gw01'); step(4); must(tapAt(13), 'Create node'); step(10);
        must(label(30).startsWith('tgnode --registration tg1-'), 'node key shown: ' + label(30).slice(0, 40));
        must(tapAt(14), 'Done');
        // An invitation
        x.tg_test_goto(1); step(10);
        must(tapAt(15), 'Invite'); must(fill(16, 'Veli'), 'person name'); must(fill(17, 'web_*'), 'nodes'); must(fill(19, '2'), 'sessions');
        must(tapAt(20), 'Create invitation'); step(10);
        must(label(30).startsWith('tgterm --invite tg1-'), 'invitation shown: ' + label(30).slice(0, 40) + ' / ' + label(32));
        must(tapAt(14), 'Done');
        // Roles: one with two rights; one made and deleted again (asks first)
        x.tg_test_goto(5); step(10);
        must(tapAt(28), 'New role'); step(4); type('operator'); step(4);
        must(tapAt(41), 'right node:browse'); must(tapAt(42), 'right session:watch');
        must(tapAt(33), 'Save role'); step(10);
        must(label(32) === 'Saved.', 'role saved: ' + label(32));
        must(tapAt(28), 'New role'); step(4); type('zz-temp'); x.tg_key(3); step(10);
        must(label(32) === 'Saved.', 'second role saved: ' + label(32));
        must(tapAt(35), 'Delete role'); step(10); must(tapAt(36), 'Yes'); step(20);
        must(label(32) === 'Deleted.', 'role deleted: ' + label(32));
        // A user: the password is shown once, then the user gets a role
        x.tg_test_goto(4); step(10);
        must(tapAt(8), 'New user'); must(fill(21, 'veli'), 'user name');
        // Enter in a field presses the form's button (Save)
        x.tg_key(3); step(10);
        must(label(30).length === 20, 'password shown: ' + label(32));
        must(tapAt(14), 'Done'); step(10);
        must(tapAt(38), 'Give role'); step(10);
        must(label(32) === 'Role given.', 'role given: ' + label(32));
        // Acting as veli (the last user in the list), then back
        x.tg_test_goto(4); step(10);
        must(tapAt(48), 'Act as veli'); step(20);
        must(x.tg_test_acting() === 1, 'acting as veli');
        must(tapAt(49), 'Back to myself'); step(20);
        must(x.tg_test_acting() === 0, 'back to myself');
        // Configuration: session length 480 -> 90 minutes
        x.tg_test_goto(6); step(20);
        must(tapAt(23), 'session length field');
        x.tg_key(9); for (let i = 0; i < 6; i++) x.tg_key(1); type('90'); step(4);
        must(tapAt(24), 'Save'); step(10);
        must(label(31) === 'Saved.', 'settings saved: ' + label(31));
        // Signing out (at the bottom of the menu)
        must(tapAt(26), 'Sign out'); step(20);
        must(x.tg_test_signed_in() === 0, 'signed out');
        return 'test: ok (scenario)';
      } catch (e) { return 'test: FAILED (' + e.message + ')'; }
    }

    function tapAt(what) {
      if (!x.tg_test_tap(what)) return false;
      x.tg_test_press(1); step(4); x.tg_test_press(0); step(4);
      return true;
    }
  }
})();
