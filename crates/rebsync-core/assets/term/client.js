// rbq operator terminal client. One xterm.js view, one resumable session.
//
// The server keeps the shell alive when the connection drops and numbers every
// output byte. This client remembers the next byte it needs and asks for it on
// reconnect, so a flaky mesh link loses nothing and repeats nothing — the
// mosh idea, over a WebSocket. Frames:
//   server → client, binary: 8-byte big-endian offset, then output bytes
//   server → client, text:   {"t":"hello","session":ID,"offset":N} | {"t":"gap","from":N} | {"t":"exit","code":N}
//   client → server, text:   {"t":"i","d":STRING} | {"t":"r","c":COLS,"r":ROWS}
(() => {
  'use strict';
  const status = document.getElementById('status');
  const term = new Terminal({ cursorBlink: true, scrollback: 10000, fontFamily: 'ui-monospace, monospace', fontSize: 14 });
  const fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById('term'));
  fit.fit();

  const stored = (() => { try { return JSON.parse(sessionStorage.getItem('rbq-term') || '{}'); } catch { return {}; } })();
  let session = new URLSearchParams(location.search).get('session') || stored.session || '';
  // A new page has an empty screen: replay recent history (as tmux would)
  // instead of starting mid-line. Reconnects within this page resume exactly.
  const REPLAY_BYTES = 64 * 1024;
  let offset = stored.session === session ? Math.max(0, (stored.offset || 0) - REPLAY_BYTES) : 0;
  let socket = null, retry = 0, pending = [], exited = false;
  const save = () => { try { sessionStorage.setItem('rbq-term', JSON.stringify({ session, offset })); } catch { /* private mode */ } };
  const show = (text, state) => { status.textContent = text; status.dataset.state = state; };
  const send = message => {
    const text = JSON.stringify(message);
    if (socket && socket.readyState === WebSocket.OPEN) socket.send(text);
    else if (message.t === 'i') pending.push(text); // typed while offline: delivered on reconnect
  };

  function connect() {
    if (exited) return;
    const url = new URL('ws', location.href);
    url.protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    url.searchParams.set('session', session || 'new');
    url.searchParams.set('offset', String(offset));
    url.searchParams.set('cols', String(term.cols));
    url.searchParams.set('rows', String(term.rows));
    show(retry ? `reconnecting (attempt ${retry})…` : 'connecting…', 'wait');
    socket = new WebSocket(url);
    socket.binaryType = 'arraybuffer';
    socket.onmessage = event => {
      if (typeof event.data === 'string') {
        const m = JSON.parse(event.data);
        if (m.t === 'hello') {
          session = m.session; offset = Math.max(offset, m.offset); retry = 0; save();
          history.replaceState(null, '', `?session=${encodeURIComponent(session)}`);
          show(`connected · ${m.identity} · session ${session.slice(0, 8)}`, 'ok');
          for (const text of pending.splice(0)) socket.send(text);
        } else if (m.t === 'gap') {
          term.write(`\r\n\x1b[33m[rbq: ${m.from - offset} bytes of output fell out of the server's buffer]\x1b[0m\r\n`);
          offset = m.from;
        } else if (m.t === 'exit') {
          exited = true;
          show(`shell exited (${m.code})`, 'off');
          try { sessionStorage.removeItem('rbq-term'); } catch { /* ignore */ }
        }
        return;
      }
      const view = new DataView(event.data);
      const start = Number(view.getBigUint64(0));
      const bytes = new Uint8Array(event.data, 8);
      // Drop anything already shown; a resumed stream may overlap.
      const skip = Math.max(0, offset - start);
      if (skip < bytes.length) {
        term.write(bytes.subarray(skip));
        offset = start + bytes.length;
        save();
      }
    };
    socket.onclose = event => {
      if (exited) return;
      if (event.code === 4401 || event.code === 4403) { show(event.reason || 'not authorised', 'off'); return; }
      retry += 1;
      const delay = Math.min(10000, 250 * 2 ** Math.min(retry, 6)) * (0.8 + Math.random() * 0.4);
      show(`offline · retrying in ${Math.round(delay / 1000)} s`, 'wait');
      setTimeout(connect, delay);
    };
  }

  term.onData(data => send({ t: 'i', d: data }));
  term.onResize(({ cols, rows }) => send({ t: 'r', c: cols, r: rows }));
  addEventListener('resize', () => fit.fit());
  // Reconnect at once when the network or the tab comes back.
  addEventListener('online', () => { if (socket && socket.readyState !== WebSocket.OPEN) { retry = 0; connect(); } });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && socket && socket.readyState === WebSocket.CLOSED) { retry = 0; connect(); }
  });
  connect();
  term.focus();
})();
