const $ = (sel, root = document) => root.querySelector(sel);

const cards = new Map(); // id -> { el, refs, pc }

// ---------------------------------------------------------------- utilities

function toast(message, bad = false) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.toggle('bad', bad);
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.hidden = true), 2600);
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 401) {
    location.href = '/login';
    throw new Error('unauthorized');
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail || detail;
    } catch {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

const fmtUptime = (s) => {
  if (!s) return '—';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
};

const fmtBytes = (n) => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
};

// ---------------------------------------------------------------- webRTC

async function play(card, camera) {
  if (card.pc) return;
  const video = card.refs.video;
  const poster = card.refs.poster;

  // Only a live path has a stream behind it. Asking MediaMTX for WHEP on a
  // waiting/publishing camera just returns 404, so say why instead.
  const state = camera.status?.state || 'idle';
  if (state !== 'live') {
    const why = camera.status?.detail || `camera is ${state}`;
    poster.querySelector('.hint').textContent = why;
    return;
  }

  poster.querySelector('.hint').textContent = 'connecting…';

  if (!window.RTCPeerConnection) {
    poster.querySelector('.hint').textContent = 'Open the portal in a WebRTC-capable browser';
    return;
  }
  const pc = new RTCPeerConnection({ iceServers: [] });
  card.pc = pc;
  pc.addTransceiver('video', { direction: 'recvonly' });

  const stream = new MediaStream();
  video.srcObject = stream;
  pc.ontrack = (event) => {
    stream.addTrack(event.track);
    poster.hidden = true;
    video.hidden = false;
    video.play().catch(() => {});
  };
  pc.onconnectionstatechange = () => {
    if (['failed', 'disconnected', 'closed'].includes(pc.connectionState)) {
      teardown(card);
    }
  };

  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    // Send the LAN candidates with the offer. The player uses non-trickle ICE.
    if (pc.iceGatheringState !== 'complete') {
      await new Promise((resolve) => {
        function finish() {
          clearTimeout(timer);
          pc.removeEventListener('icegatheringstatechange', check);
          resolve();
        }
        function check() {
          if (pc.iceGatheringState === 'complete') finish();
        }
        const timer = setTimeout(finish, 3000);
        pc.addEventListener('icegatheringstatechange', check);
        check();
      });
    }
    if (pc !== card.pc) return;
    const endpoint = `${camera.webrtc_url}/whep`;
    const rtsp = new URL(camera.rtsp_url);
    const headers = { 'Content-Type': 'application/sdp' };
    if (rtsp.username) {
      const credentials = decodeURIComponent(rtsp.username) + ':' + decodeURIComponent(rtsp.password);
      headers.Authorization = 'Basic ' + btoa(String.fromCharCode(...new TextEncoder().encode(credentials)));
    }
    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: pc.localDescription.sdp,
    });
    if (!res.ok) throw new Error(`WHEP ${res.status}`);
    const answer = await res.text();
    if (res.headers.has('Location')) {
      card.sessionUrl = new URL(res.headers.get('Location'), endpoint).href;
      card.sessionHeaders = headers;
    }
    await pc.setRemoteDescription({ type: 'answer', sdp: answer });
  } catch (err) {
    toast(`Could not open ${camera.name}: ${err.message}`, true);
    teardown(card);
    poster.querySelector('.hint').textContent = 'stream unavailable — tap to retry';
  }
}

function teardown(card) {
  if (card.pc) {
    try {
      card.pc.onconnectionstatechange = null;
      card.pc.close();
    } catch {}
    card.pc = null;
  }
  if (card.sessionUrl) {
    fetch(card.sessionUrl, { method: 'DELETE', headers: card.sessionHeaders }).catch(() => {});
    card.sessionUrl = null;
  }
  if (card.refs) {
    card.refs.video.hidden = true;
    card.refs.video.srcObject = null;
    card.refs.poster.hidden = false;
    card.refs.poster.querySelector('.hint').textContent = 'tap to play';
  }
}

// ---------------------------------------------------------------- rendering

function buildCard(camera) {
  const el = document.createElement('article');
  el.className = 'card';
  el.id = `camera-${camera.id}`;
  el.innerHTML = `
    <div class="stage">
      <video autoplay muted playsinline hidden></video>
      <button class="poster" type="button">
        <span class="play">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
        </span>
        <span class="hint">tap to play</span>
      </button>
      <span class="pill"><span class="dot"></span><span class="label">idle</span></span>
    </div>
    <div class="body">
      <div class="title-row"><h3></h3><span class="dsn"></span></div>
      <div class="meta">
        <span>codec <b class="m-codec">—</b></span>
        <span>uptime <b class="m-uptime">—</b></span>
        <span>viewers <b class="m-readers">0</b></span>
        <span>data <b class="m-bytes">0 B</b></span>
      </div>
      <p class="detail"></p>
    </div>
    <form class="lan-form body" hidden>
      <label>Set the camera's LAN IP <input name="lan_ip" placeholder="192.0.2.10" required /></label>
      <button class="iconbtn" type="submit">Save IP</button>
    </form>
    ${['rtsp', 'hls', 'webrtc'].map((kind) => `
      <div class="urlrow">
        <span>${kind === 'webrtc' ? 'WebRTC' : kind.toUpperCase()}</span>
        <code class="${kind}"></code>
        <button class="iconbtn" type="button" data-copy="${kind}" aria-label="Copy ${kind} URL">Copy</button>
      </div>`).join('')}
    <div class="urlrow">
      <button class="iconbtn edit" type="button">Edit</button>
      <button class="iconbtn restart" type="button">Restart</button>
    </div>`;

  const refs = {
    video: $('video', el),
    poster: $('.poster', el),
    pill: $('.pill', el),
    pillLabel: $('.pill .label', el),
    pillDot: $('.pill .dot', el),
    lanForm: $('.lan-form', el),
    title: $('.title-row h3', el),
    dsn: $('.dsn', el),
    codec: $('.m-codec', el),
    uptime: $('.m-uptime', el),
    readers: $('.m-readers', el),
    bytes: $('.m-bytes', el),
    detail: $('.detail', el),
    rtsp: $('.rtsp', el),
    hls: $('.hls', el),
    webrtc: $('.webrtc', el),
  };

  const card = { el, refs, camera, pc: null, sessionUrl: null };

  refs.poster.addEventListener('click', () => play(card, card.camera));
  refs.pill.addEventListener('click', () => play(card, card.camera));
  refs.lanForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await patchCamera(camera.id, { lan_ip: refs.lanForm.elements.lan_ip.value.trim() });
      toast('LAN IP saved');
    } catch (err) {
      toast(err.message, true);
    }
  });
  for (const button of el.querySelectorAll('[data-copy]')) {
    button.addEventListener('click', async () => {
      const kind = button.dataset.copy;
      try {
        const url = card.camera[`${kind}_url`];
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(url);
        } else {
          // The Clipboard API requires HTTPS. Select the URL on an HTTP LAN portal.
          const range = document.createRange();
          range.selectNodeContents(refs[kind]);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          if (!document.execCommand('copy')) throw new Error('URL selected. Use Copy in your browser.');
        }
        toast('URL copied');
      } catch (err) {
        toast(err.message, true);
      }
    });
  }
  $('.edit', el).addEventListener('click', () => openEditor(card.camera));
  $('.restart', el).addEventListener('click', async () => {
    teardown(card);
    try {
      await api(`/api/cameras/${card.camera.id}/restart`, { method: 'POST' });
      toast('Publisher restarted');
      refresh();
    } catch (err) {
      toast(err.message, true);
    }
  });

  return card;
}

function pillFor(status) {
  const state = status.state || 'idle';
  const cls = {
    live: 'pill-live',
    starting: 'pill-retry',
    retrying: 'pill-retry',
    error: 'pill-error',
    stopped: 'pill-idle',
    disabled: 'pill-idle',
  }[state] || 'pill-idle';
  return { cls, label: state };
}

function updateCard(card, camera, status) {
  card.camera = camera;
  const { refs } = card;
  refs.title.textContent = camera.name;
  refs.dsn.textContent = camera.dsn;
  refs.lanForm.hidden = Boolean(camera.lan_ip);
  refs.hls.textContent = camera.hls_url;
  refs.webrtc.textContent = camera.webrtc_url;
  refs.rtsp.textContent = camera.rtsp_url;

  const pill = pillFor(status);
  refs.pill.className = `pill ${pill.cls}`;
  refs.pillLabel.textContent = pill.label;
  refs.pillDot.className = `dot ${status.ready ? 'dot-ok' : pill.cls === 'pill-error' ? 'dot-bad' : ''}`;

  refs.codec.textContent = status.codec || '—';
  refs.uptime.textContent = fmtUptime(status.uptime);
  refs.readers.textContent = String(status.readers || 0);
  refs.bytes.textContent = fmtBytes(status.bytes_received);

  const detail = status.detail || (camera.enabled ? '' : 'not published');
  refs.detail.textContent = detail;
  refs.detail.classList.toggle('err', status.state === 'error');

  // Keep the poster honest before anyone taps it.
  if (!card.pc) {
    const hint = refs.poster.querySelector('.hint');
    if (status.state === 'live') {
      hint.textContent = 'tap to play';
    } else if (status.state === 'disabled') {
      hint.textContent = 'not published';
    } else if (status.state === 'error') {
      hint.textContent = 'stream unavailable';
    } else {
      hint.textContent = 'starting…';
    }
    refs.poster.dataset.state = status.state;
  }

  card.el.dataset.state = status.state;
}

function render(state) {
  const grid = $('#grid');
  const seen = new Set();

  for (const camera of state.cameras) {
    seen.add(camera.id);
    let card = cards.get(camera.id);
    if (!card) {
      card = buildCard(camera);
      cards.set(camera.id, card);
      grid.appendChild(card.el);
    }
    updateCard(card, camera, camera.status || {});
  }

  for (const [id, card] of cards) {
    if (!seen.has(id)) {
      teardown(card);
      card.el.remove();
      cards.delete(id);
    }
  }

  $('#empty').hidden = state.cameras.length > 0;

  const media = $('#media-status');
  const healthy = state.media.healthy;
  media.innerHTML = `<span class="dot ${healthy ? 'dot-ok' : 'dot-bad'}"></span><span class="text">${
    healthy ? 'RTSP live' : 'RTSP offline'
  }</span>`;

  $('#account').textContent = state.account?.email || '';
  $('#sync-error').textContent = state.sync_error || '';
  $('#sync-error').hidden = !state.sync_error;
}

async function refresh() {
  try {
    render(await api('/api/state'));
  } catch (err) {
    if (err.message !== 'unauthorized') console.warn(err);
  }
}

// ---------------------------------------------------------------- editor

const editor = $('#editor');

function openEditor(camera) {
  $('#f-id').value = camera.id;
  $('#f-name').value = camera.name;
  $('#f-lan-ip').value = camera.lan_ip || '';
  $('#f-lan-port').value = camera.lan_port ?? '';
  $('#f-enabled').checked = camera.enabled;
  editor.showModal();
}

async function patchCamera(id, changes) {
  render(await api(`/api/cameras/${id}`, { method: 'PATCH', body: JSON.stringify(changes) }));
}

$('#editor-cancel').addEventListener('click', () => editor.close());
$('#editor-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await patchCamera($('#f-id').value, {
      name: $('#f-name').value.trim(),
      enabled: $('#f-enabled').checked,
      lan_ip: $('#f-lan-ip').value.trim() || null,
      lan_port: $('#f-lan-port').value ? Number($('#f-lan-port').value) : null,
    });
    editor.close();
    toast('Saved');
  } catch (err) {
    toast(err.message, true);
  }
});

$('#delete').addEventListener('click', async () => {
  if (!confirm('Delete this camera from the portal? Sync can import it again.')) return;
  try {
    await api(`/api/cameras/${$('#f-id').value}`, { method: 'DELETE' });
    editor.close();
    await refresh();
  } catch (err) {
    toast(err.message, true);
  }
});

$('#unlink').addEventListener('click', async () => {
  if (!confirm('Unlink the account and remove its cameras and saved LAN settings?')) return;
  try {
    await api('/api/account/unlink', { method: 'POST' });
    location.href = '/login';
  } catch (err) {
    toast(err.message, true);
  }
});

$('#btn-sync').addEventListener('click', async () => {
  const btn = $('#btn-sync');
  btn.disabled = true;
  try {
    const { imported } = await api('/api/sync', { method: 'POST' });
    toast(`Synced ${imported} device${imported === 1 ? '' : 's'}`);
    refresh();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

// ---------------------------------------------------------------- boot

refresh();
setInterval(refresh, 4000);

// Release every WHEP session when the page goes away, so the server does not
// keep counting phantom viewers.
window.addEventListener('pagehide', () => {
  for (const card of cards.values()) teardown(card);
});
