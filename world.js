/* AgentWorld web client — Nostr-backed 3D world.
 * Plain script (no modules). Requires: THREE, nobleSecp, parseVRML (loaded first).
 *
 * Protocol
 *   kind 30030  room definition   tags: [["d", roomId]]        content: VRML text
 *   kind 30031  object state      tags: [["d", roomId+":"+objId]] content: JSON {on, emissive?}
 *   kind 30010  presence (parameterized replaceable, STORED) tags: [["d", roomId]]
 *                 content: JSON {name,x,y,z,yaw,pair?,picture?}
 *                 (stored, not ephemeral: relays throttle high-frequency 20010s,
 *                 which made avatars blink. 30010 is forwarded reliably and
 *                 gives joiners instant state. heartbeat every 10s.)
 *     name/picture come from the human's kind-0 Nostr profile; pair=[agent hex]
 *     is sent only when logged in (human npub + agent npub both set)
 *   kind 20111  chat (stored)  tags: [["room", roomId]]      content: JSON {name,text}
 *     (regular event so relays keep history; sub uses limit:60 for backfill + live)
 */
(function () {
'use strict';

/* ---------------- tiny utils ---------------- */
function $(id) { return document.getElementById(id); }
function hex(b) { var s = ''; for (var i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }
function unhex(s) { var a = new Uint8Array(s.length / 2); for (var i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16); return a; }
async function sha256hex(str) {
  var d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return hex(new Uint8Array(d));
}
function tag(ev, n) { for (var i = 0; i < ev.tags.length; i++) if (ev.tags[i][0] === n) return ev.tags[i][1]; return null; }

/* ---------------- identity ---------------- */
var S = nobleSecp;
var privHex = null, myPubHex = null, hasNsec = false;
/* ---------------- identity: npub-pair login ----------------
   Settings holds two fields: YOUR npub and AGENT npub(s). Both are required
   to log in. Your display name and profile picture come from your npub's
   kind-0 profile — there is no name field anymore. Without the pair you
   remain "guest": you can explore and chat, but no agent follows you.
   (No agent exists without its human; humans without agents are guests.)
   Optional third field: YOUR nsec. When set, this device signs presence and
   chat AS your npub — cryptographic proof nobody can fake. The nsec is
   stored only on this device and never transmitted; without it you get a
   throwaway local key and a merely claimed npub. */
var myName = 'guest';
var myPicture = null;      // profile picture URL from kind 0
var myHumanHex = null;     // your npub as hex, when logged in
var loggedIn = false;      // both npubs present and valid
var humanNpubStr = '';
var agentNpubStrs = [];    // raw strings as typed (npub or hex)
try { humanNpubStr = localStorage.getItem('aw_human_npub') || ''; } catch (e) {}
try {
  var _an = JSON.parse(localStorage.getItem('aw_agent_npubs') || '[]');
  if (Array.isArray(_an)) agentNpubStrs = _an.filter(function (x) { return typeof x === 'string' && x.trim(); });
} catch (e) {}
/* migrate v0.4.x: aw_pairs held agent hex keys */
try {
  if (!agentNpubStrs.length) {
    var _sp = JSON.parse(localStorage.getItem('aw_pairs') || '[]');
    if (Array.isArray(_sp)) agentNpubStrs = _sp.filter(function (x) { return /^[0-9a-f]{64}$/.test(x); });
  }
} catch (e) {}
function refreshLogin() {
  myHumanHex = npubToHex(humanNpubStr);
  pairedAgents = [];
  agentNpubStrs.forEach(function (s) {
    var h = npubToHex(s);
    if (h && pairedAgents.indexOf(h) < 0) pairedAgents.push(h);
  });
  loggedIn = !!(myHumanHex && pairedAgents.length);
  if (!loggedIn) { myName = 'guest'; myPicture = null; }
  return loggedIn;
}
/* ---------------- avatar look: skin/shirt/pants, shared via presence ---- */
var AV_DEFAULTS = { skin: '#c68642', shirt: '#4a90d9', pants: '#2c3e50' };
var avatarColors = null;
try { avatarColors = JSON.parse(localStorage.getItem('aw_avatar') || 'null'); } catch (e) {}
if (!avatarColors || typeof avatarColors !== 'object') avatarColors = null;
function cleanHex(v, fb) {
  v = String(v || '').trim().toLowerCase();
  return /^#[0-9a-f]{6}$/.test(v) ? v : fb;
}
function readAvatarInputs() {
  return {
    skin: cleanHex($('avskin').value, AV_DEFAULTS.skin),
    shirt: cleanHex($('avshirt').value, AV_DEFAULTS.shirt),
    pants: cleanHex($('avpants').value, AV_DEFAULTS.pants)
  };
}

/* companion pairing: our heartbeat carries pair=[agent hex pubkeys] when
   logged in and pairing is on. Each agent watches for its own key and stays
   only while its human is here. Nothing is hard-coded. */
var pairingOn = true;
try { pairingOn = localStorage.getItem('aw_pair_mica') !== '0'; } catch (e) {}
var pairedAgents = [];   // hex pubkeys, derived from the agent npub field(s)
refreshLogin();

/* bech32 (for npub -> hex) */
function bech32Decode(str) {
  var ALPH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var s = String(str).trim();
  var pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) return null;
  var hrp = s.slice(0, pos).toLowerCase(), data = [], i, j;
  for (i = pos + 1; i < s.length; i++) {
    var d = ALPH.indexOf(s[i].toLowerCase());
    if (d < 0) return null;
    data.push(d);
  }
  var vals = [];
  for (i = 0; i < hrp.length; i++) vals.push(hrp.charCodeAt(i) >> 5);
  vals.push(0);
  for (i = 0; i < hrp.length; i++) vals.push(hrp.charCodeAt(i) & 31);
  var chk = vals.concat(data);
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3], p = 1;
  for (i = 0; i < chk.length; i++) {
    var b = p >> 25;
    p = ((p & 0x1ffffff) << 5) ^ chk[i];
    for (j = 0; j < 5; j++) if ((b >> j) & 1) p ^= GEN[j];
  }
  if (p !== 1) return null;
  var payload = data.slice(0, -6), acc = 0, bits = 0, out = [];
  for (i = 0; i < payload.length; i++) {
    acc = (acc << 5) | payload[i]; bits += 5;
    while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); }
  }
  return { hrp: hrp, bytes: out };
}
function npubToHex(s) {
  s = String(s).trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
  if (s.toLowerCase().indexOf('npub1') === 0) {
    var d = bech32Decode(s);
    if (d && d.hrp === 'npub' && d.bytes.length === 32)
      return d.bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }
  return null;
}
/* bech32 encode (to derive your npub from an nsec) */
function bech32Encode(hrp, bytes) {
  var ALPH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  function step(p, v) {
    var b = p >> 25, j;
    p = ((p & 0x1ffffff) << 5) ^ v;
    for (j = 0; j < 5; j++) if ((b >> j) & 1) p ^= GEN[j];
    return p;
  }
  var data = [], acc = 0, bits = 0, i;
  for (i = 0; i < bytes.length; i++) {
    acc = (acc << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { bits -= 5; data.push((acc >> bits) & 31); }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31);
  var p = 1;
  for (i = 0; i < hrp.length; i++) p = step(p, hrp.charCodeAt(i) >> 5);
  p = step(p, 0);
  for (i = 0; i < hrp.length; i++) p = step(p, hrp.charCodeAt(i) & 31);
  for (i = 0; i < data.length; i++) p = step(p, data[i]);
  for (i = 0; i < 6; i++) p = step(p, 0);
  p ^= 1;
  var out = hrp + '1', j;
  for (j = 0; j < data.length; j++) out += ALPH[data[j]];
  for (j = 0; j < 6; j++) out += ALPH[(p >> (5 * (5 - j))) & 31];
  return out;
}
function nsecToHex(s) {
  var d = bech32Decode(s);
  if (d && d.hrp === 'nsec' && d.bytes.length === 32)
    return d.bytes.map(function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  return null;
}
function hexToNpub(h) {
  var bytes = [];
  for (var i = 0; i < 32; i++) bytes.push(parseInt(String(h).slice(i * 2, i * 2 + 2), 16));
  return bech32Encode('npub', bytes);
}

async function initIdentity() {
  var nsecHex = null;
  try { nsecHex = nsecToHex(localStorage.getItem('aw_nsec') || ''); } catch (e) {}
  if (nsecHex) {
    /* proven identity: this device signs everything AS your npub.
       The nsec itself never leaves this device — only signatures go out,
       and a signature can't be reversed into the key. */
    privHex = nsecHex; hasNsec = true;
  } else {
    try { privHex = localStorage.getItem('aw_privkey'); } catch (e) {}
    if (!privHex) {
      privHex = hex(S.utils.randomPrivateKey());
      try { localStorage.setItem('aw_privkey', privHex); } catch (e) {}
    }
    hasNsec = false;
  }
  myPubHex = hex(await S.schnorr.getPublicKey(unhex(privHex)));
}
async function makeEvent(kind, tags, content) {
  var created_at = Math.floor(Date.now() / 1000);
  var id = await sha256hex(JSON.stringify([0, myPubHex, created_at, kind, tags, content]));
  var sig = hex(await S.schnorr.sign(unhex(id), unhex(privHex)));
  return { id: id, pubkey: myPubHex, created_at: created_at, kind: kind, tags: tags, content: content, sig: sig };
}

/* ---------------- relays ---------------- */
var RELAYS = ['wss://nos.lol', 'wss://relay.snort.social', 'wss://relay.primal.net', 'wss://relay.damus.io'];
var sockets = [];
var roomId = 'lobby';
var subSeq = 0;
var activeSubs = [];   // {id, purpose, room, filter}
var connectedOnce = false;

function broadcast(msg) {
  for (var i = 0; i < sockets.length; i++) {
    var e = sockets[i];
    if (e.open) { try { e.ws.send(msg); } catch (_) {} }
  }
}
function publish(ev) { broadcast(JSON.stringify(['EVENT', ev])); }

function hook(entry) {
  entry.ws.onopen = function () {
    entry.open = true;
    if (!connectedOnce) { connectedOnce = true; sysLine('connected — exploring ' + roomId); }
    resub(entry);
  };
  entry.ws.onclose = function () { entry.open = false; scheduleReconnect(entry, 4000); };
  entry.ws.onerror = function () { try { entry.ws.close(); } catch (e) {} };
  entry.ws.onmessage = function (ev) { handleMsg(ev.data); };
}
function scheduleReconnect(entry, delay) {
  setTimeout(function () {
    try { entry.ws = new WebSocket(entry.url); hook(entry); }
    catch (e) { scheduleReconnect(entry, 9000); }
  }, delay);
}
function connectRelays() {
  RELAYS.forEach(function (url) {
    var entry = { url: url, ws: null, open: false };
    try { entry.ws = new WebSocket(url); hook(entry); } catch (e) {}
    sockets.push(entry);
  });
}
function resub(entry) {
  activeSubs.forEach(function (s) {
    try { entry.ws.send(JSON.stringify(['REQ', s.id, s.filter])); } catch (e) {}
  });
}
function setSubs() {
  activeSubs.forEach(function (s) { broadcast(JSON.stringify(['CLOSE', s.id])); });
  subSeq++;
  var r = roomId, q = subSeq;
  activeSubs = [
    { id: 'aw:room:' + r + ':' + q, purpose: 'room', room: r, filter: { kinds: [30030], '#d': [r] } },
    { id: 'aw:obj:' + r + ':' + q,  purpose: 'obj',  room: r, filter: { kinds: [30031] } },
    { id: 'aw:pres:' + r + ':' + q, purpose: 'pres', room: r, filter: { kinds: [30010], '#d': [r] } },
    { id: 'aw:chat:' + r + ':' + q, purpose: 'chat', room: r, filter: { kinds: [20111], '#room': [r], limit: 60 } },
    { id: 'aw:game:' + r + ':' + q, purpose: 'game', room: r, filter: { kinds: [30032, 30033, 30034], '#room': [r] } }
  ];
  activeSubs.forEach(function (s) { broadcast(JSON.stringify(['REQ', s.id, s.filter])); });
}
function handleMsg(data) {
  var m;
  try { m = JSON.parse(data); } catch (e) { return; }
  if (!m || m[0] !== 'EVENT') return;
  var sub = null;
  for (var i = 0; i < activeSubs.length; i++) if (activeSubs[i].id === m[1]) { sub = activeSubs[i]; break; }
  if (!sub || sub.room !== roomId) return;
  var ev = m[2];
  if (sub.purpose === 'room') onRoomEvent(ev);
  else if (sub.purpose === 'obj') onObjEvent(ev);
  else if (sub.purpose === 'pres') onPresence(ev);
  else if (sub.purpose === 'chat') onChat(ev);
  else if (sub.purpose === 'game') onGameEvent(ev);
  else if (sub.purpose === 'prof') onProfile(ev);
}

/* ---------------- three.js scene ---------------- */
var scene, camera, renderer, clock, raycaster, pointer;
var worldGroup = null, peerGroup = null;
var interactives = new Map();   // objId -> {meshes:[], def}
var portals = [];               // {mesh, room}
var orbMesh = null;
var objStates = new Map();      // "roomId:objId" -> state
var objStateTs = new Map();    // "roomId:objId" -> newest applied timestamp (newest writer wins)
var roomBest = null;            // newest 30030 seen for this room
var peers = new Map();          // pubkey -> {avatar,name,x,z,yaw,lastSeen}

var player = { x: 0, z: 7 }, yaw = 0, pitch = 0;
var EYE = 1.7, BOUND = 11;

function initThree() {
  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x0b0d12);
  scene.fog = new THREE.Fog(0x0b0d12, 20, 48);
  camera = new THREE.PerspectiveCamera(70, innerWidth / innerHeight, 0.1, 200);
  camera.rotation.order = 'YXZ';
  renderer = new THREE.WebGLRenderer({ antialias: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 2));
  renderer.setSize(innerWidth, innerHeight);
  renderer.domElement.style.touchAction = 'none';
  $('c').appendChild(renderer.domElement);
  clock = new THREE.Clock();
  raycaster = new THREE.Raycaster();
  pointer = new THREE.Vector2();
  peerGroup = new THREE.Group();
  scene.add(peerGroup);
  addEventListener('resize', function () {
    camera.aspect = innerWidth / innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(innerWidth, innerHeight);
  });
}

function disposeGroup(g) {
  g.traverse(function (o) {
    if (o.geometry) o.geometry.dispose();
    if (o.material) {
      var ms = Array.isArray(o.material) ? o.material : [o.material];
      ms.forEach(function (m) { if (m.map) m.map.dispose(); m.dispose(); });
    }
  });
}
function clearWorld() {
  if (worldGroup) { scene.remove(worldGroup); disposeGroup(worldGroup); }
  worldGroup = new THREE.Group();
  scene.add(worldGroup);
  interactives.clear();
  portals = [];
  orbMesh = null;
}

var applySpawn = true;   // true only when entering a room; rebuilds keep your position
function buildScene(vrmlText) {
  var parsed;
  try { parsed = parseVRML(vrmlText); }
  catch (e) { sysLine('room parse error: ' + e.message); return; }
  clearWorld();

  worldGroup.add(new THREE.AmbientLight(0xffffff, 0.5));
  worldGroup.add(new THREE.HemisphereLight(0xbdd0ff, 0x2a241c, 0.4));
  parsed.lights.forEach(function (L) {
    var c = new THREE.Color(L.color[0], L.color[1], L.color[2]);
    if (L.type === 'directional') {
      var d = new THREE.DirectionalLight(c, L.intensity);
      d.position.set(-L.direction[0] * 10, -L.direction[1] * 10, -L.direction[2] * 10);
      worldGroup.add(d);
    } else {
      var p = new THREE.PointLight(c, L.intensity, 30);
      p.position.set(L.location[0], L.location[1], L.location[2]);
      worldGroup.add(p);
    }
  });

  // subtle boundary ring at the movement limit
  var ring = new THREE.Mesh(
    new THREE.RingGeometry(BOUND - 0.15, BOUND + 0.05, 72),
    new THREE.MeshBasicMaterial({ color: 0x3a4a6a, transparent: true, opacity: 0.35, side: THREE.DoubleSide }));
  ring.rotation.x = -Math.PI / 2;
  ring.position.y = 0.03;
  worldGroup.add(ring);

  parsed.objects.forEach(function (o) {
    var g = null;
    if (o.kind === 'box') g = new THREE.BoxGeometry(o.params.size[0], o.params.size[1], o.params.size[2]);
    else if (o.kind === 'sphere') g = new THREE.SphereGeometry(o.params.radius, 28, 20);
    else if (o.kind === 'cylinder') g = new THREE.CylinderGeometry(o.params.radius, o.params.radius, o.params.height, 28);
    else if (o.kind === 'cone') g = new THREE.ConeGeometry(o.params.bottomRadius, o.params.height, 28);
    if (!g) return;
    var mesh = new THREE.Mesh(g, new THREE.MeshStandardMaterial({
      color: new THREE.Color(o.color[0], o.color[1], o.color[2]),
      emissive: new THREE.Color(o.emissive[0], o.emissive[1], o.emissive[2]),
      roughness: 0.65, metalness: 0.15,
      transparent: o.transparency > 0.001, opacity: 1 - o.transparency
    }));
    mesh.applyMatrix4(o.matrix);
    mesh.userData.def = o.def || null;
    mesh.userData.anchor = o.anchor || null;
    worldGroup.add(mesh);

    var isInteractive = !!(o.def && o.def.indexOf('OBJ_') === 0);
    if (isInteractive) {
      var id = o.def.slice(4);
      var entry = interactives.get(id);
      if (!entry) { entry = { meshes: [], def: o.def }; interactives.set(id, entry); }
      entry.meshes.push(mesh);
      var st = objStates.get(roomId + ':' + id);
      if (st) applyState(id, st);
    }
    if (o.anchor && o.anchor.indexOf('nostr:room:') === 0) {
      var target = o.anchor.slice(11);
      portals.push({ mesh: mesh, room: target });
      mesh.userData.portal = target;
      if (!isInteractive) mesh.material.emissive = new THREE.Color(0.28, 0.12, 0.5); // portals glow
    }
    if (o.def === 'OBJ_orb') { var oe = interactives.get('orb'); if (oe) orbMesh = oe.meshes[0]; }
  });

  if (parsed.viewpoints.length && applySpawn) {
    var v = parsed.viewpoints[0];
    player.x = v.position[0];
    player.z = v.position[2];
    var ax = v.orientation;
    if (Math.abs(ax[0]) < 0.2 && Math.abs(ax[2]) < 0.2 && Math.abs(Math.abs(ax[1]) - 1) < 0.2)
      yaw = ax[3] * (ax[1] >= 0 ? 1 : -1);
    else yaw = 0;
    pitch = 0;
    applySpawn = false;
  }
}

/* ---------------- room / object events ---------------- */
function onRoomEvent(ev) {
  if (ev.kind !== 30030) return;
  if (tag(ev, 'd') !== roomId) return;
  // relays replay the stored room event on every (re)subscribe — ignore
  // replays so a reconnect never rebuilds the world or moves the player
  if (roomBest && (ev.id === roomBest.id || ev.created_at < roomBest.created_at)) return;
  roomBest = { id: ev.id, created_at: ev.created_at };
  buildScene(ev.content);
  sysLine('room loaded: ' + roomId);
}
function onObjEvent(ev) {
  if (ev.kind !== 30031) return;
  var d = tag(ev, 'd');
  if (!d) return;
  var st = null;
  try { st = JSON.parse(ev.content); } catch (e) { return; }
  // newest writer wins across authors: a late duplicate from a slow relay
  // must not clobber a newer state (this is what made the orb look stuck).
  var ts = (st && st.at) || ev.created_at || 0;
  if (ts <= (objStateTs.get(d) || 0)) return;
  objStateTs.set(d, ts);
  objStates.set(d, st);
  var prefix = roomId + ':';
  if (d.indexOf(prefix) === 0) applyState(d.slice(prefix.length), st);
}
function applyState(objId, state) {
  var it = interactives.get(objId);
  if (!it) return;
  it.meshes.forEach(function (mesh) {
    var m = mesh.material;
    if (state && state.emissive && state.emissive.length === 3)
      m.emissive.setRGB(state.emissive[0], state.emissive[1], state.emissive[2]);
    else if (state && typeof state.on === 'boolean') {
      if (state.on) m.emissive.setRGB(1, 0.6, 0.15);       // gold
      else m.emissive.setRGB(0.02, 0.02, 0.02);            // dark / off
    }
  });
}
async function toggleObject(objId) {
  var key = roomId + ':' + objId;
  var cur = objStates.get(key) || {};
  var isOn = (cur.on !== false);   // VRML default is lit; no state yet means on
  var next = { on: !isOn, by: myName, at: Math.floor(Date.now() / 1000) };
  objStateTs.set(key, next.at);
  objStates.set(key, next);
  applyState(objId, next);
  publish(await makeEvent(30031, [['d', key]], JSON.stringify(next)));
  sysLine('you toggled ' + objId + ' ' + (next.on ? 'on' : 'off'));
}
function setRoom(id) {
  if (!id || id === roomId) return;
  roomId = id;
  roomBest = null;
  peers.forEach(function (p) { peerGroup.remove(p.avatar); disposeGroup(p.avatar); });
  peers.clear();
  $('roomname').textContent = 'room: ' + id;
  setSubs();
  clearChat();
  clearGames();
  applySpawn = true;  // fresh room entry: start at the viewpoint
  buildScene(fallbackVRML(id));
  sysLine('entering ' + id + '…');
  publishPresence();
  updateOnline();
}

/* ---------------- presence ---------------- */
function onPresence(ev) {
  if (ev.kind !== 30010 || ev.pubkey === myPubHex) return;
  if (tag(ev, 'd') !== roomId) return;
  /* stored presence is replayed by relays long after its author left —
     trust the event's own clock, not receipt time, or ghosts linger */
  var age = Date.now() / 1000 - (ev.created_at || 0);
  if (age < -30 || age > 35) return;
  var p = null;
  try { p = JSON.parse(ev.content); } catch (e) { return; }
  if (typeof p.x !== 'number' || typeof p.z !== 'number') return;
  var peer = peers.get(ev.pubkey);
  var colKey = JSON.stringify((p && p.avatar) || null);
  if (!peer) {
    var av = makeAvatar(p.name || 'guest', p.avatar);
    av.position.set(p.x, 0, p.z);
    peerGroup.add(av);
    peer = { avatar: av, name: (p.name || 'guest').slice(0, 24), x: p.x, z: p.z, yaw: p.yaw || 0, lastSeen: Date.now(), picUrl: null, picSprite: null, colKey: colKey };
    peers.set(ev.pubkey, peer);
    sysLine(peer.name + ' entered');
  } else {
    peer.x = p.x; peer.z = p.z; peer.yaw = p.yaw || 0; peer.lastSeen = Date.now();
    if (peer.colKey !== colKey) {
      /* they changed their look: rebuild the avatar live */
      peerGroup.remove(peer.avatar);
      peer.avatar = makeAvatar(peer.name, p.avatar);
      peer.avatar.position.set(peer.x, 0, peer.z);
      peerGroup.add(peer.avatar);
      peer.colKey = colKey;
      peer.picUrl = null; peer.picSprite = null;  // re-attach picture below
    }
  }
  setPeerPicture(peer, (p && typeof p.picture === 'string') ? p.picture : null);
  updateOnline();
}
/* profile picture above the avatar's head (from the human's kind-0 via presence) */
var texLoader = null;
function setPeerPicture(peer, url) {
  if (!url || !/^https?:\/\//i.test(url)) url = null;
  if (peer.picUrl === url) return;
  peer.picUrl = url;
  if (peer.picSprite) { peer.avatar.remove(peer.picSprite); peer.picSprite = null; }
  if (!url) return;
  try {
    if (!texLoader) { texLoader = new THREE.TextureLoader(); texLoader.setCrossOrigin('anonymous'); }
    texLoader.load(url, function (tex) {
      var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, transparent: true, depthTest: false }));
      sp.scale.set(0.55, 0.55, 1);
      sp.position.y = 2.78;
      peer.avatar.add(sp);
      peer.picSprite = sp;
    }, undefined, function () { peer.picUrl = 'bad'; });
  } catch (e) { peer.picUrl = 'bad'; }
}
function makeAvatar(name, av) {
  var g = new THREE.Group();
  var h = 0;
  for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  av = (av && typeof av === 'object') ? av : {};
  var skins = ['#f1c9a5', '#e0ac69', '#c68642', '#8d5524', '#5c3a21', '#3b2314'];
  var shirt = new THREE.MeshStandardMaterial({ color: new THREE.Color(cleanHex(av.shirt, null) || ('hsl(' + (h % 360) + ',60%,55%)')), roughness: 0.7 });
  var skin = new THREE.MeshStandardMaterial({ color: new THREE.Color(cleanHex(av.skin, null) || skins[h % skins.length]), roughness: 0.6 });
  var pants = new THREE.MeshStandardMaterial({ color: new THREE.Color(cleanHex(av.pants, null) || ('hsl(' + (h % 360) + ',25%,28%)')), roughness: 0.8 });
  var dark = new THREE.MeshStandardMaterial({ color: 0x1a1a1a, roughness: 0.5 });
  // legs
  var legGeo = new THREE.CylinderGeometry(0.11, 0.13, 0.55, 10);
  var legL = new THREE.Mesh(legGeo, pants); legL.position.set(-0.14, 0.28, 0); g.add(legL);
  var legR = new THREE.Mesh(legGeo, pants); legR.position.set(0.14, 0.28, 0); g.add(legR);
  // torso
  var torso = new THREE.Mesh(new THREE.CapsuleGeometry(0.30, 0.55, 6, 14), shirt);
  torso.position.y = 0.95; g.add(torso);
  // arms + hands
  var armGeo = new THREE.CapsuleGeometry(0.09, 0.5, 4, 10);
  var armL = new THREE.Mesh(armGeo, shirt); armL.position.set(-0.42, 1.05, 0); armL.rotation.z = 0.15; g.add(armL);
  var armR = new THREE.Mesh(armGeo, shirt); armR.position.set(0.42, 1.05, 0); armR.rotation.z = -0.15; g.add(armR);
  var handGeo = new THREE.SphereGeometry(0.09, 10, 8);
  var handL = new THREE.Mesh(handGeo, skin); handL.position.set(-0.47, 0.72, 0); g.add(handL);
  var handR = new THREE.Mesh(handGeo, skin); handR.position.set(0.47, 0.72, 0); g.add(handR);
  // head + eyes: the face looks along local -z, which is where the
  // camera looks when rotation.y = yaw (forward = (-sin yaw, -cos yaw)),
  // so the eyes end up on the side the avatar is actually facing.
  var head = new THREE.Mesh(new THREE.SphereGeometry(0.26, 18, 14), skin);
  head.position.y = 1.72; g.add(head);
  var eyeGeo = new THREE.SphereGeometry(0.035, 8, 6);
  var eyeL = new THREE.Mesh(eyeGeo, dark); eyeL.position.set(-0.09, 1.76, -0.23); g.add(eyeL);
  var eyeR = new THREE.Mesh(eyeGeo, dark); eyeR.position.set(0.09, 1.76, -0.23); g.add(eyeR);
  var cv = document.createElement('canvas');
  cv.width = 256; cv.height = 64;
  var cx = cv.getContext('2d');
  cx.fillStyle = 'rgba(0,0,0,0.45)'; cx.fillRect(0, 0, 256, 64);
  cx.font = 'bold 34px sans-serif'; cx.textAlign = 'center'; cx.textBaseline = 'middle';
  cx.fillStyle = '#fff'; cx.fillText(name.slice(0, 16), 128, 34);
  var sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: new THREE.CanvasTexture(cv), transparent: true, depthTest: false }));
  sp.scale.set(1.7, 0.42, 1);
  sp.position.y = 2.3;
  g.add(sp);
  return g;
}
async function publishPresence() {
  if (!myPubHex) return;
  var body = { name: myName, x: +player.x.toFixed(2), y: 0, z: +player.z.toFixed(2), yaw: +yaw.toFixed(2) };
  if (myPicture) body.picture = myPicture;   // others render our kind-0 picture
  if (avatarColors) body.avatar = avatarColors;  // our look: skin/shirt/pants
  if (loggedIn && pairingOn && pairedAgents.length) body.pair = pairedAgents.slice();
  publish(await makeEvent(30010, [['d', roomId]], JSON.stringify(body)));
}
/* ---- kind-0 profile: name + picture come from your npub ---- */
function shortId(h) { return '@' + String(h || '').slice(0, 8); }
function resolveProfile() {
  if (!loggedIn || !myHumanHex) { myName = 'guest'; myPicture = null; return; }
  myName = shortId(myHumanHex);   // placeholder until kind 0 arrives
  myPicture = null;
  var id = 'aw:prof:' + (subSeq++);
  var filter = { kinds: [0], authors: [myHumanHex], limit: 1 };
  activeSubs.push({ id: id, purpose: 'prof', room: roomId, filter: filter });
  broadcast(JSON.stringify(['REQ', id, filter]));
  setTimeout(function () { closeProfileSub(id); }, 12000);
}
function closeProfileSub(id) {
  broadcast(JSON.stringify(['CLOSE', id]));
  for (var i = 0; i < activeSubs.length; i++)
    if (activeSubs[i].id === id) { activeSubs.splice(i, 1); break; }
}
function onProfile(ev) {
  if (ev.kind !== 0 || ev.pubkey !== myHumanHex) return;
  var p = null;
  try { p = JSON.parse(ev.content); } catch (e) { return; }
  var nm = String(p.display_name || p.name || '').trim().slice(0, 24);
  myName = nm || shortId(myHumanHex);
  var pic = (typeof p.picture === 'string' && /^https?:\/\//i.test(p.picture)) ? p.picture : null;
  myPicture = pic;
  for (var i = activeSubs.length - 1; i >= 0; i--)
    if (activeSubs[i].purpose === 'prof') { closeProfileSub(activeSubs[i].id); }
  publishPresence();   // heartbeat at once with our real name + picture
  sysLine('logged in as ' + myName);
}
function togglePair() {
  pairingOn = !pairingOn;
  try { localStorage.setItem('aw_pair_mica', pairingOn ? '1' : '0'); } catch (e) {}
  refreshPairBtn();
  publishPresence();  // heartbeat immediately so agents arrive/leave at once
  sysLine(pairingOn ? 'agent pairing on.' : 'agent pairing off.');
}
function refreshPairBtn() {
  var b = $('pairbtn');
  if (!b) return;
  b.classList.toggle('off', !pairingOn);
  b.title = !loggedIn ? 'log in with your npub pair (⚙️)' :
    (pairingOn ? 'agents paired — tap to dismiss them' : 'pairing off — tap to call your agents');
}
/* ---------------- settings: npub-pair login ---------------- */
function openSettings() {
  $('humannpub').value = humanNpubStr;
  $('pairin').value = agentNpubStrs.join('\n');
  $('nsecin').value = '';
  $('nsecin').placeholder = hasNsec ? 'nsec saved on this device — enter a new one to replace it' : 'nsec1… (stays on this device)';
  var ac = avatarColors || AV_DEFAULTS;
  $('avskin').value = cleanHex(ac.skin, AV_DEFAULTS.skin);
  $('avshirt').value = cleanHex(ac.shirt, AV_DEFAULTS.shirt);
  $('avpants').value = cleanHex(ac.pants, AV_DEFAULTS.pants);
  $('loginmsg').textContent = '';
  $('settingspanel').classList.add('open');
}
function closeSettings() { $('settingspanel').classList.remove('open'); }
async function saveLogin() {
  var msg = '';
  var nsecInput = $('nsecin').value.trim();
  if (nsecInput) {
    var nh = nsecToHex(nsecInput);
    if (!nh) { $('loginmsg').textContent = 'that nsec doesn\u2019t decode \u2014 nothing saved'; return; }
    try { localStorage.setItem('aw_nsec', nsecInput); } catch (e) {}
    await initIdentity();           // this device now signs AS your npub
    humanNpubStr = hexToNpub(myPubHex);   // derived from the PUBLIC key — never the nsec bytes
    $('humannpub').value = humanNpubStr;
    $('nsecin').value = '';
    msg = 'proven identity \u2014 you sign as ' + shortId(myPubHex) + '. ';
  }
  humanNpubStr = $('humannpub').value.trim();
  var lines = $('pairin').value.split('\n'), out = [], bad = 0;
  lines.forEach(function (ln) {
    ln = ln.trim(); if (!ln) return;
    if (npubToHex(ln)) { if (out.indexOf(ln) < 0) out.push(ln); } else bad++;
  });
  agentNpubStrs = out;
  try {
    localStorage.setItem('aw_human_npub', humanNpubStr);
    localStorage.setItem('aw_agent_npubs', JSON.stringify(out));
    localStorage.removeItem('aw_pairs');   // v0.4.x key, superseded
    localStorage.removeItem('aw_name');    // v0.4.x key, superseded
  } catch (e) {}
  avatarColors = readAvatarInputs();
  try { localStorage.setItem('aw_avatar', JSON.stringify(avatarColors)); } catch (e) {}
  refreshLogin();
  if (loggedIn) { msg += 'logged in — resolving profile…'; resolveProfile(); }
  else {
    msg += 'guest mode — both npubs are required to log in';
    myName = 'guest'; myPicture = null;
  }
  if (bad) msg += ' (' + bad + ' line(s) ignored)';
  $('loginmsg').textContent = msg;
  refreshPairBtn();
  publishPresence();
}
function bindSettings() {
  $('setbtn').addEventListener('click', function () {
    $('settingspanel').classList.contains('open') ? closeSettings() : openSettings();
  });
  $('setclose').addEventListener('click', closeSettings);
  $('pairsave').addEventListener('click', saveLogin);
  $('nsecclear').addEventListener('click', async function () {
    try { localStorage.removeItem('aw_nsec'); } catch (e) {}
    $('nsecin').value = '';
    await initIdentity();   // back to the throwaway local key
    openSettings();
    $('loginmsg').textContent = 'nsec forgotten on this device — claimed-npub mode';
    publishPresence();
  });
}
function updateOnline() { $('online').textContent = (peers.size + 1) + ' online'; }

/* ---------------- chat ---------------- */
var histMode = false;
function fmtTime(ts) {
  var d = new Date(ts * 1000);
  var h = d.getHours(), m = d.getMinutes();
  return (h < 10 ? '0' + h : h) + ':' + (m < 10 ? '0' + m : m);
}
function addLine(name, text, sys, ts) {
  var log = $('chatlog');
  var div = document.createElement('div');
  div.className = 'chatline' + (sys ? ' sys' : '');
  div.textContent = sys ? text : '[' + fmtTime(ts || Math.floor(Date.now() / 1000)) + '] <' + name + '> ' + text;
  log.appendChild(div);
  while (log.children.length > 200) log.removeChild(log.firstChild);
  if (histMode) {
    var nearBottom = (log.scrollHeight - log.scrollTop - log.clientHeight) < 60;
    if (nearBottom) log.scrollTop = log.scrollHeight;
  }
}
function sysLine(t) { addLine('', t, true); }
function onChat(ev) {
  if (ev.kind !== 20111 || ev.pubkey === myPubHex) return;
  var c = null;
  try { c = JSON.parse(ev.content); } catch (e) { return; }
  addLine((c.name || 'guest').slice(0, 24), String(c.text || '').slice(0, 280), false, ev.created_at);
}
async function sendChat() {
  var inp = $('chatin');
  var text = inp.value.trim();
  if (!text) return;
  inp.value = '';
  addLine(myName, text, false);
  publish(await makeEvent(20111, [['room', roomId]], JSON.stringify({ name: myName, text: text })));
}
function clearChat() { $('chatlog').innerHTML = ''; }
function bindHist() {
  $('histbtn').addEventListener('click', function () {
    histMode = !histMode;
    $('chatlog').classList.toggle('history', histMode);
    $('histbtn').classList.toggle('active', histMode);
    if (histMode) { var log = $('chatlog'); log.scrollTop = log.scrollHeight; }
  });
  var pb = $('pairbtn');
  if (pb) {
    refreshPairBtn();
    pb.addEventListener('click', function () {
      if (!loggedIn) openSettings(); else togglePair();
    });
  }
}

/* ---------------- games: lobby + tic-tac-toe + connect 4 + trivia ------ */
/* Protocol (AgentWorld v0.7):
 *   kind 30032  game session, parameterized replaceable, #d = gameId, #room
 *               {v,id,game,status,host,hostName,players[],names{},room,winner,at}
 *               status: open -> playing -> finished
 *   kind 30033  game state, #d = gameId, #room
 *               tictactoe/connect4: {v,id,game,seq,board[],turn,winner,at}
 *               trivia: {v,id,game:'trivia',seq,round,phase,q,answers{},scores{},at}
 *   kind 30034  trivia answer, parameterized replaceable, #d = gameId:playerHex
 *               {v,choice} — one slot per player, no write clobbering
 * Humans and agents share the same events; either side can host or join.
 */
var GK = { SESSION: 30032, STATE: 30033, ANSWER: 30034 };
var GDEF = {
  tictactoe: { label: 'Tic-tac-toe', maxp: 2 },
  connect4:  { label: 'Connect 4', maxp: 2 },
  trivia:    { label: 'Trivia', maxp: 8 }
};
var games = {};        // gameId -> session
var gstates = {};      // gameId -> latest state
var ganswers = {};     // gameId -> {playerHex: choiceIdx}
var openGameId = null; // board currently displayed
var triviaTimers = {}; // gameId -> timeout id (host only)
var TRIVIA_ROUNDS = 5, TRIVIA_QSECS = 25, TRIVIA_RSECS = 6;

/* ---- pure game logic (unit-tested in node) ---- */
function tttWinner(b) {
  var L = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  for (var i = 0; i < L.length; i++) {
    var a = L[i][0], c = L[i][1], d = L[i][2];
    if (b[a] && b[a] === b[c] && b[a] === b[d]) return b[a];
  }
  for (var j = 0; j < 9; j++) if (!b[j]) return null;
  return 'draw';
}
function c4Drop(b, col, piece) {
  for (var r = 5; r >= 0; r--) {
    var i = r * 7 + col;
    if (!b[i]) { b[i] = piece; return r; }
  }
  return -1;
}
function c4Winner(b) {
  function at(r, c) { return (r < 0 || r > 5 || c < 0 || c > 6) ? null : b[r * 7 + c]; }
  for (var r = 0; r < 6; r++) for (var c = 0; c < 7; c++) {
    var p = at(r, c);
    if (!p) continue;
    if (at(r, c+1) === p && at(r, c+2) === p && at(r, c+3) === p) return p;
    if (at(r+1, c) === p && at(r+2, c) === p && at(r+3, c) === p) return p;
    if (at(r+1, c+1) === p && at(r+2, c+2) === p && at(r+3, c+3) === p) return p;
    if (at(r+1, c-1) === p && at(r+2, c-2) === p && at(r+3, c-3) === p) return p;
  }
  for (var k = 0; k < 42; k++) if (!b[k]) return null;
  return 'draw';
}

/* ---- trivia question bank (shared with the Mica bot) ---- */
var TRIVIA_BANK = [
  { q: 'Which planet is known as the Red Planet?', c: ['Venus', 'Mars', 'Jupiter', 'Mercury'], a: 1 },
  { q: 'How many legs does a spider have?', c: ['6', '8', '10', '4'], a: 1 },
  { q: 'What is the largest ocean on Earth?', c: ['Atlantic', 'Indian', 'Pacific', 'Arctic'], a: 2 },
  { q: 'What gas do plants absorb from the air?', c: ['Oxygen', 'Carbon dioxide', 'Nitrogen', 'Hydrogen'], a: 1 },
  { q: 'How many days are in a leap year?', c: ['365', '366', '367', '364'], a: 1 },
  { q: 'What is the capital of Japan?', c: ['Kyoto', 'Osaka', 'Tokyo', 'Beijing'], a: 2 },
  { q: 'H2O is the chemical formula for…', c: ['Salt', 'Sugar', 'Water', 'Oxygen'], a: 2 },
  { q: 'Which planet is famous for its rings?', c: ['Mars', 'Saturn', 'Venus', 'Neptune'], a: 1 },
  { q: 'How many colors are in a rainbow?', c: ['5', '6', '7', '8'], a: 2 },
  { q: 'What is the fastest land animal?', c: ['Lion', 'Greyhound', 'Cheetah', 'Horse'], a: 2 },
  { q: 'What do honeybees make?', c: ['Wax paper', 'Honey', 'Silk', 'Syrup'], a: 1 },
  { q: 'How many strings does a standard guitar have?', c: ['4', '5', '6', '7'], a: 2 },
  { q: 'What is the largest mammal on Earth?', c: ['Elephant', 'Blue whale', 'Giraffe', 'Hippo'], a: 1 },
  { q: 'Water boils at what temperature (°C)?', c: ['90', '95', '100', '110'], a: 2 },
  { q: 'Which of these is a prime number?', c: ['4', '6', '7', '9'], a: 2 },
  { q: 'What is the capital of France?', c: ['London', 'Paris', 'Rome', 'Madrid'], a: 1 },
  { q: 'How many sides does a hexagon have?', c: ['5', '6', '7', '8'], a: 1 },
  { q: 'Which planet is closest to the Sun?', c: ['Venus', 'Earth', 'Mercury', 'Mars'], a: 2 },
  { q: 'Which instrument has 88 keys?', c: ['Guitar', 'Piano', 'Violin', 'Drums'], a: 1 },
  { q: 'How many minutes are in an hour?', c: ['30', '60', '90', '100'], a: 1 },
  { q: 'What does a thermometer measure?', c: ['Weight', 'Temperature', 'Speed', 'Pressure'], a: 1 },
  { q: 'Which animal is a marsupial?', c: ['Kangaroo', 'Zebra', 'Panda', 'Koala'], a: 0 },
  { q: 'How many players does a soccer team field?', c: ['9', '10', '11', '12'], a: 2 },
  { q: 'What is frozen water called?', c: ['Steam', 'Ice', 'Mist', 'Dew'], a: 1 }
];

/* ---- protocol helpers ---- */
function nowSec() { return Math.floor(Date.now() / 1000); }
function newGameId() {
  var h = '0123456789abcdef', s = 'g';
  for (var i = 0; i < 8; i++) s += h[Math.floor(Math.random() * 16)];
  return s;
}
function dTag(ev) {
  var t = ev.tags || [];
  for (var i = 0; i < t.length; i++) if (t[i][0] === 'd') return t[i][1];
  return null;
}
async function pubGameSession(s) {
  s.at = nowSec();
  publish(await makeEvent(GK.SESSION, [['d', s.id], ['room', roomId]], JSON.stringify(s)));
}
async function pubGameState(st) {
  st.at = nowSec();
  publish(await makeEvent(GK.STATE, [['d', st.id], ['room', roomId]], JSON.stringify(st)));
}
async function pubAnswer(id, choice) {
  publish(await makeEvent(GK.ANSWER, [['d', id + ':' + myPubHex], ['room', roomId]],
    JSON.stringify({ v: 1, choice: choice })));
}
function gameName(s) {
  var n = (s.names && s.names[s.host]) || s.hostName || 'host';
  return GDEF[s.game].label + ' — ' + String(n).slice(0, 18);
}
function shortHex(h) { return '@' + String(h || '').slice(0, 8); }

/* ---- actions ---- */
async function startGame(game) {
  var id = newGameId();
  var s = { v: 1, id: id, game: game, status: 'open', host: myPubHex, hostName: myName,
            players: [myPubHex], names: {}, room: roomId, winner: null, at: nowSec() };
  s.names[myPubHex] = myName;
  games[id] = s;
  await pubGameSession(s);
  var st;
  if (game === 'tictactoe') {
    st = { v: 1, id: id, game: game, seq: 0, board: ['', '', '', '', '', '', '', '', ''],
           turn: myPubHex, winner: null, at: nowSec() };
  } else if (game === 'connect4') {
    var b = []; for (var i = 0; i < 42; i++) b.push('');
    st = { v: 1, id: id, game: game, seq: 0, board: b, turn: myPubHex, winner: null, at: nowSec() };
  } else {
    st = { v: 1, id: id, game: 'trivia', seq: 0, round: 0, phase: 'lobby',
           q: null, answers: {}, scores: {}, at: nowSec() };
  }
  gstates[id] = st;
  await pubGameState(st);
  renderGameList();
  openBoard(id);
  sysLine('you started ' + GDEF[game].label + ' — others join from 🎮');
  publish(await makeEvent(20111, [['room', roomId]],
    JSON.stringify({ name: myName, text: '🎮 started ' + GDEF[game].label + ' — open 🎮 to join!' })));
}
async function joinGame(id) {
  var s = games[id];
  if (!s || s.status !== 'open') return;
  if (s.players.indexOf(myPubHex) >= 0) { openBoard(id); return; }
  if (s.players.length >= GDEF[s.game].maxp) return;
  s.players.push(myPubHex);
  s.names[myPubHex] = myName;
  if (s.game !== 'trivia' && s.players.length >= 2) s.status = 'playing';
  games[id] = s;
  await pubGameSession(s);
  renderGameList();
  openBoard(id);
  sysLine('you joined ' + gameName(s));
}
async function finishGame(s, winner) {
  s.status = 'finished'; s.winner = winner || null;
  await pubGameSession(s);
  renderGameList(); renderBoard();
}
function otherPlayer(s) {
  for (var i = 0; i < s.players.length; i++)
    if (s.players[i] !== myPubHex) return s.players[i];
  return null;
}
async function tttMove(i) {
  var s = games[openGameId], st = gstates[openGameId];
  if (!s || !st || s.status !== 'playing' || st.winner) return;
  if (st.turn !== myPubHex || st.board[i]) return;
  var piece = (s.players[0] === myPubHex) ? 'X' : 'O';
  st.board[i] = piece;
  var w = tttWinner(st.board);
  st.winner = (w === 'draw') ? 'draw' : (w ? myPubHex : null);
  st.turn = otherPlayer(s);
  st.seq++;
  await pubGameState(st);
  renderBoard();
  if (st.winner) finishGame(s, st.winner);
}
async function c4Move(col) {
  var s = games[openGameId], st = gstates[openGameId];
  if (!s || !st || s.status !== 'playing' || st.winner) return;
  if (st.turn !== myPubHex) return;
  var piece = (s.players[0] === myPubHex) ? 'R' : 'Y';
  var board = st.board.slice();
  if (c4Drop(board, col, piece) < 0) return;   // column full
  st.board = board;
  var w = c4Winner(st.board);
  st.winner = (w === 'draw') ? 'draw' : (w ? myPubHex : null);
  st.turn = otherPlayer(s);
  st.seq++;
  await pubGameState(st);
  renderBoard();
  if (st.winner) finishGame(s, st.winner);
}
/* trivia: host drives rounds, everyone answers into their own 30034 slot */
async function triviaStart(id) {
  var s = games[id];
  if (!s || s.host !== myPubHex || s.status !== 'open') return;
  if (s.players.length < 2) { sysLine('trivia needs at least 2 players'); return; }
  s.status = 'playing';
  await pubGameSession(s);
  triviaAsk(id);
}
async function triviaAsk(id) {
  var s = games[id];
  if (!s || s.host !== myPubHex || s.status !== 'playing') return;
  var st = gstates[id] || { v: 1, id: id, game: 'trivia', seq: 0, scores: {} };
  var round = (st.round || 0) + 1;
  var q = TRIVIA_BANK[Math.floor(Math.random() * TRIVIA_BANK.length)];
  st.round = round; st.phase = 'question';
  st.q = { q: q.q, c: q.c, a: q.a };
  st.answers = {}; st.seq++;
  gstates[id] = st; ganswers[id] = {};
  await pubGameState(st);
  renderBoard();
  if (triviaTimers[id]) clearTimeout(triviaTimers[id]);
  triviaTimers[id] = setTimeout(function () { triviaReveal(id); }, TRIVIA_QSECS * 1000);
}
async function triviaReveal(id) {
  var s = games[id], st = gstates[id];
  if (!s || !st || s.host !== myPubHex || st.phase !== 'question') return;
  var ans = ganswers[id] || {};
  var scores = st.scores || {};
  for (var hx in ans) {
    if (ans[hx] === st.q.a) scores[hx] = (scores[hx] || 0) + 1;
    else if (!(hx in scores)) scores[hx] = 0;
  }
  for (var i = 0; i < s.players.length; i++)
    if (!(s.players[i] in scores)) scores[s.players[i]] = 0;
  st.answers = ans; st.scores = scores; st.phase = 'reveal'; st.seq++;
  await pubGameState(st);
  renderBoard();
  if (triviaTimers[id]) clearTimeout(triviaTimers[id]);
  triviaTimers[id] = setTimeout(function () {
    var cur = gstates[id];
    if (!cur || games[id].host !== myPubHex) return;
    if (cur.round >= TRIVIA_ROUNDS) {
      var best = null, bestN = -1, tie = false;
      for (var hx in cur.scores) {
        if (cur.scores[hx] > bestN) { best = hx; bestN = cur.scores[hx]; tie = false; }
        else if (cur.scores[hx] === bestN) tie = true;
      }
      finishGame(games[id], tie ? 'draw' : best);
    } else triviaAsk(id);
  }, TRIVIA_RSECS * 1000);
}
async function triviaAnswer(i) {
  var st = gstates[openGameId];
  if (!st || st.game !== 'trivia' || st.phase !== 'question') return;
  var cur = (ganswers[openGameId] || {})[myPubHex];
  if (cur === i) return;
  if (!ganswers[openGameId]) ganswers[openGameId] = {};
  ganswers[openGameId][myPubHex] = i;
  await pubAnswer(openGameId, i);
  renderBoard();
}

/* ---- event handlers ---- */
function onGameEvent(ev) {
  if (ev.kind === GK.SESSION) onGameSession(ev);
  else if (ev.kind === GK.STATE) onGameState(ev);
  else if (ev.kind === GK.ANSWER) onGameAnswer(ev);
}
function onGameSession(ev) {
  if (dTag(ev) === null) return;
  var s = null;
  try { s = JSON.parse(ev.content); } catch (e) { return; }
  if (!s || s.id !== dTag(ev) || !GDEF[s.game] || !Array.isArray(s.players)) return;
  if (!s.players.every(function (p) { return typeof p === 'string' && /^[0-9a-f]{64}$/.test(p); })) return;
  var old = games[s.id];
  if (old && (s.at || 0) < (old.at || 0)) return;   // older session update: ignore
  if (old && old.host !== s.host) return;          // host never changes
  games[s.id] = s;
  if (s.status === 'open' && s.players.indexOf(myPubHex) < 0 &&
      s.players.length < GDEF[s.game].maxp) {
    sysLine(gameName(s) + ' is open — tap 🎮 to join');
  }
  renderGameList();
  if (openGameId === s.id) renderBoard();
}
function onGameState(ev) {
  var st = null;
  try { st = JSON.parse(ev.content); } catch (e) { return; }
  if (!st || st.id !== dTag(ev) || !GDEF[st.game]) return;
  if (!Array.isArray(st.board) || st.board.length !== (st.game === 'connect4' ? 42 : 9)) {
    if (st.game !== 'trivia') return;
  }
  var old = gstates[st.id];
  if (old && (st.seq || 0) <= (old.seq || 0)) return;   // stale move: ignore
  gstates[st.id] = st;
  if (openGameId === st.id) renderBoard();
}
function onGameAnswer(ev) {
  var d = dTag(ev);
  if (!d) return;
  var parts = d.split(':');
  if (parts.length !== 2) return;
  var id = parts[0], hx = parts[1];
  if (hx !== ev.pubkey) return;   // answer slot belongs to its author
  var a = null;
  try { a = JSON.parse(ev.content); } catch (e) { return; }
  if (!a || typeof a.choice !== 'number' || a.choice < 0 || a.choice > 3) return;
  if (!ganswers[id]) ganswers[id] = {};
  ganswers[id][hx] = a.choice;
  if (openGameId === id) renderBoard();
}

/* ---- lobby + board UI ---- */
function openGames() {
  closeBoard();
  $('boardpanel').classList.remove('open');
  $('gamespanel').classList.add('open');
  renderGameList();
}
function closeGames() { $('gamespanel').classList.remove('open'); }
function renderGameList() {
  var list = $('gamelist');
  var ids = Object.keys(games).filter(function (id) { return games[id].status !== 'finished'; });
  ids.sort(function (a, b) { return (games[b].at || 0) - (games[a].at || 0); });
  var done = Object.keys(games).filter(function (id) { return games[id].status === 'finished'; });
  done.sort(function (a, b) { return (games[b].at || 0) - (games[a].at || 0); });
  done = done.slice(0, 3);
  var html = '';
  function row(s) {
    var me = s.players.indexOf(myPubHex) >= 0;
    var btn;
    if (s.status === 'open' && !me && s.players.length < GDEF[s.game].maxp)
      btn = '<button data-join="' + s.id + '">Join</button>';
    else if (me || s.status !== 'open')
      btn = '<button data-open="' + s.id + '">Open</button>';
    else btn = '<span class="gs">full</span>';
    var pl = s.players.map(function (p) { return (s.names && s.names[p]) || shortHex(p); }).join(', ');
    var res = '';
    if (s.status === 'finished') {
      res = ' · ' + (s.winner === 'draw' ? 'draw' :
        'winner: ' + (((s.names && s.names[s.winner]) || shortHex(s.winner)) || '?'));
    }
    return '<div class="gamerow"><div class="gt">' + escHtml(GDEF[s.game].label) + '</div>' +
      '<div class="gs">' + escHtml(gameName(s)) + ' · ' + s.status + ' · ' +
      s.players.length + '/' + GDEF[s.game].maxp + res + '<br>' + escHtml(pl) + '</div>' + btn + '</div>';
  }
  ids.forEach(function (id) { html += row(games[id]); });
  done.forEach(function (id) { html += row(games[id]); });
  if (!html) html = '<div class="gs">No games yet — start one below.</div>';
  list.innerHTML = html;
  var btns = list.querySelectorAll('button[data-join]');
  for (var i = 0; i < btns.length; i++)
    btns[i].addEventListener('click', function () { joinGame(this.getAttribute('data-join')); });
  var ops = list.querySelectorAll('button[data-open]');
  for (var j = 0; j < ops.length; j++)
    ops[j].addEventListener('click', function () { openBoard(this.getAttribute('data-open')); });
  var anyOpen = ids.some(function (id) {
    var s = games[id];
    return s.status === 'open' && s.players.indexOf(myPubHex) < 0;
  });
  var dot = $('gamebtn').querySelector('.dot');
  if (dot) dot.style.display = anyOpen && !$('gamespanel').classList.contains('open') ? '' : 'none';
}
function escHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function openBoard(id) {
  if (!games[id]) return;
  openGameId = id;
  closeGames();
  $('boardpanel').classList.add('open');
  renderBoard();
}
function closeBoard() {
  openGameId = null;
  $('boardpanel').classList.remove('open');
}
function pname(s, hx) {
  return escHtml((s.names && s.names[hx]) || shortHex(hx));
}
function renderBoard() {
  var body = $('boardbody'), status = $('boardstatus'), title = $('boardtitle');
  var s = games[openGameId], st = gstates[openGameId];
  if (!s) { closeBoard(); return; }
  title.textContent = '🎮 ' + GDEF[s.game].label;
  var html = '', stat = '';
  if (s.game === 'tictactoe') {
    var r = renderTTT(s, st); stat = r.stat; html = r.html;
  } else if (s.game === 'connect4') {
    var r2 = renderC4(s, st); stat = r2.stat; html = r2.html;
  } else {
    var r3 = renderTrivia(s, st); stat = r3.stat; html = r3.html;
  }
  status.innerHTML = stat;
  body.innerHTML = html;
  bindBoardButtons(s, st);
}
function turnText(s, st) {
  if (!st || st.winner) {
    if (!st || !st.winner) return 'waiting for players…';
    if (st.winner === 'draw') return "it's a draw!";
    return (st.winner === myPubHex ? 'you win! 🎉' : pname(s, st.winner) + ' wins!');
  }
  if (s.status !== 'playing') return 'waiting for players…';
  return st.turn === myPubHex ? 'your move' : pname(s, st.turn) + "'s move";
}
function renderTTT(s, st) {
  var html = '<div id="tttgrid">';
  var b = (st && st.board) || ['', '', '', '', '', '', '', '', ''];
  for (var i = 0; i < 9; i++)
    html += '<button class="cell" data-ttt="' + i + '">' + (b[i] || '') + '</button>';
  html += '</div>';
  return { stat: escHtml(turnText(s, st)), html: html };
}
function renderC4(s, st) {
  var b = (st && st.board) || [];
  while (b.length < 42) b.push('');
  var html = '<div id="c4grid">';
  for (var c = 0; c < 7; c++)
    html += '<button class="cell top" data-c4="' + c + '">▼</button>';
  for (var r = 0; r < 6; r++) for (var cc = 0; cc < 7; cc++) {
    var v = b[r * 7 + cc];
    html += '<button class="cell" data-c4="' + cc + '">' + (v === 'R' ? '🔴' : v === 'Y' ? '🟡' : '') + '</button>';
  }
  html += '</div>';
  return { stat: escHtml(turnText(s, st)), html: html };
}
function renderTrivia(s, st) {
  var html = '', stat = '';
  var me = myPubHex;
  if (s.status === 'open') {
    stat = escHtml(s.players.length + ' player' + (s.players.length > 1 ? 's' : '') + ' — waiting');
    html = '<div class="gs">' + s.players.map(function (p) { return pname(s, p); }).join(', ') + '</div>';
    if (s.host === me)
      html += '<div style="text-align:center;margin-top:10px"><button class="gstartbtn" data-trivstart="1">Start rounds</button></div>';
    else html += '<div class="gs" style="text-align:center">host starts the rounds…</div>';
    return { stat: stat, html: html };
  }
  if (!st || st.phase === 'lobby') return { stat: 'starting…', html: '' };
  stat = 'round ' + st.round + '/' + TRIVIA_ROUNDS;
  if (st.phase === 'question' && st.q) {
    html = '<div class="trivq">' + escHtml(st.q.q) + '</div>';
    var mine = (ganswers[s.id] || {})[me];
    for (var i = 0; i < st.q.c.length; i++)
      html += '<button class="trivchoice' + (mine === i ? ' picked' : '') + '" data-tqa="' + i + '">' +
        escHtml(st.q.c[i]) + '</button>';
    var n = Object.keys(ganswers[s.id] || {}).length;
    html += '<div class="gs" style="text-align:center">' + n + '/' + s.players.length + ' answered</div>';
  } else if (st.phase === 'reveal' && st.q) {
    html = '<div class="trivq">' + escHtml(st.q.q) + '</div>';
    var mine2 = (ganswers[s.id] || {})[me];
    for (var j = 0; j < st.q.c.length; j++) {
      var cls = 'trivchoice';
      if (j === st.q.a) cls += ' right';
      else if (mine2 === j) cls += ' wrong';
      html += '<button class="' + cls + '" disabled>' + escHtml(st.q.c[j]) + '</button>';
    }
    html += '<div class="trivscores">' + Object.keys(st.scores || {}).sort(function (a, b) {
      return (st.scores[b] || 0) - (st.scores[a] || 0);
    }).map(function (p) {
      return '<div>' + pname(s, p) + ': ' + (st.scores[p] || 0) + '</div>';
    }).join('') + '</div>';
  }
  if (s.status === 'finished') {
    stat = s.winner === 'draw' ? "it's a draw!" :
      (s.winner === me ? 'you win! 🎉' : pname(s, s.winner) + ' wins! 🎉');
  }
  return { stat: stat, html: html };
}
function bindBoardButtons(s, st) {
  var body = $('boardbody');
  var tcells = body.querySelectorAll('button[data-ttt]');
  for (var i = 0; i < tcells.length; i++)
    tcells[i].addEventListener('click', function () { tttMove(+this.getAttribute('data-ttt')); });
  var ccells = body.querySelectorAll('button[data-c4]');
  for (var j = 0; j < ccells.length; j++)
    ccells[j].addEventListener('click', function () { c4Move(+this.getAttribute('data-c4')); });
  var qa = body.querySelectorAll('button[data-tqa]');
  for (var k = 0; k < qa.length; k++)
    qa[k].addEventListener('click', function () { triviaAnswer(+this.getAttribute('data-tqa')); });
  var ts = body.querySelectorAll('button[data-trivstart]');
  for (var m = 0; m < ts.length; m++)
    ts[m].addEventListener('click', function () { triviaStart(openGameId); });
  var sb = body.querySelectorAll('button.gstartbtn');
  for (var n = 0; n < sb.length; n++)
    sb[n].style.cssText = 'background:#3b5bd6;border:none;color:#fff;border-radius:8px;padding:8px 18px;font-size:14px;';
}
function bindGames() {
  $('gamebtn').innerHTML = '🎮<span class="dot" style="display:none">●</span>';
  $('gamebtn').addEventListener('click', function () {
    $('gamespanel').classList.contains('open') ? closeGames() : openGames();
  });
  $('gclose').addEventListener('click', closeGames);
  $('bclose').addEventListener('click', closeBoard);
  $('gstart-ttt').addEventListener('click', function () { startGame('tictactoe'); });
  $('gstart-c4').addEventListener('click', function () { startGame('connect4'); });
  $('gstart-trivia').addEventListener('click', function () { startGame('trivia'); });
}
function clearGames() {
  games = {}; gstates = {}; ganswers = {}; openGameId = null;
  for (var id in triviaTimers) clearTimeout(triviaTimers[id]);
  triviaTimers = {};
  closeGames(); closeBoard();
}

/* ---------------- input: joystick / look / tap / keys ---------------- */
var keys = {};
var joyEl, stickEl, joyId = null, joyVec = { x: 0, y: 0 };
var lookId = null, lookLast = null, downPos = null, downTime = 0;

function bindKeys() {
  addEventListener('keydown', function (e) {
    if (document.activeElement && document.activeElement.tagName === 'INPUT') return;
    keys[e.key.toLowerCase()] = true;
  });
  addEventListener('keyup', function (e) { keys[e.key.toLowerCase()] = false; });
}
function joyCenter() {
  var r = joyEl.getBoundingClientRect();
  return { x: r.left + r.width / 2, y: r.top + r.height / 2, r: r.width / 2 };
}
function joyMove(e) {
  var c = joyCenter(), max = c.r - 6;
  var dx = e.clientX - c.x, dy = e.clientY - c.y;
  var len = Math.hypot(dx, dy);
  if (len > max) { dx = dx / len * max; dy = dy / len * max; }
  joyVec.x = dx / max; joyVec.y = dy / max;
  stickEl.style.transform = 'translate(' + dx + 'px,' + dy + 'px)';
}
function bindJoy() {
  joyEl = $('joy'); stickEl = $('stick');
  joyEl.addEventListener('pointerdown', function (e) {
    joyId = e.pointerId;
    try { joyEl.setPointerCapture(e.pointerId); } catch (_) {}
    joyMove(e); e.preventDefault();
  });
  joyEl.addEventListener('pointermove', function (e) { if (e.pointerId === joyId) joyMove(e); });
  var end = function (e) {
    if (e.pointerId !== joyId) return;
    joyId = null; joyVec.x = 0; joyVec.y = 0;
    stickEl.style.transform = 'translate(0px,0px)';
  };
  joyEl.addEventListener('pointerup', end);
  joyEl.addEventListener('pointercancel', end);
}
function bindLook() {
  var cv = renderer.domElement;
  cv.addEventListener('pointerdown', function (e) {
    lookId = e.pointerId;
    lookLast = { x: e.clientX, y: e.clientY };
    downPos = { x: e.clientX, y: e.clientY };
    downTime = Date.now();
    try { cv.setPointerCapture(e.pointerId); } catch (_) {}
  });
  cv.addEventListener('pointermove', function (e) {
    if (e.pointerId !== lookId || !lookLast) return;
    yaw -= (e.clientX - lookLast.x) * 0.0052;
    pitch -= (e.clientY - lookLast.y) * 0.0052;
    if (pitch > 1.25) pitch = 1.25;
    if (pitch < -1.25) pitch = -1.25;
    lookLast = { x: e.clientX, y: e.clientY };
  });
  var up = function (e) {
    if (e.pointerId !== lookId) return;
    lookId = null; lookLast = null;
    if (downPos && Date.now() - downTime < 280 &&
        Math.hypot(e.clientX - downPos.x, e.clientY - downPos.y) < 14)
      onTap(e.clientX, e.clientY);
    downPos = null;
  };
  cv.addEventListener('pointerup', up);
  cv.addEventListener('pointercancel', function (e) {
    if (e.pointerId === lookId) { lookId = null; lookLast = null; downPos = null; }
  });
}
function bindChat() {
  $('sendbtn').addEventListener('click', sendChat);
  $('chatin').addEventListener('keydown', function (e) { if (e.key === 'Enter') sendChat(); });
}
function onTap(cx, cy) {
  var r = renderer.domElement.getBoundingClientRect();
  pointer.x = ((cx - r.left) / r.width) * 2 - 1;
  pointer.y = -((cy - r.top) / r.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  var meshes = [];
  interactives.forEach(function (v) { v.meshes.forEach(function (m) { meshes.push(m); }); });
  portals.forEach(function (p) { meshes.push(p.mesh); });
  var hits = raycaster.intersectObjects(meshes, false);
  if (!hits.length) return;
  var ud = hits[0].object.userData;
  if (ud.def && ud.def.indexOf('OBJ_') === 0) toggleObject(ud.def.slice(4));
  else if (ud.portal) setRoom(ud.portal);
  hideHint();
}
function updatePlayer(dt) {
  var f = 0, s = 0;
  if (keys['w'] || keys['arrowup']) f += 1;
  if (keys['s'] || keys['arrowdown']) f -= 1;
  if (keys['a'] || keys['arrowleft']) s -= 1;
  if (keys['d'] || keys['arrowright']) s += 1;
  f += -joyVec.y; s += joyVec.x;
  var len = Math.hypot(f, s);
  if (len > 1) { f /= len; s /= len; }
  var sp = 3.4 * dt, sin = Math.sin(yaw), cos = Math.cos(yaw);
  player.x += (-sin * f + cos * s) * sp;
  player.z += (-cos * f - sin * s) * sp;
  var d = Math.hypot(player.x, player.z);
  if (d > BOUND) { player.x *= BOUND / d; player.z *= BOUND / d; }
}

/* ---------------- fallback room (shown until a 30030 arrives) ---------------- */
function fallbackVRML(id) {
  var target = (id === 'lobby') ? 'garden' : 'lobby';
  var L = [];
  L.push('# AgentWorld fallback grand lobby');
  L.push('Viewpoint { position 0 1.7 8 orientation 0 1 0 0 description "spawn" }');
  L.push('DirectionalLight { direction 0.25 -1 0.3 intensity 0.8 color 1 0.96 0.9 }');
  L.push('PointLight { location 0 4.2 -1 intensity 0.8 color 1 0.85 0.6 }');
  L.push('PointLight { location 0 2.6 -8.2 intensity 0.5 color 0.3 0.9 0.9 }');
  function T(x, y, z, geo, dc, ec) {
    L.push('Transform { translation ' + x + ' ' + y + ' ' + z + ' children [');
    L.push('  Shape { appearance Appearance { material Material { diffuseColor ' + dc +
      (ec ? ' emissiveColor ' + ec : '') + ' } } geometry ' + geo + ' } ] }');
  }
  T(0, -0.1, 0, 'Box { size 24 0.2 24 }', '0.10 0.11 0.14');
  T(0, 0.02, -1, 'Cylinder { radius 2.3 height 0.05 }', '0.42 0.07 0.10');
  T(0, 0.03, 3.9, 'Box { size 3 0.04 8.6 }', '0.48 0.07 0.11');
  T(0, 6.3, 0, 'Box { size 24 0.3 24 }', '0.07 0.07 0.09');
  T(0, 6.12, -1, 'Box { size 6 0.12 6 }', '0.9 0.95 1.0', '0.55 0.6 0.65');
  [[-6, -6], [6, -6], [-6, 4], [6, 4]].forEach(function (c) {
    T(c[0], 0.25, c[1], 'Box { size 1.3 0.5 1.3 }', '0.50 0.46 0.42');
    T(c[0], 2.95, c[1], 'Cylinder { radius 0.42 height 4.9 }', '0.58 0.55 0.50');
    T(c[0], 5.6, c[1], 'Box { size 1.2 0.4 1.2 }', '0.50 0.46 0.42');
  });
  T(-7.2, 3, -10, 'Box { size 9.6 6 0.4 }', '0.20 0.16 0.24');
  T(7.2, 3, -10, 'Box { size 9.6 6 0.4 }', '0.20 0.16 0.24');
  T(0, 5.3, -10, 'Box { size 4.8 1.4 0.4 }', '0.20 0.16 0.24');
  T(-10, 3, 0, 'Box { size 0.4 6 24 }', '0.18 0.15 0.22');
  T(10, 3, 0, 'Box { size 0.4 6 24 }', '0.18 0.15 0.22');
  // chandelier (interactive)
  L.push('DEF OBJ_chandelier Transform { translation 0 0 -1 children [');
  L.push('  Transform { translation 0 4.45 0 children [ Shape { appearance Appearance { material Material { diffuseColor 0.72 0.58 0.30 emissiveColor 0.30 0.22 0.08 } } geometry Cylinder { radius 1.15 height 0.1 } } ] }');
  L.push('  Transform { translation 0 4.15 0 children [ Shape { appearance Appearance { material Material { diffuseColor 1.0 0.9 0.6 emissiveColor 0.9 0.65 0.2 } } geometry Sphere { radius 0.28 } } ] }');
  L.push('] }');
  // orb pedestal + orb (interactive)
  T(0, 0.35, -1, 'Cylinder { radius 0.8 height 0.7 }', '0.55 0.51 0.46');
  T(0, 0.85, -1, 'Cylinder { radius 0.5 height 0.35 }', '0.60 0.56 0.50');
  L.push('DEF OBJ_orb Transform { translation 0 1.75 -1 children [');
  L.push('  Shape { appearance Appearance { material Material { diffuseColor 1.0 0.78 0.30 emissiveColor 1.0 0.62 0.15 } } geometry Sphere { radius 0.45 } } ] }');
  // portal arch to the other room
  L.push('Anchor { url "nostr:room:' + target + '" children [');
  L.push('  Transform { translation 0 2.15 -9.85 children [ Shape { appearance Appearance { material Material { diffuseColor 0.10 0.55 0.60 emissiveColor 0.08 0.45 0.50 } } geometry Box { size 3.4 4.3 0.15 } } ] }');
  L.push('  Transform { translation -2.05 2.3 -9.85 children [ Shape { appearance Appearance { material Material { diffuseColor 0.72 0.58 0.30 } } geometry Box { size 0.5 4.6 0.5 } } ] }');
  L.push('  Transform { translation 2.05 2.3 -9.85 children [ Shape { appearance Appearance { material Material { diffuseColor 0.72 0.58 0.30 } } geometry Box { size 0.5 4.6 0.5 } } ] }');
  L.push('  Transform { translation 0 4.75 -9.85 children [ Shape { appearance Appearance { material Material { diffuseColor 0.72 0.58 0.30 } } geometry Box { size 4.6 0.5 0.5 } } ] }');
  L.push('] }');
  return L.join('\n');
}

/* ---------------- main loop ---------------- */
function animate() {
  requestAnimationFrame(animate);
  var dt = Math.min(clock.getDelta(), 0.05);
  updatePlayer(dt);
  camera.position.set(player.x, EYE, player.z);
  camera.rotation.y = yaw;
  camera.rotation.x = pitch;
  camera.rotation.z = 0;
  if (orbMesh) {
    var s = 1 + 0.07 * Math.sin(performance.now() / 1000 * 2.4);
    orbMesh.scale.set(s, s, s);
  }
  var now = Date.now(), changed = false;
  peers.forEach(function (peer, key) {
    if (now - peer.lastSeen > 35000) {
      peerGroup.remove(peer.avatar);
      disposeGroup(peer.avatar);
      peers.delete(key);
      sysLine(peer.name + ' left');
      changed = true;
      return;
    }
    peer.avatar.position.set(peer.x, 0, peer.z);
    peer.avatar.rotation.y = peer.yaw;
  });
  if (changed) updateOnline();
  renderer.render(scene, camera);
}

/* ---------------- ui ---------------- */
function hideHint() {
  var h = $('hint');
  if (h) h.style.display = 'none';
  try { localStorage.setItem('aw_seen', '1'); } catch (e) {}
}

async function init() {
  initThree();
  bindKeys();
  bindJoy();
  bindLook();
  bindChat();
  bindHist();
  bindSettings();
  bindGames();
  refreshLogin();
  $('roomname').textContent = 'room: ' + roomId;
  var seen = false;
  try { seen = !!localStorage.getItem('aw_seen'); } catch (e) {}
  if (seen) hideHint(); else setTimeout(hideHint, 10000);
  buildScene(fallbackVRML(roomId));   // instant local room; replaced when 30030 arrives
  sysLine('welcome to AgentWorld — waiting for the live room…');
  if (!loggedIn) sysLine('guest mode: open ⚙️ and enter your npub + an agent npub to log in');
  try {
    await initIdentity();
  } catch (e) { sysLine('identity error: ' + e.message); return; }
  setSubs();
  connectRelays();
  if (loggedIn) resolveProfile();   // fetch our kind-0 name + picture
  setInterval(publishPresence, 10000);
  animate();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
else init();

/* Headless QA hook — only exposed with ?awtest=1 in the URL. Lets automated
 * smoke tests drive the game lobby (read sessions, inject remote events)
 * without touching network or identity code paths. */
try {
  if (new URLSearchParams(location.search).get('awtest') === '1') {
    window.AWTEST = {
      games: function () { return games; },
      gstates: function () { return gstates; },
      myPub: function () { return myPubHex; },
      onGameSession: onGameSession,
      onGameState: onGameState,
      renderGameList: renderGameList
    };
  }
} catch (e) {}

})();
