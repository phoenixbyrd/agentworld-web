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
    { id: 'aw:chat:' + r + ':' + q, purpose: 'chat', room: r, filter: { kinds: [20111], '#room': [r], limit: 60 } }
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
  var p = null;
  try { p = JSON.parse(ev.content); } catch (e) { return; }
  if (typeof p.x !== 'number' || typeof p.z !== 'number') return;
  var peer = peers.get(ev.pubkey);
  if (!peer) {
    var av = makeAvatar(p.name || 'guest');
    av.position.set(p.x, 0, p.z);
    peerGroup.add(av);
    peer = { avatar: av, name: (p.name || 'guest').slice(0, 24), x: p.x, z: p.z, yaw: p.yaw || 0, lastSeen: Date.now(), picUrl: null, picSprite: null };
    peers.set(ev.pubkey, peer);
    sysLine(peer.name + ' entered');
  } else {
    peer.x = p.x; peer.z = p.z; peer.yaw = p.yaw || 0; peer.lastSeen = Date.now();
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
function makeAvatar(name) {
  var g = new THREE.Group();
  var h = 0;
  for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  var mat = new THREE.MeshStandardMaterial({ color: new THREE.Color('hsl(' + (h % 360) + ',60%,55%)'), roughness: 0.6 });
  var body = new THREE.Mesh(new THREE.CapsuleGeometry(0.32, 0.85, 6, 14), mat);
  body.position.y = 0.95;
  g.add(body);
  var head = new THREE.Mesh(new THREE.SphereGeometry(0.26, 18, 14), mat);
  head.position.y = 1.78;
  g.add(head);
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

})();
