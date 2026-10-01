/* AgentWorld vrml.js — VRML97 subset parser.
 * Plain script (no modules). Requires global THREE (Matrix4/Vector3/Quaternion).
 * Exposes: parseVRML(text) -> { viewpoints, lights, objects }
 *
 * Supported nodes:
 *   Transform { translation | rotation | scale | scaleOrientation | children [ ... ] }
 *   Group { children [ ... ] }
 *   Shape { appearance Appearance { material Material {
 *             diffuseColor | emissiveColor | transparency } }
 *           geometry (Box { size } | Sphere { radius } |
 *                     Cylinder { radius height } | Cone { bottomRadius height }) }
 *   Viewpoint { position | orientation | description }
 *   Anchor { url | children [ ... ] }          (shapes inside inherit anchor url)
 *   DirectionalLight { direction | intensity | color }
 *   PointLight { location | intensity | color }
 *   DEF Name <node>  — def name captured on the node; shapes inherit the
 *                      nearest enclosing DEF (used for DEF OBJ_<id> interactives).
 * '#' starts a comment. All fields optional with VRML97-ish defaults.
 */
(function (global) {
'use strict';

function parseVRML(text) {
  var P = { toks: tokenize(text), pos: 0 };
  var S = { viewpoints: [], lights: [], objects: [] };
  var I = new THREE.Matrix4();
  while (P.pos < P.toks.length) parseStatement(P, S, I, null, null);
  return S;
}

/* ---------------- tokenizer ---------------- */
function tokenize(text) {
  var toks = [], i = 0, n = text.length;
  while (i < n) {
    var c = text.charAt(i);
    if (c === '#') { while (i < n && text.charAt(i) !== '\n') i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === ',') { i++; continue; }
    if (c === '"') {
      var s = '', j = i + 1;
      while (j < n) {
        var d = text.charAt(j);
        if (d === '\\' && j + 1 < n) { s += text.charAt(j + 1); j += 2; continue; }
        if (d === '"') break;
        s += d; j++;
      }
      if (j >= n) throw new Error('VRML: unterminated string');
      toks.push({ t: 'str', v: s }); i = j + 1; continue;
    }
    if (c === '{' || c === '}' || c === '[' || c === ']') { toks.push({ t: c, v: c }); i++; continue; }
    var rest = text.slice(i);
    var m = /^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?/.exec(rest);
    if (m) { toks.push({ t: 'num', v: parseFloat(m[0]) }); i += m[0].length; continue; }
    var m2 = /^[A-Za-z_][A-Za-z0-9_\-\.]*/.exec(rest);
    if (m2) { toks.push({ t: 'word', v: m2[0] }); i += m2[0].length; continue; }
    throw new Error('VRML: unexpected character ' + JSON.stringify(c) + ' at offset ' + i);
  }
  return toks;
}

/* ---------------- token helpers ---------------- */
function peek(P) { return P.pos < P.toks.length ? P.toks[P.pos] : null; }
function next(P) { var t = peek(P); if (!t) throw new Error('VRML: unexpected end of input'); P.pos++; return t; }
function accept(P, ch) { var t = peek(P); if (t && t.t === ch) { P.pos++; return true; } return false; }
function expect(P, ch) {
  var t = next(P);
  if (!t || t.t !== ch) throw new Error('VRML: expected "' + ch + '", got ' + (t ? (t.v !== undefined ? t.v : t.t) : 'EOF'));
}
function expectWord(P) { var t = next(P); if (t.t !== 'word') throw new Error('VRML: expected identifier, got ' + t.v); return t.v; }
function parseNum(P) { var t = next(P); if (t.t !== 'num') throw new Error('VRML: expected number, got ' + t.v); return t.v; }
function parseStr(P) { var t = next(P); if (t.t !== 'str') throw new Error('VRML: expected string, got ' + t.v); return t.v; }
function parseVec3(P) { return [parseNum(P), parseNum(P), parseNum(P)]; }
function parseRot(P) { return [parseNum(P), parseNum(P), parseNum(P), parseNum(P)]; }

function skipBraced(P) {           // opening '{' already consumed
  var d = 0;
  for (;;) {
    var t = next(P);
    if (t.t === '{') d++;
    else if (t.t === '}') { if (d === 0) break; d--; }
  }
}
function skipFieldValue(P) {
  var t = peek(P); if (!t) return;
  if (t.t === '{') { next(P); skipBraced(P); }
  else if (t.t === '[') {
    next(P); var d = 0;
    for (;;) { var u = next(P); if (u.t === '[') d++; else if (u.t === ']') { if (d === 0) break; d--; } }
  }
  else next(P);                    // number, string, TRUE/FALSE/NULL, identifier
}
function skipNodeBody(P) { if (accept(P, '{')) skipBraced(P); }

/* ---------------- math helpers ---------------- */
function quatFromAxisAngle(ax) {
  var v = new THREE.Vector3(ax[0], ax[1], ax[2]);
  if (v.lengthSq() < 1e-12) return new THREE.Quaternion();
  v.normalize();
  return new THREE.Quaternion().setFromAxisAngle(v, ax[3]);
}
function composeMatrix(parentM, tr, rot, sc, so) {
  var mT = new THREE.Matrix4().makeTranslation(tr[0], tr[1], tr[2]);
  var mR = new THREE.Matrix4().makeRotationFromQuaternion(quatFromAxisAngle(rot));
  var mSO = new THREE.Matrix4().makeRotationFromQuaternion(quatFromAxisAngle(so));
  var mS = new THREE.Matrix4().makeScale(sc[0], sc[1], sc[2]);
  var m = new THREE.Matrix4();
  m.copy(parentM).multiply(mT).multiply(mR).multiply(mSO).multiply(mS).multiply(mSO.clone().invert());
  return m;
}
function xformPoint(parentM, p) {
  var v = new THREE.Vector3(p[0], p[1], p[2]).applyMatrix4(parentM);
  return [v.x, v.y, v.z];
}
function xformDir(parentM, d) {
  var q = new THREE.Quaternion().setFromRotationMatrix(parentM);
  var v = new THREE.Vector3(d[0], d[1], d[2]).applyQuaternion(q);
  if (v.lengthSq() < 1e-12) return [0, 0, -1];
  v.normalize();
  return [v.x, v.y, v.z];
}

/* ---------------- statements ---------------- */
function parseStatement(P, S, parentM, anchor, def) {
  var t = peek(P);
  if (!t) return;
  if (t.t === 'word' && t.v === 'DEF') { next(P); def = expectWord(P); t = peek(P); }
  if (!t || t.t !== 'word') throw new Error('VRML: expected node, got ' + (t ? t.v : 'EOF'));
  var type = next(P).v;
  if (type === 'USE') { expectWord(P); return; }
  if (type === 'ROUTE') { next(P); next(P); next(P); return; } // ROUTE a.b TO c.d
  switch (type) {
    case 'Transform': parseTransform(P, S, parentM, anchor, def); break;
    case 'Group': parseGroup(P, S, parentM, anchor, def); break;
    case 'Shape': parseShape(P, S, parentM, anchor, def); break;
    case 'Viewpoint': parseViewpoint(P, S, parentM); break;
    case 'Anchor': parseAnchor(P, S, parentM, anchor, def); break;
    case 'DirectionalLight': parseDirLight(P, S, parentM); break;
    case 'PointLight': parsePointLight(P, S, parentM); break;
    default: skipNodeBody(P); break;   // unknown node type
  }
}

// children blocks are copied as token slices and parsed with a fresh cursor,
// so field order never matters and nesting can't corrupt the token position.
function parseChildTokens(P) {
  expect(P, '[');
  var start = P.pos, depth = 0;
  for (;;) {
    var t = next(P);
    if (t.t === '[') depth++;
    else if (t.t === ']') { if (depth === 0) break; depth--; }
  }
  return P.toks.slice(start, P.pos - 1); // up to (not incl.) the closing ']'
}
function parseChildBlocks(S, M, anchor, def, blocks) {
  blocks.forEach(function (btoks) {
    var P2 = { toks: btoks, pos: 0 };
    while (P2.pos < btoks.length) parseStatement(P2, S, M, anchor, def);
  });
}

function parseTransform(P, S, parentM, anchor, def) {
  expect(P, '{');
  var tr = [0, 0, 0], rot = [0, 0, 1, 0], sc = [1, 1, 1], so = [0, 0, 1, 0];
  var blocks = [];
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'translation') tr = parseVec3(P);
    else if (f === 'rotation') rot = parseRot(P);
    else if (f === 'scale') sc = parseVec3(P);
    else if (f === 'scaleOrientation') so = parseRot(P);
    else if (f === 'children') blocks.push(parseChildTokens(P));
    else skipFieldValue(P);
  }
  parseChildBlocks(S, composeMatrix(parentM, tr, rot, sc, so), anchor, def, blocks);
}

function parseGroup(P, S, parentM, anchor, def) {
  expect(P, '{');
  var blocks = [];
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'children') blocks.push(parseChildTokens(P));
    else skipFieldValue(P);
  }
  parseChildBlocks(S, parentM, anchor, def, blocks);
}

function parseAnchor(P, S, parentM, anchor, def) {
  expect(P, '{');
  var url = null, blocks = [];
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'url') {
      var t = peek(P);
      if (t && t.t === '[') { next(P); var ss = []; while (!accept(P, ']')) ss.push(parseStr(P)); url = ss[0] || null; }
      else url = parseStr(P);
    }
    else if (f === 'children') blocks.push(parseChildTokens(P));
    else if (f === 'description') parseStr(P);
    else skipFieldValue(P);
  }
  parseChildBlocks(S, parentM, url != null ? url : anchor, def, blocks);
}

function parseAppearance(P) {
  expectWord(P); // Appearance
  expect(P, '{');
  var color = [0.8, 0.8, 0.8], emissive = [0, 0, 0], transparency = 0;
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'material') {
      expectWord(P); // Material
      expect(P, '{');
      while (!accept(P, '}')) {
        var mf = expectWord(P);
        if (mf === 'diffuseColor') color = parseVec3(P);
        else if (mf === 'emissiveColor') emissive = parseVec3(P);
        else if (mf === 'transparency') transparency = parseNum(P);
        else skipFieldValue(P);
      }
    } else skipFieldValue(P);
  }
  return { color: color, emissive: emissive, transparency: transparency };
}

function parseGeometry(P) {
  var type = expectWord(P);
  expect(P, '{');
  var kind = null, params = {};
  if (type === 'Box') {
    var size = [2, 2, 2];
    while (!accept(P, '}')) { var f = expectWord(P); if (f === 'size') size = parseVec3(P); else skipFieldValue(P); }
    kind = 'box'; params = { size: size };
  } else if (type === 'Sphere') {
    var radius = 1;
    while (!accept(P, '}')) { var f2 = expectWord(P); if (f2 === 'radius') radius = parseNum(P); else skipFieldValue(P); }
    kind = 'sphere'; params = { radius: radius };
  } else if (type === 'Cylinder') {
    var r = 1, h = 2;
    while (!accept(P, '}')) { var f3 = expectWord(P); if (f3 === 'radius') r = parseNum(P); else if (f3 === 'height') h = parseNum(P); else skipFieldValue(P); }
    kind = 'cylinder'; params = { radius: r, height: h };
  } else if (type === 'Cone') {
    var br = 1, ch = 2;
    while (!accept(P, '}')) { var f4 = expectWord(P); if (f4 === 'bottomRadius') br = parseNum(P); else if (f4 === 'height') ch = parseNum(P); else skipFieldValue(P); }
    kind = 'cone'; params = { bottomRadius: br, height: ch };
  } else {
    skipBraced(P); // unknown geometry
  }
  return { kind: kind, params: params };
}

function parseShape(P, S, parentM, anchor, def) {
  expect(P, '{');
  var app = { color: [0.8, 0.8, 0.8], emissive: [0, 0, 0], transparency: 0 };
  var geo = { kind: null, params: {} };
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'appearance') app = parseAppearance(P);
    else if (f === 'geometry') geo = parseGeometry(P);
    else skipFieldValue(P);
  }
  if (!geo.kind) return;
  S.objects.push({
    def: def || null,
    kind: geo.kind,
    params: geo.params,
    color: app.color,
    emissive: app.emissive,
    transparency: app.transparency,
    matrix: parentM.clone(),
    anchor: anchor || null
  });
}

function parseViewpoint(P, S, parentM) {
  expect(P, '{');
  var pos = [0, 0, 10], ori = [0, 0, 1, 0], desc = '';
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'position') pos = parseVec3(P);
    else if (f === 'orientation') ori = parseRot(P);
    else if (f === 'description') desc = parseStr(P);
    else skipFieldValue(P);
  }
  var ax = xformDir(parentM, [ori[0], ori[1], ori[2]]);
  S.viewpoints.push({ position: xformPoint(parentM, pos), orientation: [ax[0], ax[1], ax[2], ori[3]], description: desc });
}

function parseDirLight(P, S, parentM) {
  expect(P, '{');
  var dir = [0, 0, -1], inten = 1, col = [1, 1, 1], on = true;
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'direction') dir = parseVec3(P);
    else if (f === 'intensity') inten = parseNum(P);
    else if (f === 'color') col = parseVec3(P);
    else if (f === 'on') on = next(P).v !== 'FALSE';
    else skipFieldValue(P);
  }
  if (on) S.lights.push({ type: 'directional', direction: xformDir(parentM, dir), intensity: inten, color: col });
}

function parsePointLight(P, S, parentM) {
  expect(P, '{');
  var loc = [0, 0, 0], inten = 1, col = [1, 1, 1], on = true;
  while (!accept(P, '}')) {
    var f = expectWord(P);
    if (f === 'location') loc = parseVec3(P);
    else if (f === 'intensity') inten = parseNum(P);
    else if (f === 'color') col = parseVec3(P);
    else if (f === 'on') on = next(P).v !== 'FALSE';
    else skipFieldValue(P);
  }
  if (on) S.lights.push({ type: 'point', location: xformPoint(parentM, loc), intensity: inten, color: col });
}

global.parseVRML = parseVRML;
})(typeof window !== 'undefined' ? window : globalThis);
