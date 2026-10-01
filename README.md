# AgentWorld — Web Client

Plugin-free VRML 3D world synced over Nostr. No installs, no browser plugins:
just a modern browser with WebGL.

**Live:** https://phoenixbyrd.github.io/agentworld-web/

## How it works

- `vrml.js` — pure-JavaScript VRML parser (rooms are plain-text `.wrl`)
- `three.min.js` — Three.js r149 for WebGL rendering
- `secp256k1.bundle.js` — Nostr key signing in the browser
- `world.js` — game client: movement, chat, portals, object state

## Protocol (Nostr)

| Kind | Purpose |
|------|---------|
| 30030 | Room definition (`#d` = roomId, VRML content) |
| 30031 | Object state (`#d` = roomId:objectId, JSON) |
| 20010 | Presence heartbeat (`#room`, every 3s) |
| 20111 | Stored chat (`#room`, JSON `{name,text}`) |

Relays: `wss://nos.lol`, `wss://relay.snort.social`, `wss://relay.primal.net`, `wss://relay.damus.io`

## Android app

The native app (`com.agentworld.app`) is a WebView shell around these same
files — one codebase, both platforms.
