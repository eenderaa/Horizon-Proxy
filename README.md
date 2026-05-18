# Horizon Local Proxy

A localhost-first browser web proxy inspired by projects like Utopia and Interstellar, built for legitimate personal testing, development, and access through a browser you control.

## Run

```powershell
npm.cmd install
npm.cmd start
```

Then open `http://127.0.0.1:8080`.

## Configuration

- `PORT=3000 npm.cmd start` changes the port.
- `HOST=0.0.0.0 npm.cmd start` binds outside localhost.
- `ALLOW_PRIVATE=1 npm.cmd start` allows private-network and localhost targets.
- `DEBUG_PROXY=1 npm.cmd start` logs proxied upstream requests while debugging.

By default, Horizon blocks private and local-network targets to avoid turning the server into an unsafe open relay. Use it only on networks and sites where you have permission, and do not rely on it as an anonymity or security tool.

## Site compatibility

Horizon now handles root-relative app navigation used by sites like YouTube, so search and watch pages can load instead of falling back to local 404s. Full video playback on YouTube may still fail because `googlevideo.com` signed media streams can reject server-side fetchers with `403`; that is an upstream media-token/TLS behavior, not an ordinary missing HTML rewrite.
