# Security

## Reporting a vulnerability
Please open a private security advisory on GitHub (Security → Report a vulnerability) rather than a public issue.

## Design notes
NetScope is a packet-inspection tool, so its security model is documented here:

- **Headers only.** Capture reads addresses, ports and TCP flags. Payload bytes are never read, stored or sent anywhere.
- **Privilege separation.** Only the capture helper (`netscope --capture-helper`) runs elevated. It talks to
  the unprivileged app over `127.0.0.1` using a random per-run token, only *sends* events, and never executes
  anything it receives. It exits when the app exits.
- **Local only.** The web server binds to `127.0.0.1`, rejects requests whose `Host` header isn't local
  (DNS-rebinding protection) and only accepts WebSocket connections from its own origin.
- **No telemetry.** The only network requests are: the one-off location-database download (DB-IP or MaxMind),
  map tiles from OpenStreetMap, and the Leaflet / Socket.IO / font assets the page loads from public CDNs.
  IP lookups are local; none of your connection data leaves your machine.
- **Running from source on macOS:** if the checkout lives in `~/Desktop`, `~/Documents` or `~/Downloads`
  (which macOS protects from the elevated helper), a copy of the package is staged in
  `~/Library/Application Support/NetScope/helper-src` and run as root. As with any script you run with
  `sudo`, only run code you trust. The packaged app and pip installs don't need this.
- Release builds are currently **unsigned** (macOS: ad-hoc, Windows: no Authenticode), so the OS will warn on first launch.

Only monitor networks you own or are authorised to monitor.
