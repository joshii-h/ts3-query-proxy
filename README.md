# ts3-query-proxy

A translation layer that bridges the legacy TeamSpeak 3 ServerQuery raw protocol (TCP port 10011) to TeamSpeak 6's SSH Query interface (TCP port 10022).

## Why?

TeamSpeak 6 dropped support for the raw ServerQuery protocol on port 10011. Many existing tools (like TS3MusicBot) rely on this protocol. This proxy sits in front of TS6 and transparently translates raw query connections to SSH query sessions, requiring zero changes to existing tools.

## How it works

```
TS3MusicBot ──TCP:10011──▶ ts3-query-proxy ──SSH:10022──▶ TeamSpeak 6
              (raw query)                     (ssh query)
```

1. Client connects to the proxy on TCP port 10011
2. Proxy sends the standard TS3 ServerQuery welcome banner
3. Client sends `login serveradmin <password>`
4. Proxy captures credentials and opens an SSH session to TS6
5. All subsequent commands are proxied bidirectionally

## Quick start (Docker)

```bash
docker compose up -d
```

The proxy expects a TeamSpeak 6 server reachable at hostname `teamspeak6` on port `10022` (SSH query). Adjust via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TS6_HOST` | `teamspeak6` | TS6 server hostname |
| `TS6_SSH_PORT` | `10022` | TS6 SSH query port |
| `LISTEN_PORT` | `10011` | Port the proxy listens on |

## Docker Compose example

```yaml
services:
  ts3query-proxy:
    image: ghcr.io/yourusername/ts3-query-proxy:latest
    # or: build: .
    restart: unless-stopped
    ports:
      - "10011:10011"
    environment:
      - TS6_HOST=teamspeak6
      - TS6_SSH_PORT=10022
    networks:
      - your_ts6_network

networks:
  your_ts6_network:
    external: true
```

## License

MIT
