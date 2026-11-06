# openbekci-agent

The OpenBekci on-site access agent. It runs on a Raspberry-Pi-class box (or the guard PC) on the site LAN, hears plate cameras and readers, opens the gate or door, and **keeps deciding when the internet is down**. It is the hands of the access-control module of [OpenBekci](https://github.com/ekremyk2/OpenBekci); the design is `docs/plans/07-access-control.md` in that repository.

- Outbound connections only: a WebSocket to your server (HTTPS long-poll when a proxy blocks the upgrade). No inbound ports from outside the LAN.
- Offline-first: it holds an encrypted copy of the allow-list, decides locally, logs every decision, and syncs the log when the server is reachable again.
- Single static binary, no CGO: `linux/arm64`, `linux/amd64`, `windows/amd64`.
- Licence: AGPL-3.0 (see `LICENSE`).

## Install

Download the archive for your platform from the releases page, then on Linux:

```sh
sudo useradd --system --home /var/lib/openbekci-agent --shell /usr/sbin/nologin openbekci-agent
sudo usermod -aG dialout openbekci-agent          # USB / serial relay boards
sudo usermod -aG gpio openbekci-agent             # Raspberry Pi GPIO (when that driver exists)
sudo install -m 0755 openbekci-agent /usr/local/bin/
sudo install -d -m 0750 -o root -g openbekci-agent /etc/openbekci-agent
sudo install -m 0640 -g openbekci-agent agent.example.yaml /etc/openbekci-agent/agent.yaml   # edit it
sudo install -m 0644 openbekci-agent.service /etc/systemd/system/
```

## Enrol

In the web admin (site access settings) create an agent; you get a one-time token (`obk_enr_...`, valid 15 minutes). Then, as the service user:

```sh
sudo -u openbekci-agent openbekci-agent enrol --server https://bekci.example.org --token obk_enr_XXXX
sudo systemctl enable --now openbekci-agent
```

Enrolment stores the long-lived agent credential in `<state_dir>/agent.token` (mode 0600, never in `agent.yaml`) before it reports success. On Windows the mode bits mean nothing, so the agent replaces the ACL of the state directory (and of the token, identity, key and database in it) with a protected DACL that grants full control to SYSTEM and to the account the agent runs as, and to nobody else (no inheritance from `ProgramData`, so the `Users` group cannot read it). Run the service under a dedicated account; Administrators can still take ownership, as root can on Linux. A server with a private CA works by putting the CA certificate in `ca_file`; certificate verification can not be turned off.

By default the token alone identifies the site (`POST /v1/agent/enrol`). If your server only offers the org/site scoped endpoint, add `--org <id> --site <id>`.

## Run

```sh
openbekci-agent run                       # foreground service (what systemd starts)
openbekci-agent status                    # enrolment, allow-list version, queue depth, drivers, last contact
openbekci-agent config check              # validate agent.yaml and build every driver (touches no hardware)
openbekci-agent rotate-token              # replace the token now (the old one lives 10 more minutes)
openbekci-agent version
```

The service also rotates its token by itself within 14 days of the server's `rotate_by` (default 180 days) and whenever the manager forces it.

Configuration is `agent.yaml` (see `deploy/agent.example.yaml`); every key has an `OPENBEKCI_AGENT_*` override (`SERVER`, `STATE_DIR`, `CA_FILE`, `LOG_LEVEL`, `OFFLINE_GRACE_HOURS`, `CONFIG`).

### Try it without hardware

```sh
openbekci-agent run --mock --mock-open-log /tmp/opens.log
curl -X POST http://127.0.0.1:8099/present -d '{"instance":"gate-cam","channel":"in","kind":"plate","value":"34 ABC 123"}'
```

`--mock` ignores the configured drivers and routes every driver instance named by an access point to one scriptable mock (`--mock-script` plays `[{after_ms, instance, channel, kind, value}]`, `--mock-loop` repeats it, `--mock-open-log` records every open). The agent still has to be enrolled against a server (the integration tests use the in-repo fake server instead).

## Drivers

Hardware is declared under `drivers:` in `agent.yaml`; the server's access points refer to an instance by `driver_ref.instance` (+ `channel`). Reading and opening are separate instances: a plate camera and the relay that lifts the barrier. A `points:` entry pairs a reader instance with the opener where they differ; otherwise a point is opened through its own instance.

| type | direction | notes |
|---|---|---|
| `relay` | open | Pulse = on, wait `pulse_ms` (100-10 000, default 800), off; **off is always attempted**, also on cancellation and panic. `min_interval_ms` (default 2 000) refuses a second pulse too soon; a pulse in progress refuses another. Modes: `http` (Shelly Gen1 `.../relay/0?turn=on&timer=1`, Gen2 RPC, or any URL pair; LAN/private addresses only; omit `off_url` when the device resets itself), `serial` (hex frames per channel written to the device file; the line speed is **not** configured by the agent in this release), `gpio` (config is validated, switching is a stub that reports an error) |
| `platecam` | read | Only the `mock` adapter exists; the brand adapter is added once the first site's camera is known. Reads below `confidence_min` (0.80) become `deny / unknown` without acting; the same plate on the same lane within `dedupe_s` (30 s) is ignored |
| `mock` | both | For tests and demos |

Adding a driver is one line in `cmd/openbekci-agent/drivers.go` (an explicit slice, no `init()` side effects) plus a package under `internal/driver/`.

## Offline behaviour

- The agent decides from its last allow-list (snapshot plus deltas), in **its own clock** and the site timezone, and logs every decision (allow and deny) to a local SQLite queue that survives power loss.
- A credential that **expires** while offline denies exactly as it would online. A credential that is **revoked** while offline keeps working until contact returns, bounded by the grace period: the accepted trade-off of offline-first.
- **Grace period:** `offline_grace_hours` (the site setting, default 72) counts from the last authenticated server contact. After it the agent is *stopped*: it opens nothing, decisions are still logged as `deny / agent_stopped`, and it keeps reconnecting; contact resumes it.
- On reconnect: configuration and allow-list first, then the queued events in order (batches of up to 100, at most 5 in flight), each keeping its original id and time. Duplicates are harmless.
- Guard "open" commands arrive only on the live connection, carry a 15 s expiry (60 s maximum) and are executed once per command id.
- Revocation (`command revoked`, a 4401 close or any HTTP 401): the allow-list, queue, configuration and token are wiped, the agent exits with status 3 and refuses to start until enrolled again.
- At rest only plates and hashes are stored, plates encrypted per row with AES-256-GCM under `<state_dir>/store.key` (mode 0600). This protects a casually copied database, not root on the box.
- Logs contain event, point, credential and command ids, never plates (unless `log_level: debug`, which warns at start).

## Updating

Replace the binary and restart the service (`systemctl restart openbekci-agent`); the state directory is compatible across versions of protocol v1. The server lists each agent's version. Opt-in auto-update (cosign-verified, at the site's maintenance hour) is planned and not part of this release.

## Development

```sh
go tool task test           # go test ./...
go tool task lint           # go vet + golangci-lint
go tool task build:linux-arm64
```

Go 1.27, no CGO required (the race detector needs a C toolchain: `go tool task test:race`). Layout:

```
cmd/openbekci-agent   CLI (enrol, run, status, rotate-token, config check, version)
internal/protocol     envelope and message types, validation; testdata/protocol/v1 are the shared conformance fixtures
internal/transport    WebSocket + long-poll client, backoff, TLS, enrol/rotate calls
internal/store        SQLite store (WAL), encryption, delta/snapshot apply, event queue, command cache
internal/engine       decision engine, plate normalization, recurring windows
internal/driver       driver interface, mock, relay, platecam
internal/agent        wiring: hello, sync, events, commands, rotation, revocation
internal/fakeserver   the server side of the protocol for tests
```

The integration tests in `internal/agent` run the real agent against `internal/fakeserver` over TLS WebSocket and long-poll: enrolment, snapshot and deltas with a gap, event batching and redelivery after a restart, offline decisions and reconciliation, grace and stop, command expiry and replay, revocation wipe and token rotation. `testdata/protocol/v1/*.json` are regenerated with `go tool task fixtures:update`.
