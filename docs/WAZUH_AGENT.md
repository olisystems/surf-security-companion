# Wazuh agent path (SOC Phase 2b)

The portal correlates **two** event streams in the same `surf-events-*` index:

1. **Application logs** — Vector on VPS1 ships Caddy access logs, Keycloak
   events, backend audit lines and `auth.log` (Phase 2a, `docs/INGEST.md`).
2. **Host telemetry** — the **Wazuh agent** on VPS1 (FIM, rootcheck, SCA/CIS,
   syscollector, its own sshd rules) reports to the manager on VPS2; the
   manager's `alerts.json` is mirrored into the index by a second Vector
   instance on VPS2 (`observability/vector-soc.yaml`).

```
VPS1 (prod)                           VPS2 (SOC)
wazuh-agent ──1514 (TLS)──wg0 tunnel──► wazuh-manager ──alerts.json──► vector ──► POST /ingest/events
   enrolment 1515 (once)   10.44.0.2 → 10.44.0.1                                    │
                                                                       surf-events-* → R-21 / R-22 → incidents
```

## Network

- WireGuard tunnel: VPS2 `wg0 10.44.0.1/24` (server, UDP 51820, ufw allows only
  the VPS1 address), VPS1 `10.44.0.2/24` (client, PersistentKeepalive 25).
  Set-up scripts live in the SURF repo (`scripts/soc/wg-setup.sh`).
- `docker-compose.prod.yml` publishes 1514/1515 **only on 10.44.0.1**. Docker
  bypasses ufw, so the bind address is the guard. `wg-quick@wg0` must be
  enabled at boot; until the address exists Docker keeps restarting the manager.
- Enrolment (`wazuh-authd`, 1515) runs **without** a password: it is reachable
  only through the tunnel, and an agent needs the tunnel keys first.

## Agent configuration

The host-side `ossec.conf` on VPS1 only names the manager (`10.44.0.1`) and
the agent name (`vps1-prod`). Everything else comes from the manager's
centralised group config `wazuh/shared/default/agent.conf` (mounted via the
config-mount mechanism), pushed to the agent on enrolment and on every change:

| Module | What it covers on VPS1 |
|---|---|
| syscheck (FIM) | realtime + diffs: `/opt/surf`, `/root/.ssh`, `/etc/wireguard`, `/etc/ssh`; 6-hourly: `/etc`, `/usr/local/bin`; secrets (`.env`, `wg0.conf`) hashed but never diffed (`nodiff`) |
| rootcheck | rootkit files/trojans, hidden pids/ports (12 h) |
| SCA | CIS benchmark for Ubuntu (12 h) — the automated SEC-SSH audit |
| syscollector | hardware/os/packages/ports/processes hourly → manager vulnerability detection against CVE feeds |
| localfile | `/var/log/auth.log` for Wazuh's sshd rules (intentional duplicate of the Vector path, needed for Active Response) |

## Alerts → portal

`observability/vector-soc.yaml` tails `/var/ossec/logs/alerts/alerts.json` and
maps every alert to flat ECS: `observer.product=wazuh`,
`observer.service=<first rule group>`, `wazuh.rule.{id,level,description,groups}`,
`event.severity`, `host.name=<agent>`, `source.ip`/`user.name` from `data.*`,
`file.path` + `wazuh.syscheck.event` for FIM, `message` (truncated full_log).
It also ships VPS2's own `auth.log` (`host.name=vps2`) so R-19 covers both hosts.

Sigma rules consuming the stream:

- **R-21** — any Wazuh alert with level 10–15 → high.
- **R-22** — syscheck alert touching `/opt/surf/`, `/root/.ssh/`, `/etc/wireguard/`,
  `/etc/ssh/`, `/etc/sudoers` → medium (every change is reviewed; change windows later).

## Operations

```bash
C="docker compose -f docker-compose.yml -f docker-compose.prod.yml"
$C exec wazuh-manager /var/ossec/bin/agent_control -l          # enrolled agents + status
$C exec wazuh-manager /var/ossec/bin/agent_control -r -a       # force syscheck/rootcheck run on all agents
$C exec wazuh-manager /var/ossec/bin/agent_groups -l -g default # agents in the default group
$C logs --since=10m vector | grep -c '"accepted"'               # mirror activity (also in backend "ingest batch" logs)
```

- Agent side (VPS1): `systemctl status wazuh-agent`, `/var/ossec/bin/agent_control -i 001`,
  logs in `/var/ossec/logs/ossec.log`. Re-enrol: stop agent, delete `/var/ossec/etc/client.keys`,
  start agent (manager purges stale keys, `<purge>yes</purge>`).
- **Active Response** for R-16 (block the brute-forcing IP for 1 h at the agent's
  firewall) is defined in `wazuh/ossec.conf` but `<disabled>yes</disabled>`.
  Enable it only after R-16 has fired a few times without false positives:
  set `disabled` to `no`, `$C restart wazuh-manager`.
- `.env` on VPS2 needs `INGEST_TOKEN` (Phase 2a) — the mirror reuses it.
