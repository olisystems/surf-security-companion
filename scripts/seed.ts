/**
 * Seed script — pushes representative events into OpenSearch so that the 15 seeded
 * scenarios (R-01…R-15) fire at least once on the next scheduler tick.
 *
 * Usage: npm run seed  (reads .env for OPENSEARCH_* credentials)
 */
import { Client } from '@opensearch-project/opensearch';
import 'dotenv/config';
import { Enricher } from '../backend/src/correlation/enrichment.js';
import { DefaultReferenceData, DEMO_REFERENCE_CONFIG } from '../backend/src/correlation/enrichmentReferenceData.js';

const client = new Client({
  node: process.env['OPENSEARCH_URL'] ?? 'https://localhost:9200',
  auth: {
    username: process.env['OPENSEARCH_USERNAME'] ?? 'admin',
    password: process.env['OPENSEARCH_PASSWORD'] ?? 'admin',
  },
  ssl: { rejectUnauthorized: false }, // dev self-signed
});

type Doc = Record<string, unknown>;

const now = Date.now();
let seq = 0;
const ts = (secondsAgo: number): string => new Date(now - secondsAgo * 1000).toISOString();
const id = (): string => `seed-${now}-${(seq += 1)}`;

function base(product: string, service: string, secondsAgo: number, extra: Doc): Doc {
  return {
    '@timestamp': ts(secondsAgo),
    'event.id': id(),
    'observer.product': product,
    'observer.service': service,
    'surf.tenant.id': 'vnb-saar',
    'surf.tenant.name': 'VNB Saar Netz GmbH',
    ...extra,
  };
}

const events: Doc[] = [];

// R-01: >10 failed keycloak logins for one user within 5m
for (let i = 0; i < 12; i += 1) {
  events.push(
    base('keycloak', 'events', 120 - i, {
      'event.action': 'LOGIN_ERROR',
      'event.outcome': 'failure',
      'keycloak.error': 'invalid_user_credentials',
      'user.name': 'dirk.dso',
      'source.ip': '203.0.113.66',
    }),
  );
}

// R-02: impossible travel — TWO real successful logins the enricher pairs
// (Frankfurt → Singapore, 8 s apart). No baked flag; the engine computes
// surf.enrichment.impossible_travel from the geo distance and time gap.
events.push(
  base('keycloak', 'events', 100, {
    'event.action': 'LOGIN',
    'event.outcome': 'success',
    'user.name': 'dirk.dso',
    'source.ip': '198.51.100.7',
  }),
);
events.push(
  base('keycloak', 'events', 92, {
    'event.action': 'LOGIN',
    'event.outcome': 'success',
    'user.name': 'dirk.dso',
    'source.ip': '203.0.113.5',
  }),
);

// R-03: >=5 rejected MFA + one success for the same user
for (let i = 0; i < 6; i += 1) {
  events.push(
    base('keycloak', 'events', 200 - i * 10, {
      'event.action': 'LOGIN_ERROR',
      'keycloak.error': 'invalid_authentication',
      'keycloak.credential_type': 'otp',
      'user.name': 'anna.analyst',
      'source.ip': '203.0.113.77',
    }),
  );
}
events.push(
  base('keycloak', 'events', 60, {
    'event.action': 'LOGIN',
    'event.outcome': 'success',
    'user.name': 'anna.analyst',
    'source.ip': '203.0.113.77',
  }),
);

// R-04: cross-tenant query — actor's home tenant (vnb-saar) ≠ the queried
// tenant (vnb-pfalz). surf.enrichment.cross_tenant_mismatch is computed.
events.push(
  base('postgres', 'pgaudit', 80, {
    'event.action': 'query',
    'surf.query.tenant_id': 'vnb-pfalz',
    'user.name': 'app_vnb_saar',
    'user.roles': ['DSO_OPERATOR'],
    'source.ip': '10.0.4.12',
  }),
);

// R-05: >20 JWT signature failures from one IP
for (let i = 0; i < 22; i += 1) {
  events.push(
    base('api-gateway', 'access', 150 - i * 2, {
      'event.action': 'jwt_verification',
      'event.outcome': 'failure',
      'error.type': 'signature_invalid',
      'source.ip': '203.0.113.99',
    }),
  );
}

// R-06: >5 signing failures
for (let i = 0; i < 7; i += 1) {
  events.push(
    base('surf-engine', 'signing', 100 - i * 5, {
      'event.action': 'command_sign',
      'event.outcome': 'failure',
      'host.name': 'surf-engine-01',
    }),
  );
}

// R-07: unsigned schedule command at MQTT broker
events.push(
  base('mqtt', 'broker', 70, {
    'surf.command.type': 'schedule',
    'surf.command.signed': false,
    'surf.command.id': 'cmd-forged-001',
    'surf.ems.id': 'ems-4711',
    'host.name': 'mqtt-broker-01',
  }),
);

// R-08: >50 curtailments in one grid section, no emergency declared
for (let i = 0; i < 55; i += 1) {
  events.push(
    base('surf-engine', 'dispatch', 250 - i * 2, {
      'event.action': 'command_dispatch',
      'surf.command.type': 'curtailment',
      'surf.command.magnitude_kw': 11.5,
      'surf.grid.section': 'saar-feeder-07',
      'surf.grid.emergency_declared': false,
      'host.name': 'surf-engine-01',
    }),
  );
}

// R-09: safety envelope violation
events.push(
  base('surf-engine', 'validation', 65, {
    'event.action': 'setpoint_validation',
    'surf.command.safety_envelope_violation': true,
    'surf.command.id': 'cmd-override-13',
    'surf.ems.id': 'ems-0815',
    'host.name': 'surf-engine-01',
  }),
);

// R-10: firmware downgrade — reported 2.1.0 is below the 2.4.0 inventory
// baseline; the engine computes surf.enrichment.firmware_downgrade via semver.
events.push(
  base('wazuh', 'syscollector', 60, {
    'event.action': 'firmware_inventory',
    'surf.ems.id': 'ems-0815',
    'surf.ems.firmware_version': '2.1.0',
    'host.name': 'ems-0815',
  }),
);

// R-11: >=10 schedule delivery failures to one EMS in 30m
for (let i = 0; i < 11; i += 1) {
  events.push(
    base('mqtt', 'broker', 280 - i * 20, {
      'event.action': 'schedule_delivery',
      'event.outcome': 'failure',
      'surf.ems.id': 'ems-2222',
      'host.name': 'mqtt-broker-01',
    }),
  );
}

// R-12: privileged role grant
events.push(
  base('keycloak', 'admin-events', 55, {
    'event.action': 'UPDATE',
    'keycloak.resource_type': 'REALM_ROLE_MAPPING',
    'keycloak.operation': 'CREATE',
    'keycloak.role_name': 'PLATFORM_ADMIN',
    'user.name': 'petra.platform',
    'source.ip': '10.0.2.5',
  }),
);

// R-13: service account created outside any declared change window — the
// engine computes surf.enrichment.in_change_window=false from the calendar.
events.push(
  base('keycloak', 'admin-events', 50, {
    'event.action': 'CREATE',
    'keycloak.resource_type': 'CLIENT',
    'keycloak.service_account_enabled': true,
    'user.name': 'petra.platform',
    'source.ip': '10.0.2.5',
  }),
);

// R-14: exec into production pod
events.push(
  base('kubernetes', 'audit', 45, {
    'kubernetes.audit.verb': 'create',
    'kubernetes.audit.objectRef.resource': 'pods',
    'kubernetes.audit.objectRef.subresource': 'exec',
    'kubernetes.audit.namespace_labels.environment': 'production',
    'user.name': 'ops-user',
    'source.ip': '10.0.3.9',
  }),
);

// R-15: DB access from an IP outside the allow-list — the engine computes
// surf.enrichment.ip_allowlisted=false (198.51.100.201 ∉ 10/8, 192.168/16).
events.push(
  base('postgres', 'pgaudit', 40, {
    'event.action': 'connection_authorized',
    'user.name': 'soc_app',
    'source.ip': '198.51.100.201',
  }),
);

// A few benign events so the store isn't only attack traffic
for (let i = 0; i < 20; i += 1) {
  events.push(
    base('surf-engine', 'dispatch', 290 - i * 10, {
      'event.action': 'command_dispatch',
      'surf.command.type': 'schedule',
      'surf.command.signed': true,
      'surf.command.magnitude_kw': 3.2,
      'surf.grid.section': 'pfalz-feeder-02',
      'surf.tenant.id': 'vnb-pfalz',
      'surf.prosumer.pseudonym': `pros-${1000 + i}`,
      'host.name': 'surf-engine-01',
    }),
  );
}

async function main(): Promise<void> {
  // Compute surf.enrichment.* exactly as the backend ingest path does: process
  // oldest-first, enrich each event against prior state, then let it contribute
  // its own (so the two R-02 logins pair, firmware baseline holds, etc.).
  const refs = new DefaultReferenceData(DEMO_REFERENCE_CONFIG);
  const enricher = new Enricher(refs);
  const ordered = [...events].sort(
    (a, b) => Date.parse(String(a['@timestamp'])) - Date.parse(String(b['@timestamp'])),
  );
  const enriched = ordered.map((doc) => {
    const out = enricher.enrich(doc);
    refs.observe(doc);
    return out;
  });

  const index = `surf-events-${new Date().toISOString().slice(0, 10).replaceAll('-', '.')}`;
  const operations = enriched.flatMap((doc) => [{ index: { _index: index, _id: String(doc['event.id']) } }, doc]);
  const response = await client.bulk({ body: operations, refresh: true });
  if (response.body.errors) {
    console.error('bulk ingest had item errors');
    process.exitCode = 1;
    return;
  }
  console.log(`seeded ${enriched.length} events into ${index} — enrichment computed at ingest, all 15 rules should fire within ~60s`);
}

main().catch((err) => {
  console.error('seed failed:', err);
  process.exit(1);
});
