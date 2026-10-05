/**
 * Ingest-time enrichment engine.
 *
 * Five SURF rules match on `surf.enrichment.*` booleans rather than raw fields
 * (see docs/DATA_MODEL.md). Those booleans have to be *computed* — the raw log
 * shippers do not carry them. This module is the component that computes them,
 * so detections fire on real telemetry instead of pre-baked seed flags.
 *
 *   surf.enrichment.impossible_travel    → R-02  (two logins > 500 km / 30 min apart)
 *   surf.enrichment.cross_tenant_mismatch→ R-04  (queried tenant ≠ actor's home tenant)
 *   surf.enrichment.firmware_downgrade   → R-10  (semver below last inventory)
 *   surf.enrichment.in_change_window     → R-13  (inside a declared change window)
 *   surf.enrichment.ip_allowlisted       → R-15  (client IP on the maintained allow-list)
 *                                          R-19  (same flag, computed for sshd logins)
 *
 * The engine is pure with respect to its injected reference data: all mutable
 * state (login history, firmware inventory) lives behind the reference ports, so
 * the flag logic itself is deterministic and unit-testable. It runs at the
 * correlation read/eval boundary (CorrelationScheduler), because raw shippers
 * write un-enriched events straight to OpenSearch; enrich() is idempotent, so an
 * event already carrying a flag (e.g. baked by a future write path) is left as-is.
 */
import { getField } from './evaluator.js';

export type Event = Record<string, unknown>;

export interface GeoPoint {
  lat: number;
  lon: number;
}

/** Resolves a client IP to an approximate location. */
export interface GeoResolver {
  locate(ip: string): GeoPoint | undefined;
}

/** Prior successful logins for a user, used to detect impossible travel. */
export interface LoginHistory {
  /** Successful logins for `user` strictly before `beforeIso`, within `windowMs`. */
  recentSuccessfulLogins(user: string, beforeIso: string, windowMs: number): Array<{ ts: string; ip: string }>;
}

/** Last-known firmware version reported for an EMS device. */
export interface FirmwareInventory {
  lastVersion(emsId: string): string | undefined;
}

/** Declared maintenance / change windows. */
export interface ChangeWindowCalendar {
  isOpen(atIso: string): boolean;
}

/** Maintained set of IPs permitted to reach a protected resource. */
export interface IpAllowlist {
  allows(ip: string): boolean;
}

/** Maps an actor (service or human account) to its home tenant. */
export interface TenantDirectory {
  homeTenant(user: string): string | undefined;
}

export interface EnrichmentRefs {
  geo: GeoResolver;
  logins: LoginHistory;
  firmware: FirmwareInventory;
  changeWindow: ChangeWindowCalendar;
  allowlist: IpAllowlist;
  tenants: TenantDirectory;
}

export interface EnrichmentOptions {
  /** Great-circle distance that counts as "impossible" within the window. */
  impossibleTravelKm: number;
  /** Look-back window pairing two logins for the impossible-travel check. */
  impossibleTravelWindowMinutes: number;
}

export const DEFAULT_ENRICHMENT_OPTIONS: EnrichmentOptions = {
  impossibleTravelKm: 500,
  impossibleTravelWindowMinutes: 30,
};

/** Great-circle distance in kilometres between two points (haversine). */
export function haversineKm(a: GeoPoint, b: GeoPoint): number {
  const R = 6371;
  const toRad = (d: number): number => (d * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(h)));
}

/**
 * Returns < 0 if `a` is an earlier version than `b`, 0 if equal, > 0 if later.
 * Non-numeric or missing components are treated as 0 (e.g. "2.1" == "2.1.0").
 */
export function compareSemver(a: string, b: string): number {
  const parts = (v: string): number[] => v.split('.').map((p) => Number.parseInt(p, 10) || 0);
  const av = parts(a);
  const bv = parts(b);
  const len = Math.max(av.length, bv.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (av[i] ?? 0) - (bv[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function str(v: unknown): string | undefined {
  return v === undefined || v === null ? undefined : String(v);
}

/**
 * Computes the enrichment flags for a single event, returning a shallow copy
 * with the applicable `surf.enrichment.*` key set. Events whose action is not
 * enrichment-relevant pass through unchanged.
 */
export class Enricher {
  constructor(
    private readonly refs: EnrichmentRefs,
    private readonly opts: EnrichmentOptions = DEFAULT_ENRICHMENT_OPTIONS,
  ) {}

  enrich(event: Event): Event {
    const action = str(getField(event, 'event.action'));
    const outcome = str(getField(event, 'event.outcome'));

    if (action === 'LOGIN' && outcome === 'success') {
      return this.setIfAbsent(event, 'surf.enrichment.impossible_travel', () => this.impossibleTravel(event));
    }
    if (action === 'query') {
      return this.setIfAbsent(event, 'surf.enrichment.cross_tenant_mismatch', () => this.crossTenantMismatch(event));
    }
    if (action === 'firmware_inventory') {
      return this.setIfAbsent(event, 'surf.enrichment.firmware_downgrade', () => this.firmwareDowngrade(event));
    }
    if (
      action === 'CREATE' &&
      str(getField(event, 'keycloak.resource_type')) === 'CLIENT' &&
      getField(event, 'keycloak.service_account_enabled') === true
    ) {
      return this.setIfAbsent(event, 'surf.enrichment.in_change_window', () =>
        this.refs.changeWindow.isOpen(str(getField(event, '@timestamp')) ?? new Date().toISOString()),
      );
    }
    if (action === 'connection_authorized' || action === 'ssh_login') {
      const ip = str(getField(event, 'source.ip'));
      // No client IP (e.g. a local unix-socket DB connection) → the allowlist
      // does not apply. Leave the flag unset so R-15/R-19 don't fire; a missing
      // IP is not the same as an off-allowlist IP.
      if (ip === undefined) return event;
      return this.setIfAbsent(event, 'surf.enrichment.ip_allowlisted', () => this.refs.allowlist.allows(ip));
    }
    return event;
  }

  private impossibleTravel(event: Event): boolean {
    const user = str(getField(event, 'user.name'));
    const ip = str(getField(event, 'source.ip'));
    const ts = str(getField(event, '@timestamp'));
    if (user === undefined || ip === undefined || ts === undefined) return false;
    const here = this.refs.geo.locate(ip);
    if (here === undefined) return false;
    const windowMs = this.opts.impossibleTravelWindowMinutes * 60_000;
    for (const prior of this.refs.logins.recentSuccessfulLogins(user, ts, windowMs)) {
      const there = this.refs.geo.locate(prior.ip);
      if (there !== undefined && haversineKm(here, there) > this.opts.impossibleTravelKm) return true;
    }
    return false;
  }

  private crossTenantMismatch(event: Event): boolean {
    const user = str(getField(event, 'user.name'));
    // The tenant whose data the query targeted, distinct from the actor's home tenant.
    const queried = str(getField(event, 'surf.query.tenant_id')) ?? str(getField(event, 'surf.tenant.id'));
    if (user === undefined || queried === undefined) return false;
    const home = this.refs.tenants.homeTenant(user);
    if (home === undefined) return false;
    return queried !== home;
  }

  private firmwareDowngrade(event: Event): boolean {
    const emsId = str(getField(event, 'surf.ems.id'));
    const reported = str(getField(event, 'surf.ems.firmware_version'));
    if (emsId === undefined || reported === undefined) return false;
    const last = this.refs.firmware.lastVersion(emsId);
    if (last === undefined) return false;
    return compareSemver(reported, last) < 0;
  }

  /**
   * Sets `key` only if the event does not already carry it, so enriching an
   * already-enriched event (e.g. one re-read at eval time after being enriched
   * at write time) is idempotent and never recomputes — critical because a
   * narrow eval window may lack the history the original computation had.
   */
  private setIfAbsent(event: Event, key: string, compute: () => boolean): Event {
    if (getField(event, key) !== undefined) return event;
    return { ...event, [key]: compute() };
  }
}
