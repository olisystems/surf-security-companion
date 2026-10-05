import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import type { ReferenceConfig } from './enrichmentReferenceData.js';

/**
 * File-backed override for the enrichment reference data (ENRICHMENT_REFERENCE_PATH).
 *
 * The demo config in enrichmentReferenceData.ts keeps the seed scenarios
 * working; a deployment supplies its real allow-list / geo table / change
 * calendar / tenant directory / firmware baseline as JSON. Every top-level key
 * is optional and, when present, REPLACES the demo value for that key (no deep
 * merge — an allow-list is a complete statement, not a delta). Validation fails
 * fast at startup with a readable report, mirroring loadConfig().
 */

const IPV4_CIDR = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:\/(?:3[0-2]|[12]?\d))?$/;

const geoEntrySchema = z
  .object({
    lat: z.number().min(-90).max(90),
    lon: z.number().min(-180).max(180),
    label: z.string().max(128).optional(),
  })
  .strict();

const changeWindowSchema = z
  .object({
    startIso: z.string().datetime({ offset: true }),
    endIso: z.string().datetime({ offset: true }),
  })
  .strict()
  .refine((w) => Date.parse(w.endIso) > Date.parse(w.startIso), { message: 'endIso must be after startIso' });

export const referenceFileSchema = z
  .object({
    geo: z.record(z.string().min(1), geoEntrySchema).optional(),
    allowlistCidrs: z.array(z.string().regex(IPV4_CIDR, 'expected IPv4 address or CIDR')).optional(),
    changeWindows: z.array(changeWindowSchema).optional(),
    tenantByUser: z.record(z.string().min(1), z.string().min(1)).optional(),
    firmwareBaseline: z.record(z.string().min(1), z.string().min(1)).optional(),
  })
  .strict();

export type ReferenceFileConfig = z.infer<typeof referenceFileSchema>;

export class ReferenceFileError extends Error {
  constructor(filePath: string, cause: string) {
    super(`Enrichment reference file invalid (${filePath}):\n${cause}`);
    this.name = 'ReferenceFileError';
  }
}

/** Validates an already-parsed JSON document against the ReferenceConfig shape. */
export function parseReferenceFile(doc: unknown, filePath = '<inline>'): ReferenceFileConfig {
  const parsed = referenceFileSchema.safeParse(doc);
  if (!parsed.success) {
    const report = parsed.error.issues.map((i) => `  - ${i.path.join('.') || '<root>'}: ${i.message}`).join('\n');
    throw new ReferenceFileError(filePath, report);
  }
  return parsed.data;
}

/** Reads + validates the JSON file; missing, malformed or invalid all throw ReferenceFileError. */
export async function loadReferenceConfigFile(filePath: string): Promise<ReferenceFileConfig> {
  let raw: string;
  try {
    raw = await readFile(filePath, 'utf8');
  } catch (err) {
    throw new ReferenceFileError(filePath, `  - cannot read: ${err instanceof Error ? err.message : String(err)}`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (err) {
    throw new ReferenceFileError(filePath, `  - not valid JSON: ${err instanceof Error ? err.message : String(err)}`);
  }
  return parseReferenceFile(doc, filePath);
}

/** File wins per top-level key; keys absent from the file keep the base value. */
export function mergeReferenceConfig(base: ReferenceConfig, override: ReferenceFileConfig): ReferenceConfig {
  return {
    geo: override.geo ?? base.geo,
    allowlistCidrs: override.allowlistCidrs ?? base.allowlistCidrs,
    changeWindows: override.changeWindows ?? base.changeWindows,
    tenantByUser: override.tenantByUser ?? base.tenantByUser,
    firmwareBaseline: override.firmwareBaseline ?? base.firmwareBaseline,
  };
}
