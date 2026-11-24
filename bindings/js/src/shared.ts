// The public types both builds share, and the conversion from the engine's JSON answers.
// Nothing here holds a personal value: a finding or decision says where something is, what
// it is and how sure Veil is, so it's safe to log. Use `text.slice(start, end)` for the value.

export type Profile = "rules" | "nano" | "hybrid";
export type Enforcement = "closed" | "open" | "rules_fallback";
export type Action = "DETECT" | "ALLOW" | "MASK" | "REDACT" | "TOKENIZE" | "BLOCK";
export type Validation = "INVALID" | "UNVERIFIED" | "NOT_APPLICABLE" | "VALID_FORMAT" | "VALID";
export type Evidence = "ISSUER_CONFIRMED" | "INTERNATIONAL_STANDARD" | "SECONDARY" | "UNPUBLISHED";

/** Veil's published models. Any Hugging Face repository with the same files also works. */
export const MODELS = {
  "veil-ner-nano": "dekka-cloud/veil-ner-nano",
  "veil-ner-deep": "dekka-cloud/veil-ner-deep",
} as const;

export type ModelName = keyof typeof MODELS;

export interface VeilOptions {
  /** Limits detection to one country's pack, such as `"GH"`. Every pack applies when unset. */
  country?: string;
  /** A built-in policy's name. `default-protection` when unset. */
  policy?: string;
  /** A policy written in YAML, which wins over `policy`. */
  policyYaml?: string;
  /**
   * Adds Veil's contextual model, which finds names, addresses given as directions and
   * institutions' own ID numbers: `"veil-ner-nano"`, `"veil-ner-deep"` or a Hugging Face
   * repository id, downloaded once and checked against its manifest. In Node it can also be
   * the path of a directory that holds a model.
   */
  model?: ModelName | (string & {});
  /** `rules`, `nano` or `hybrid`. `hybrid` when there's a model, `rules` otherwise. */
  profile?: Profile;
  /** The model repository's branch, tag or commit. Pin a commit for a reproducible deployment. */
  revision?: string;
}

/** Request attributes that policy rules can match on. */
export interface RequestContext {
  destinationProvider?: string;
  application?: string;
  environment?: string;
  purpose?: string;
}

export interface ScanOptions {
  context?: RequestContext;
  /** Overrides the profile for this call. */
  profile?: Profile;
}

export interface ProtectOptions extends ScanOptions {
  /**
   * What happens when a scan can't complete: `closed` blocks, `open` lets the text through
   * with a warning, and `rules_fallback` carries on with the rules alone.
   */
  enforcement?: Enforcement;
  /** Keeps the original values in memory so `Protection.restore` can put them back. */
  restore?: boolean;
}

/** Something Veil detected. `text.slice(start, end)` is the value. */
export interface Finding {
  entityType: string;
  start: number;
  end: number;
  confidence: number;
  detector: string;
  validation: Validation;
  evidence: Evidence | null;
  family: string;
  categories: string[];
  sensitivity: string;
  jurisdiction: string | null;
}

/** What the policy did with one finding. `start` and `end` index the original text. */
export interface Decision {
  entityType: string;
  start: number;
  end: number;
  action: Action;
  rule: string | null;
  detector: string;
  validation: Validation;
  evidence: Evidence | null;
  confidence: number;
}

/** What Veil found in one text. */
export interface Detection {
  findings: Finding[];
  profile: Profile;
  warnings: string[];
}

export interface PolicyInfo {
  name: string;
  revision: string;
  description: string;
}

/** Raised when Veil can't build or can't answer a request. */
export class VeilError extends Error {
  override name = "VeilError";
}

/**
 * One text after the policy was applied. `text` is the protected text, or `null` when the
 * policy blocked the request; when texts are protected together, one block blocks them all.
 */
export class Protection {
  readonly #values: Readonly<Record<string, string>> | null;

  constructor(
    readonly text: string | null,
    readonly blocked: boolean,
    readonly decisions: readonly Decision[],
    readonly policy: string,
    readonly profile: Profile,
    readonly warnings: readonly string[],
    values: Record<string, string> | null,
  ) {
    this.#values = values;
  }

  /**
   * Puts the original values back in place of this protection's placeholders, such as in an
   * AI model's reply. Needs `restore: true` on the call that protected the text.
   */
  restore(text: string): string {
    if (this.#values === null) {
      throw new VeilError("this protection holds no values to restore; protect with restore: true");
    }
    let out = text;
    for (const [placeholder, value] of Object.entries(this.#values)) {
      out = out.split(placeholder).join(value);
    }
    return out;
  }
}

// The engine's JSON, as the bindings return it.
interface RawSpan {
  start: number;
  end: number;
}
interface RawFinding {
  entity_type: string;
  span: RawSpan;
  confidence: number;
  detector: string;
  validation: Validation;
  evidence?: Evidence;
  family: string;
  categories?: string[];
  sensitivity: string;
  jurisdiction?: string | null;
}
interface RawDecision {
  entity_type: string;
  span: RawSpan;
  action: Action;
  rule: { id: string | null } | null;
  detector: string;
  validation: Validation;
  evidence?: Evidence;
  confidence: number;
}
interface RawDetect {
  segments: { findings: RawFinding[] }[];
  profile_used: Profile;
  warnings: string[];
}
interface RawProtect {
  blocked: boolean;
  segments: { output: string | null; decisions: RawDecision[] }[];
  policy: { name: string; revision: string };
  profile_used: Profile;
  warnings: string[];
  restore: Record<string, string> | null;
}

export function callJson(segments: readonly string[], options: ProtectOptions = {}): string {
  for (const s of segments) {
    if (typeof s !== "string") {
      throw new TypeError(`Veil scans text; got ${typeof s}`);
    }
  }
  const context = options.context ?? {};
  return JSON.stringify({
    segments,
    context: {
      destination_provider: context.destinationProvider,
      application: context.application,
      environment: context.environment,
      purpose: context.purpose,
    },
    enforcement: options.enforcement,
    restore: options.restore ?? false,
    profile: options.profile,
  });
}

export function detections(json: string): Detection[] {
  const raw = JSON.parse(json) as RawDetect;
  return raw.segments.map((segment) => ({
    findings: segment.findings.map((f) => ({
      entityType: f.entity_type,
      start: f.span.start,
      end: f.span.end,
      confidence: f.confidence,
      detector: f.detector,
      validation: f.validation,
      evidence: f.evidence ?? null,
      family: f.family,
      categories: f.categories ?? [],
      sensitivity: f.sensitivity,
      jurisdiction: f.jurisdiction ?? null,
    })),
    profile: raw.profile_used,
    warnings: [...raw.warnings],
  }));
}

export function protections(json: string): Protection[] {
  const raw = JSON.parse(json) as RawProtect;
  const policy = `${raw.policy.name}@${raw.policy.revision}`;
  return raw.segments.map(
    (segment) =>
      new Protection(
        segment.output,
        raw.blocked,
        segment.decisions.map((d) => ({
          entityType: d.entity_type,
          start: d.span.start,
          end: d.span.end,
          action: d.action,
          rule: d.rule?.id ?? null,
          detector: d.detector,
          validation: d.validation,
          evidence: d.evidence ?? null,
          confidence: d.confidence,
        })),
        policy,
        raw.profile_used,
        raw.warnings,
        raw.restore,
      ),
  );
}

/** The repository a model name refers to, or an error for a name that can't be one. */
export function modelRepo(model: string): string {
  const repo = (MODELS as Record<string, string>)[model] ?? model;
  if (repo.split("/").length !== 2) {
    throw new VeilError(
      `there is no model called ${JSON.stringify(model)}; use one of ${Object.keys(MODELS).join(", ")}, or a Hugging Face repository id`,
    );
  }
  return repo;
}

export function modelUrl(repo: string, revision: string, file: string): string {
  return `https://huggingface.co/${repo}/resolve/${encodeURIComponent(revision)}/${file}`;
}

/** Wraps an engine error so callers can catch `VeilError`. */
export function rethrow(e: unknown): never {
  if (e instanceof VeilError || e instanceof TypeError) throw e;
  throw new VeilError(e instanceof Error ? e.message : String(e));
}
