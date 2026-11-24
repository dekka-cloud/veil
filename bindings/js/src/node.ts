// Veil in Node.js, through the native addon. Scans run on libuv's thread pool, so a server
// keeps answering requests while Veil works.

import { existsSync, mkdirSync, renameSync, rmSync, statSync, createWriteStream } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

import {
  type Detection,
  type PolicyInfo,
  type Profile,
  type ProtectOptions,
  type ScanOptions,
  type VeilOptions,
  type Protection,
  VeilError,
  callJson,
  detections,
  modelRepo,
  modelUrl,
  protections,
  rethrow,
} from "./shared.js";

export * from "./shared.js";

interface NativeEngine {
  protect(call: string): Promise<string>;
  detect(call: string): Promise<string>;
  readonly profile: string;
  readonly policy: string;
}

interface Native {
  Engine: new (options?: {
    country?: string;
    policy?: string;
    policyYaml?: string;
    modelDir?: string;
    profile?: string;
    threads?: number;
  }) => NativeEngine;
  builtinPolicies(): string;
  entities(): string;
  countries(): string;
  validatePolicy(yaml: string): string;
  engineVersion(): string;
}

const native = createRequire(import.meta.url)("../native/binding.cjs") as Native;

export interface NodeVeilOptions extends VeilOptions {
  /** Threads one model inference may use. One by default. */
  threads?: number;
  /** Where downloaded models are kept. `$DEKKA_VEIL_CACHE`, else `~/.cache/dekka-veil`. */
  cacheDir?: string;
}

/** Finds personal information in text and protects it under a policy. Build one with
 * {@link Veil.load} and reuse it; every call is safe to run concurrently. */
export class Veil {
  readonly #engine: NativeEngine;

  private constructor(engine: NativeEngine) {
    this.#engine = engine;
  }

  /** Builds a Veil, downloading the model first if `model` names one that isn't cached. */
  static async load(options: NodeVeilOptions = {}): Promise<Veil> {
    const modelDir = options.model === undefined ? undefined : await resolveModel(options);
    try {
      return new Veil(
        new native.Engine({
          country: options.country,
          policy: options.policy,
          policyYaml: options.policyYaml,
          modelDir,
          profile: options.profile,
          threads: options.threads,
        }),
      );
    } catch (e) {
      rethrow(e);
    }
  }

  /** The profile scans use unless they ask for another. */
  get profile(): Profile {
    return this.#engine.profile as Profile;
  }

  /** The policy's name and revision, such as `default-protection@2026-11-04`. */
  get policy(): string {
    return this.#engine.policy;
  }

  /** Finds personal information in `text` without changing it. */
  async detect(text: string, options?: ScanOptions): Promise<Detection> {
    const [one] = await this.detectAll([text], options);
    return one!;
  }

  /** Runs {@link Veil.detect} on several texts in one call. */
  async detectAll(texts: readonly string[], options?: ScanOptions): Promise<Detection[]> {
    const call = callJson(texts, options);
    return detections(await this.#engine.detect(call).catch(rethrow));
  }

  /** Applies the policy to `text`. */
  async protect(text: string, options?: ProtectOptions): Promise<Protection> {
    const [one] = await this.protectAll([text], options);
    return one!;
  }

  /** Protects several texts together, such as the messages of one chat: the same value gets
   * the same placeholder in every text, and a block in any text blocks them all. */
  async protectAll(texts: readonly string[], options?: ProtectOptions): Promise<Protection[]> {
    const call = callJson(texts, options);
    return protections(await this.#engine.protect(call).catch(rethrow));
  }
}

/** The built-in policies, with each one's name, revision and description. */
export async function builtinPolicies(): Promise<PolicyInfo[]> {
  return JSON.parse(native.builtinPolicies()) as PolicyInfo[];
}

/** Every kind of personal information Veil can report, with its categories and sensitivity. */
export async function entities(): Promise<Record<string, unknown>[]> {
  return JSON.parse(native.entities()) as Record<string, unknown>[];
}

/** The country packs in this build and their versions. */
export async function countries(): Promise<Record<string, unknown>[]> {
  return JSON.parse(native.countries()) as Record<string, unknown>[];
}

/** Checks a policy written in YAML and returns every problem with its path. An empty list
 * means the policy is valid. */
export async function validatePolicy(yaml: string): Promise<{ path: string; message: string }[]> {
  return (JSON.parse(native.validatePolicy(yaml)) as { errors: { path: string; message: string }[] }).errors;
}

/** Where downloaded models are kept. */
export function cacheDir(): string {
  const configured = process.env.DEKKA_VEIL_CACHE;
  if (configured) return configured;
  const base = process.env.XDG_CACHE_HOME || join(homedir(), ".cache");
  return join(base, "dekka-veil");
}

/** Downloads a model once and returns the directory that holds it. */
export async function downloadModel(
  name: string = "veil-ner-nano",
  { revision = "main", cacheDir: cache }: { revision?: string; cacheDir?: string } = {},
): Promise<string> {
  const repo = modelRepo(name);
  const dir = join(cache ?? cacheDir(), repo.replace("/", "--"), revision);
  mkdirSync(dir, { recursive: true });
  for (const file of ["manifest.yaml", "tokenizer.json", "model.onnx"]) {
    const path = join(dir, file);
    if (!existsSync(path)) await fetchTo(modelUrl(repo, revision, file), path);
  }
  return dir;
}

async function resolveModel(options: NodeVeilOptions): Promise<string> {
  const model = options.model!;
  if (existsSync(model) && statSync(model).isDirectory()) return model;
  if (/^(\.|\/|~|[A-Za-z]:[\\/])/.test(model)) {
    throw new VeilError(`there is no model directory at ${model}`);
  }
  return downloadModel(model, { revision: options.revision, cacheDir: options.cacheDir });
}

async function fetchTo(url: string, path: string): Promise<void> {
  const response = await fetch(url, { headers: { "user-agent": `dekka-veil/${native.engineVersion()}` } });
  if (!response.ok || response.body === null) {
    throw new VeilError(`couldn't download ${url}: ${response.status} ${response.statusText}`);
  }
  // Write beside the destination and rename, so an interrupted download never leaves a
  // partial file that looks complete.
  const partial = `${path}.${process.pid}.partial`;
  try {
    await pipeline(Readable.fromWeb(response.body as import("node:stream/web").ReadableStream), createWriteStream(partial));
    renameSync(partial, path);
  } catch (e) {
    rmSync(partial, { force: true });
    throw e;
  }
}

