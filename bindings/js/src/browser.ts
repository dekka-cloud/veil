// Veil in the browser, and in any JavaScript runtime without native addons, through
// WebAssembly. The rules run in Veil's engine compiled to WebAssembly. With a model, the
// engine splits each text into the model's windows, onnxruntime-web runs them on the
// device, and the engine decodes the result exactly as the native build does, so nothing
// leaves the page.

import init, {
  Engine,
  builtinPolicies as wasmBuiltinPolicies,
  countries as wasmCountries,
  entities as wasmEntities,
  validatePolicy as wasmValidatePolicy,
} from "../wasm/pkg/veil_wasm.js";
import {
  type Detection,
  type PolicyInfo,
  type Profile,
  type ProtectOptions,
  type Protection,
  type ScanOptions,
  type VeilOptions,
  VeilError,
  callJson,
  detections,
  modelRepo,
  modelUrl,
  protections,
  rethrow,
} from "./shared.js";

export * from "./shared.js";

type Ort = typeof import("onnxruntime-web");
type Session = Awaited<ReturnType<Ort["InferenceSession"]["create"]>>;

/** Where the engine's `.wasm` file comes from: a URL, a fetch response, its bytes or a
 * compiled module. */
export type WasmSource = string | URL | Request | Response | BufferSource | WebAssembly.Module;

export interface BrowserVeilOptions extends VeilOptions {
  /** The engine's `.wasm` file, when you serve it from somewhere other than beside this module. */
  wasm?: WasmSource;
  /** onnxruntime-web, if you've imported and configured it yourself. Imported on demand otherwise. */
  ort?: Ort;
  /** Keeps downloaded model files in the browser's Cache Storage. On by default. */
  cache?: boolean;
  /**
   * Where to fetch the model's three files from instead of Hugging Face, such as your own
   * CDN: a base URL that holds `manifest.yaml`, `tokenizer.json` and `model.onnx`.
   */
  modelUrl?: string | URL;
}

let ready: Promise<unknown> | undefined;

/** Loads the WebAssembly engine once. {@link Veil.load} calls it for you. */
export function initWasm(source?: WasmSource): Promise<unknown> {
  ready ??= init(source === undefined ? undefined : { module_or_path: source });
  return ready;
}

/** Finds personal information in text and protects it under a policy. Build one with
 * {@link Veil.load} and reuse it. */
export class Veil {
  readonly #engine: Engine;
  readonly #session: Session | undefined;
  readonly #ort: Ort | undefined;
  #turn: Promise<unknown> = Promise.resolve();

  private constructor(engine: Engine, session?: Session, ort?: Ort) {
    this.#engine = engine;
    this.#session = session;
    this.#ort = ort;
  }

  /** Builds a Veil, fetching and checking the model first when `model` names one. */
  static async load(options: BrowserVeilOptions = {}): Promise<Veil> {
    await initWasm(options.wasm);
    const settings = JSON.stringify({
      country: options.country,
      policy: options.policy,
      policy_yaml: options.policyYaml,
      profile: options.profile,
    });
    try {
      if (options.model === undefined && options.modelUrl === undefined) {
        return new Veil(new Engine(settings, undefined, undefined));
      }
      const cache = options.cache ?? true;
      const where = (file: string): string => {
        if (options.modelUrl !== undefined) return new URL(file, withSlash(options.modelUrl)).href;
        return modelUrl(modelRepo(options.model!), options.revision ?? "main", file);
      };
      const [manifest, tokenizer, graph] = await Promise.all(
        ["manifest.yaml", "tokenizer.json", "model.onnx"].map((file) => fetchBytes(where(file), cache)),
      );
      const engine = new Engine(settings, manifest, tokenizer);
      await verify(graph!, engine.modelSha256!, "model.onnx");
      const ort = options.ort ?? (await importOrt());
      const session = await ort.InferenceSession.create(graph!, { executionProviders: ["wasm"] });
      return new Veil(engine, session, ort);
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

  /** The loaded model's id and version, such as `veil-ner-nano-v0.3.0`. */
  get model(): string | undefined {
    return this.#engine.modelId;
  }

  /** Finds personal information in `text` without changing it. */
  async detect(text: string, options?: ScanOptions): Promise<Detection> {
    const [one] = await this.detectAll([text], options);
    return one!;
  }

  /** Runs {@link Veil.detect} on several texts in one call. */
  detectAll(texts: readonly string[], options?: ScanOptions): Promise<Detection[]> {
    const call = callJson(texts, options);
    return this.#exclusive(async () => {
      await this.#runModel(texts, options?.profile);
      return detections(this.#engine.detect(call));
    });
  }

  /** Applies the policy to `text`. */
  async protect(text: string, options?: ProtectOptions): Promise<Protection> {
    const [one] = await this.protectAll([text], options);
    return one!;
  }

  /** Protects several texts together, such as the messages of one chat: the same value gets
   * the same placeholder in every text, and a block in any text blocks them all. */
  protectAll(texts: readonly string[], options?: ProtectOptions): Promise<Protection[]> {
    const call = callJson(texts, options);
    return this.#exclusive(async () => {
      await this.#runModel(texts, options?.profile);
      return protections(this.#engine.protect(call));
    });
  }

  /** Frees the engine's memory and the model's session. The instance can't be used after. */
  async dispose(): Promise<void> {
    await this.#exclusive(async () => {
      await this.#session?.release();
      this.#engine.free();
    });
  }

  // The engine holds the model's findings between `provide` and the scan, so calls on one
  // instance take turns.
  #exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = this.#turn.then(work, work);
    this.#turn = run.catch(() => undefined);
    return run.catch(rethrow);
  }

  async #runModel(texts: readonly string[], profile: Profile | undefined): Promise<void> {
    const session = this.#session;
    const ort = this.#ort;
    if (session === undefined || ort === undefined || (profile ?? this.profile) === "rules") return;
    for (const text of new Set(texts)) {
      const plan = this.#engine.plan(text);
      try {
        const logits: Float32Array[] = [];
        for (let i = 0; i < plan.batches; i++) {
          const [rows, width] = plan.shape(i);
          const dims = [rows!, width!];
          const feeds: Record<string, InstanceType<Ort["Tensor"]>> = {
            input_ids: new ort.Tensor("int64", plan.ids(i), dims),
            attention_mask: new ort.Tensor("int64", plan.mask(i), dims),
          };
          const out = await session.run(feeds);
          const tensor = out["logits"];
          if (tensor === undefined) throw new VeilError("the model returned no logits");
          logits.push(tensor.data as Float32Array);
        }
        this.#engine.provide(plan, logits);
      } finally {
        plan.free();
      }
    }
  }
}

/** The built-in policies, with each one's name, revision and description. */
export async function builtinPolicies(): Promise<PolicyInfo[]> {
  await initWasm();
  return JSON.parse(wasmBuiltinPolicies()) as PolicyInfo[];
}

/** Every kind of personal information Veil can report, with its categories and sensitivity. */
export async function entities(): Promise<Record<string, unknown>[]> {
  await initWasm();
  return JSON.parse(wasmEntities()) as Record<string, unknown>[];
}

/** The country packs in this build and their versions. */
export async function countries(): Promise<Record<string, unknown>[]> {
  await initWasm();
  return JSON.parse(wasmCountries()) as Record<string, unknown>[];
}

/** Checks a policy written in YAML and returns every problem with its path. An empty list
 * means the policy is valid. */
export async function validatePolicy(yaml: string): Promise<{ path: string; message: string }[]> {
  await initWasm();
  return (JSON.parse(wasmValidatePolicy(yaml)) as { errors: { path: string; message: string }[] }).errors;
}

function withSlash(base: string | URL): string {
  const href = base instanceof URL ? base.href : base;
  return href.endsWith("/") ? href : `${href}/`;
}

async function importOrt(): Promise<Ort> {
  try {
    return await import("onnxruntime-web");
  } catch {
    throw new VeilError("running a model in the browser needs onnxruntime-web; install it beside dekka-veil");
  }
}

async function fetchBytes(url: string, useCache: boolean): Promise<Uint8Array<ArrayBuffer>> {
  const store = useCache && typeof caches !== "undefined" ? await caches.open("dekka-veil") : undefined;
  let response = await store?.match(url);
  if (response === undefined) {
    response = await fetch(url);
    if (!response.ok) throw new VeilError(`couldn't download ${url}: ${response.status} ${response.statusText}`);
    await store?.put(url, response.clone());
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function verify(bytes: Uint8Array<ArrayBuffer>, want: string, file: string): Promise<void> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const got = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
  if (got !== want.trim().toLowerCase()) {
    throw new VeilError(`${file} doesn't match the SHA-256 in the manifest`);
  }
}
