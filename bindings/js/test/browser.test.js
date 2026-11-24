// Tests for the WebAssembly build, which browsers use. They run in Node with the same
// code a browser loads: the engine compiled to WebAssembly, and onnxruntime-web for the
// model, which is served here from a local HTTP server the way a CDN would serve it.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { after, before, describe, it } from "node:test";

import * as browser from "../lib/browser.js";
import * as node from "../lib/node.js";

const wasm = readFileSync(new URL("../wasm/pkg/veil_wasm_bg.wasm", import.meta.url));
const TINY = new URL("../../../crates/veil-inference/tests/fixtures/tiny/", import.meta.url);

describe("Veil in the browser build", () => {
  let server;
  let modelUrl;

  before(async () => {
    server = createServer((req, res) => {
      try {
        res.end(readFileSync(new URL(req.url.slice(1), TINY)));
      } catch {
        res.statusCode = 404;
        res.end();
      }
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    modelUrl = `http://127.0.0.1:${server.address().port}/`;
  });

  after(() => server.close());

  it("protects text with the rules alone", async () => {
    const veil = await browser.Veil.load({ country: "GH", wasm });
    const out = await veil.protect("Please call 024 123 4567 or write to ama@example.com");
    assert.equal(out.text, "Please call 024 *** 4567 or write to [EMAIL_ADDRESS]");
    assert.equal(out.profile, "rules");
  });

  it("reports offsets that slice JavaScript strings, even after emoji", async () => {
    const veil = await browser.Veil.load({ wasm });
    const text = "Ɛyɛ 🙂 me number yɛ 024 123 4567";
    const { findings } = await veil.detect(text);
    assert.equal(text.slice(findings[0].start, findings[0].end), "024 123 4567");
  });

  it("runs the model in onnxruntime-web and finds what the native build finds", async () => {
    const veil = await browser.Veil.load({ wasm, modelUrl, cache: false });
    assert.equal(veil.profile, "hybrid");
    assert.equal(veil.model, "veil-ner-tiny-v0.0.1");
    const native = await node.Veil.load({ model: new URL(TINY).pathname });
    const texts = ["call Ama Mensah , Kofi lives in Osu .", "ɛyɛ Ama Mensah ɔno", "Call 024 123 4567"];
    const fromWasm = await veil.detectAll(texts);
    const fromNative = await native.detectAll(texts);
    assert.deepEqual(fromWasm, fromNative);
    const names = fromWasm[0].findings.filter((f) => f.entityType === "PERSON_NAME").map((f) => texts[0].slice(f.start, f.end));
    assert.deepEqual(names, ["Ama Mensah", "Kofi"]);
  });

  it("refuses a model whose graph doesn't match its manifest", async () => {
    const tampered = createServer((req, res) => {
      const body = req.url === "/model.onnx" ? Buffer.from("not the model") : readFileSync(new URL(req.url.slice(1), TINY));
      res.end(body);
    });
    await new Promise((resolve) => tampered.listen(0, "127.0.0.1", resolve));
    try {
      await assert.rejects(
        browser.Veil.load({ wasm, modelUrl: `http://127.0.0.1:${tampered.address().port}/`, cache: false }),
        (e) => e instanceof browser.VeilError && /SHA-256/.test(e.message),
      );
    } finally {
      tampered.close();
    }
  });

  it("keeps concurrent calls on one instance apart", async () => {
    const veil = await browser.Veil.load({ wasm, modelUrl, cache: false });
    const texts = Array.from({ length: 20 }, (_, i) => `call Ama Mensah on 024 123 45${String(i).padStart(2, "0")}`);
    const outputs = await Promise.all(texts.map(async (t) => (await veil.protect(t)).text));
    assert.deepEqual(
      outputs,
      texts.map((_, i) => `call [PERSON_NAME] on 024 *** 45${String(i).padStart(2, "0")}`),
    );
  });
});
