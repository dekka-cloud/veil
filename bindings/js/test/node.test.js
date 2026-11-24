// Tests for the Node build, run against the compiled package with `node --test`.

import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { describe, it, before } from "node:test";

import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Protection, Veil, VeilError, builtinPolicies, countries, downloadModel, entities, validatePolicy } from "../lib/node.js";

// A 1 KB test model that tags a handful of words, not trained weights.
const TINY_MODEL = fileURLToPath(new URL("../../../crates/veil-inference/tests/fixtures/tiny", import.meta.url));

const TOKENIZE = `
version: 1
name: support-desk
revision: "1"
default_action: tokenize
rules: []
`;

describe("Veil in Node", () => {
  let veil;
  before(async () => {
    veil = await Veil.load({ country: "GH" });
  });

  it("masks phone numbers and redacts the rest under the default policy", async () => {
    const out = await veil.protect("Please call 024 123 4567 or write to ama@example.com");
    assert.equal(out.text, "Please call 024 *** 4567 or write to [EMAIL_ADDRESS]");
    assert.equal(out.blocked, false);
    assert.deepEqual(
      out.decisions.map((d) => [d.entityType, d.action]),
      [
        ["GH_MOBILE_NUMBER", "MASK"],
        ["EMAIL_ADDRESS", "REDACT"],
      ],
    );
    assert.match(out.policy, /^default-protection@/);
    assert.equal(out.profile, "rules");
  });

  it("blocks every text protected together with a Ghana Card PIN", async () => {
    const [first, second] = await veil.protectAll(["My Ghana Card is GHA-123456789-0", "Thanks"]);
    assert.ok(first.blocked && second.blocked);
    assert.equal(first.text, null);
    assert.equal(first.decisions[0].rule, "block-ghana-card");
  });

  it("reports offsets that slice JavaScript strings, even after emoji", async () => {
    const text = "Ɛyɛ 🙂 me number yɛ 024 123 4567";
    const { findings } = await veil.detect(text);
    assert.equal(findings.length, 1);
    assert.equal(text.slice(findings[0].start, findings[0].end), "024 123 4567");
  });

  it("never puts the value it found into a finding", async () => {
    const { findings } = await veil.detect("Send the MoMo to 024 123 4567");
    assert.equal(findings[0].entityType, "GH_MOBILE_NUMBER");
    assert.equal(findings[0].jurisdiction, "GH");
    assert.ok(!JSON.stringify(findings).includes("024"));
  });

  it("tokenises with a custom policy and restores values in a reply", async () => {
    const custom = await Veil.load({ policyYaml: TOKENIZE });
    const out = await custom.protect("Email ama@example.com about it", { restore: true });
    assert.equal(out.text, "Email [EMAIL_ADDRESS_1] about it");
    assert.equal(out.restore("I've written to [EMAIL_ADDRESS_1]."), "I've written to ama@example.com.");
    const kept = await custom.protect("Email ama@example.com");
    assert.throws(() => kept.restore("[EMAIL_ADDRESS_1]"), VeilError);
  });

  it("leaves a restored value that looks like a placeholder as it is", () => {
    const values = { "[EMAIL_ADDRESS_1]": "[EMAIL_ADDRESS_2]", "[EMAIL_ADDRESS_2]": "ama@example.com" };
    const out = new Protection("x", false, [], "p@1", "rules", [], values);
    assert.equal(out.restore("[EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_2]"), "[EMAIL_ADDRESS_2] and ama@example.com");
  });

  it("refuses a revision that would lead out of the model cache", async () => {
    const cacheDir = mkdtempSync(join(tmpdir(), "veil-cache-"));
    for (const revision of ["../../tmp/evil", "..", "/etc", "a//b", "main/..", "a\\b", ""]) {
      await assert.rejects(downloadModel("veil-ner-nano", { revision, cacheDir }), VeilError, revision);
    }
    assert.deepEqual(readdirSync(cacheDir), []);
  });

  it("reports mistakes as VeilError", async () => {
    await assert.rejects(Veil.load({ policy: "no-such-policy" }), (e) => e instanceof VeilError && /no built-in policy/.test(e.message));
    await assert.rejects(veil.detect("hello", { profile: "hybrid" }), VeilError);
    await assert.rejects(Veil.load({ model: "./missing-model" }), VeilError);
    await assert.rejects(veil.protect(42), TypeError);
  });

  it("runs the model beside the rules when given one", async () => {
    const withModel = await Veil.load({ model: TINY_MODEL });
    assert.equal(withModel.profile, "hybrid");
    const text = "call Ama Mensah , Kofi lives in Osu .";
    const names = (await withModel.detect(text)).findings
      .filter((f) => f.entityType === "PERSON_NAME")
      .map((f) => text.slice(f.start, f.end));
    assert.deepEqual(names, ["Ama Mensah", "Kofi"]);
    assert.deepEqual((await withModel.detect(text, { profile: "rules" })).findings, []);
  });

  it("serves many calls at once without mixing them up", async () => {
    const texts = Array.from({ length: 64 }, (_, i) => `Call 024 123 45${String(i).padStart(2, "0")}`);
    const outputs = await Promise.all(texts.map(async (t) => (await veil.protect(t)).text));
    assert.deepEqual(outputs, texts.map((_, i) => `Call 024 *** 45${String(i).padStart(2, "0")}`));
  });

  it("lists its policies, entities and countries, and validates policies", async () => {
    assert.ok((await builtinPolicies()).some((p) => p.name === "default-protection"));
    assert.ok((await entities()).some((e) => e.code === "GH_GHANA_CARD_PIN"));
    assert.ok((await countries()).some((c) => c.code === "GH"));
    assert.deepEqual(await validatePolicy(TOKENIZE), []);
    assert.ok((await validatePolicy("version: 1\nname: x\nrules:\n  - action: shout\n")).length > 0);
  });
});
