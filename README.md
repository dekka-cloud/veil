# Veil

Veil finds personal information in text and protects it before the text goes somewhere it shouldn't, such as a prompt on its way to an AI model, a log line or a shared dataset. It runs on your own machine, in Python, Node.js, the browser or Rust, and it was built for Ghanaian text: Ghana Card PINs, phone and mobile money numbers written in figures or read aloud in English, Akan and Ewe, GhanaPost GPS addresses and taxpayer numbers, alongside the emails, card numbers and credentials any text can hold. An optional open model adds names, addresses given as directions and the ID numbers hospitals, schools and employers issue.

```python
from dekka_veil import Veil

veil = Veil(country="GH")
veil.protect("Please call 024 123 4567 or write to ama@example.com").text
# 'Please call 024 *** 4567 or write to [EMAIL_ADDRESS]'
```

```js
import { Veil } from "dekka-veil";

const veil = await Veil.load({ country: "GH" });
(await veil.protect("Please call 024 123 4567 or write to ama@example.com")).text;
// 'Please call 024 *** 4567 or write to [EMAIL_ADDRESS]'
```

Install it with `pip install dekka-veil` or `npm install dekka-veil`. The Python library supports Python 3.10 and later, and the npm package supports Node.js 20 and later and current browsers.

## What it finds

| Kind | What Veil finds | How |
| --- | --- | --- |
| Ghanaian identifiers | Ghana Card PINs, mobile and landline numbers (with mobile money noted when a number is used as a wallet), GhanaPost GPS digital addresses, GRA taxpayer numbers, vehicle plates, and passport, voter ID and bank account numbers near the words that introduce them | Rules checked against each format's published source |
| Personal details anywhere | Email addresses, IP addresses, payment card numbers that pass the Luhn check, and URLs carrying personal details | Rules |
| Credentials | Private keys, JSON Web Tokens, AWS, GitHub, Stripe and Slack tokens, webhook URLs, and passwords or keys assigned in text | Rules |
| What only context reveals | Names, addresses given as directions, and patient, student and staff IDs | The model |

Every finding says what it is, where it is, how sure Veil is, and how strongly its format is documented, from `ISSUER_CONFIRMED` when the issuing body publishes it to `UNPUBLISHED` when Veil relies on context alone. The sources for every Ghanaian format are in [`country-packs/gh/identifiers.yaml`](country-packs/gh/identifiers.yaml). Findings never hold the value they found, so they're safe to log; slice the text with `start` and `end` when you need it.

## Policies

A policy decides what happens to each kind of detail. The built-in `default-protection` blocks credentials and Ghana Card PINs, masks phone numbers so a person can still recognise them, and replaces everything else with a typed placeholder.

| Action | What it does |
| --- | --- |
| `mask` | Keeps part of the value, as in `024 *** 4567` |
| `redact` | Replaces the value with a typed placeholder such as `[EMAIL_ADDRESS]` |
| `tokenize` | Replaces it with a numbered placeholder such as `[EMAIL_ADDRESS_1]` that you can restore in a reply |
| `block` | Refuses the whole text |
| `allow`, `detect` | Leaves the value alone, reporting it with `detect` |

You can write your own policy in YAML, with rules that match on entity types, categories, confidence or where the text is going. [docs/policies.md](docs/policies.md) covers the format.

```python
veil = Veil(policy_yaml=open("support-desk.yaml").read())
out = veil.protect("Email ama@example.com about the refund", restore=True)
reply = ask_model(out.text)          # the model sees [EMAIL_ADDRESS_1]
print(out.restore(reply))           # your user sees ama@example.com
```

## The model

Rules find what has a published format. Names and directions don't have one, so Veil can also run a small contextual model on the same machine. [`veil-ner-nano`](https://huggingface.co/dekka-cloud/veil-ner-nano) is 56 MB and reads a kilobyte of text in about 40 ms on one thread of a 2020 Apple M1, and [`veil-ner-deep`](https://huggingface.co/dekka-cloud/veil-ner-deep) is larger and more precise on Twi and Ewe names. Both are released under CC BY 4.0, with cards that set out how they were trained and measured.

```python
veil = Veil(model="veil-ner-nano")   # downloaded once from Hugging Face and checked against its manifest
veil.protect("Me din de Akosua Mensah, patient PT-204118. Frɛ me wɔ 024 412 3456.").text
# 'Me din de [PERSON_NAME], patient [PATIENT_ID]. Frɛ me wɔ 024 *** 3456.'
```

With a model, scans run the `hybrid` profile, where the rules decide every structured identifier and the model adds what only context reveals. `rules` runs the rules alone and `nano` runs the model alone. If the model can't run, Veil falls back to the rules and says so in the result, so a partial scan is never mistaken for a full one. [docs/models.md](docs/models.md) has the details.

## In the browser

The npm package runs Veil's engine as WebAssembly in browsers, and with a model it runs the graph on the device through [onnxruntime-web](https://www.npmjs.com/package/onnxruntime-web), so the text never leaves the page. Install `onnxruntime-web` beside `dekka-veil` to use a model there. The browser build finds the same spans as the native one, and [`examples/browser`](examples/browser) is a page you can open to try it.

```js
const veil = await Veil.load({ model: "veil-ner-nano" });            // or modelUrl: "https://your-cdn/veil-ner-nano/"
```

## Offsets

Veil works in UTF-8 bytes internally, and each library reports spans in its own language's string units, code points in Python and UTF-16 units in JavaScript, so `text[start:end]` and `text.slice(start, end)` give back exactly what was found. [docs/offsets.md](docs/offsets.md) explains how normalisation keeps spans pointing at the original text.

## This repository

| Path | What it holds |
| --- | --- |
| `crates/veil` | The Rust library: one builder for the engine, the country packs, a policy and a model |
| `crates/veil-core`, `veil-detectors`, `veil-policy`, `veil-country-packs`, `veil-inference` | The engine, the general detectors, policies, the Ghana pack's detectors and the model runtime |
| `bindings/python` | The `dekka-veil` Python library |
| `bindings/js` | The `dekka-veil` npm library, with its native and WebAssembly builds |
| `country-packs/gh` | The Ghana pack's data, sources and test fixtures |
| `policies` | Built-in policies and their test cases |
| `docs` | Policies, models, country packs and offsets |

## Building from source

The workspace builds with the Rust toolchain pinned in `rust-toolchain.toml`.

```bash
cargo test --workspace

cd bindings/python && python -m venv .venv && .venv/bin/pip install maturin pytest \
  && .venv/bin/maturin develop && .venv/bin/pytest

cd bindings/js && npm ci && npm run build && npm test     # needs the wasm32-unknown-unknown target and wasm-bindgen
```

## Limits

No detector finds everything, so treat Veil as a layer that reduces what leaves your systems, alongside choosing where your text goes. The model's scores come from mostly synthetic Ghanaian text, which flatters every system, and its cards say how it does on real text.

## Licence

Veil is released under the [Apache License 2.0](LICENSE). The data it ships is credited in [NOTICE](NOTICE), and the models are released separately under CC BY 4.0. Veil is built by [Dekka](https://dekka.cloud) in Accra and protects prompts in Dekka's AI Gateway.
