# Contextual models

Rules find what has a published format, such as phone numbers, Ghana Card PINs and digital addresses. Names, informal addresses and identifiers that only context reveals need a model. Veil runs one on the CPU with ONNX Runtime, through the `veil-inference` crate, and never sends text anywhere to do it.

## Profiles

| Profile | What runs | Needs a model |
| --- | --- | --- |
| `rules` | The pattern detectors alone. The default everywhere. | No |
| `nano` | The model alone. | Yes |
| `hybrid` | Rules and model together. Rules decide every structured type (phones, Ghana Card PINs, digital addresses, TINs, plates, emails, cards and IP addresses), and a model finding that overlaps a rules finding is dropped. | Yes |

Asking for `nano` or `hybrid` without a model is an error, never a quiet answer from the rules. If the model fails during a scan, the rules' result comes back with `profile_used: rules` and a warning that says the model didn't run, so a caller can tell a rules fallback from a full scan.

## The model directory

Veil loads a model from a directory holding three files:

- `model.onnx`, the int8 graph, with inputs `input_ids` and `attention_mask` and output `logits`.
- `tokenizer.json`, the Hugging Face tokenizer it was trained with.
- `manifest.yaml`, which pins both files by SHA-256 and gives the label order, the confidence threshold, the tokenizer window and the oldest Veil that can run it.

```yaml
format: 1
id: veil-ner-nano
version: 0.2.0
model: { file: model.onnx, sha256: 7d09… }
tokenizer: { file: tokenizer.json, sha256: b5d5…, max_length: 256, stride: 32 }
labels: [O, B-ACCOUNT_HOLDER_NAME, I-ACCOUNT_HOLDER_NAME, …]
threshold: 0.6
runtime: { veil: 0.1.0 }
```

Loading fails if a file doesn't match its checksum, if the labels don't match the graph's output, or if the manifest asks for a newer Veil. Weights are never committed to this repository; the released models live on Hugging Face, where each card records how the model was trained, what it was trained on and how it scores.

Text longer than the model's window is split into windows that overlap by `stride` tokens, and each token keeps the label from the window where it sits furthest from an edge. A span's confidence is the mean probability of its tokens' labels, and spans below `threshold` are dropped. Offsets are UTF-8 byte offsets, like every other finding, and the Python and JavaScript libraries convert them to their own string indices.

The threshold is chosen on real sentences, never on synthetic text alone, because a confident model is nearly always right on synthetic text, so a threshold set there climbs too high and throws away most names in real text.

## The released models

| Model | What it is | Size | Speed for 1 KB, one thread |
| --- | --- | --- | --- |
| [`veil-ner-nano`](https://huggingface.co/dekka-cloud/veil-ner-nano) | A two-layer DeBERTa-v3-xsmall student | 56 MB at int8 | about 40 ms on a 2020 Apple M1 |
| [`veil-ner-deep`](https://huggingface.co/dekka-cloud/veil-ner-deep) | mDeBERTa-v3-base, more precise on Twi and Ewe names | 536 MB, embeddings at int8 | 1.2 to 1.5 s on the same machine |

Both are released under CC BY 4.0. The timings come from a machine running other work, so treat them as indications.

## Using a model

The Python and JavaScript libraries download a released model by name the first time you ask for it, check it against its manifest and keep it in a cache:

```python
from dekka_veil import Veil

veil = Veil(model="veil-ner-nano")
```

```js
import { Veil } from "dekka-veil";

const veil = await Veil.load({ model: "veil-ner-nano" });
```

From Rust, with the `model` feature, point the builder at a model directory:

```rust
let veil = Veil::builder().model_dir("models/veil-ner-nano").profile(Profile::Hybrid).build()?;
```

One inference uses one thread by default. Calls take turns on the model, so a busy service should run more processes rather than more threads per inference.

## Runtimes

`veil-inference` splits a model's work in two. Tokenising, windowing and decoding need nothing native, so they build everywhere, WebAssembly included. Running the graph uses `ort` 2.0.0-rc.10, which links ONNX Runtime 1.22 statically, so the Python wheels and Node binaries need no extra libraries. In a browser the graph runs in onnxruntime-web instead, and the engine decodes its output with the same code, so the same model finds the same spans. On int8 graphs, different ONNX Runtime versions can round quantised arithmetic differently, so a token whose label probabilities are nearly tied can occasionally land on the other side.
