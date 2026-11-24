# dekka-veil

Veil finds personal information in text and protects it before the text goes somewhere it shouldn't, such as a prompt on its way to an AI model. It runs in Node.js and in the browser, entirely on the device, and was built for Ghanaian text, from Ghana Card PINs and mobile money numbers read aloud in Akan or Ewe to GhanaPost GPS addresses, alongside the emails, card numbers and credentials any text can hold. An optional open model adds names, addresses given as directions and institutions' own ID numbers.

```bash
npm install dekka-veil
```

```js
import { Veil } from "dekka-veil";

const veil = await Veil.load({ country: "GH" });
const out = await veil.protect("Please call 024 123 4567 or write to ama@example.com");
out.text;        // 'Please call 024 *** 4567 or write to [EMAIL_ADDRESS]'
out.decisions;   // what was found, where, and what the policy did with it
```

In Node.js, Veil runs as a native addon and scans on libuv's thread pool, so your server keeps answering while it works. In browsers it runs as WebAssembly. The API is the same in both, and the right build loads automatically.

## Detecting without changing anything

```js
const text = "Send the MoMo to 024 123 4567";
const { findings } = await veil.detect(text);
findings.map((f) => [f.entityType, text.slice(f.start, f.end)]);
// [['GH_MOBILE_NUMBER', '024 123 4567']]
```

Findings and decisions never hold the value they found, so they're safe to log. Their `start` and `end` count UTF-16 units, so they slice JavaScript strings directly.

## Adding the model

```js
const veil = await Veil.load({ model: "veil-ner-nano" });
(await veil.protect("Me din de Akosua Mensah, patient PT-204118.")).text;
// 'Me din de [PERSON_NAME], patient [PATIENT_ID].'
```

[veil-ner-nano](https://huggingface.co/dekka-cloud/veil-ner-nano) is downloaded once from Hugging Face and checked against the SHA-256 in its manifest. In Node it's cached in `~/.cache/dekka-veil` (or `$DEKKA_VEIL_CACHE`), and you can pass a directory path instead of a name. In the browser it's kept in Cache Storage, and it runs on the device through onnxruntime-web, which you install beside this package:

```bash
npm install dekka-veil onnxruntime-web
```

To serve the model from your own host, pass `modelUrl` with a base URL that holds `manifest.yaml`, `tokenizer.json` and `model.onnx`. If your bundler moves the engine's `.wasm` file, pass its URL as `wasm`.

## Policies

`default-protection` blocks credentials and Ghana Card PINs, masks phone numbers and redacts everything else. Pass your own policy written in YAML as `policyYaml`.

```js
const veil = await Veil.load({ policyYaml: supportDeskPolicy });   // a policy that tokenises
const out = await veil.protect("Email ama@example.com about the refund", { restore: true });
const reply = await askModel(out.text);                            // the model sees [EMAIL_ADDRESS_1]
out.restore(reply);                                                 // puts ama@example.com back
```

`protectAll` protects several texts together, such as the messages of one chat, so the same value gets the same placeholder in each. `context: { destinationProvider: "openai" }` lets policy rules match on where the text is going. `validatePolicy(yaml)` lists every problem in a policy with its path.

## More

The [repository](https://github.com/dekka-cloud/veil) has the full documentation of policies, models, country packs and offsets, and a browser example. Veil is released under the Apache License 2.0, and its models under CC BY 4.0.
