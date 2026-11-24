# dekka-veil

Veil finds personal information in text and protects it before the text goes somewhere it shouldn't, such as a prompt on its way to an AI model. It runs on your own machine and was built for Ghanaian text, from Ghana Card PINs and mobile money numbers read aloud in Akan or Ewe to GhanaPost GPS addresses, alongside the emails, card numbers and credentials any text can hold. An optional open model adds names, addresses given as directions and institutions' own ID numbers.

```bash
pip install dekka-veil
```

```python
from dekka_veil import Veil

veil = Veil(country="GH")
out = veil.protect("Please call 024 123 4567 or write to ama@example.com")
out.text        # 'Please call 024 *** 4567 or write to [EMAIL_ADDRESS]'
out.decisions   # what was found, where, and what the policy did with it
```

Build one `Veil` and reuse it. Every call is thread-safe and releases the GIL while it scans.

## Detecting without changing anything

```python
text = "Send the MoMo to 024 123 4567"
for finding in veil.detect(text):
    print(finding.entity_type, text[finding.start:finding.end], finding.confidence)
# GH_MOBILE_NUMBER 024 123 4567 0.95
```

Findings and decisions never hold the value they found, so they're safe to log. Their `start` and `end` index your Python string directly.

## Adding the model

```python
veil = Veil(model="veil-ner-nano")
veil.protect("Me din de Akosua Mensah, patient PT-204118.").text
# 'Me din de [PERSON_NAME], patient [PATIENT_ID].'
```

The first use downloads [veil-ner-nano](https://huggingface.co/dekka-cloud/veil-ner-nano) from Hugging Face into `~/.cache/dekka-veil` (or `$DEKKA_VEIL_CACHE`) and checks every file against the SHA-256 in its manifest. Pass `"veil-ner-deep"` for the larger model, a directory path for a model you keep yourself, and `revision=` to pin a commit. With a model, scans run the `hybrid` profile, rules and model together.

## Policies

`default-protection` blocks credentials and Ghana Card PINs, masks phone numbers and redacts everything else. Write your own in YAML and pass it as `policy=Path("policy.yaml")` or `policy_yaml="..."`.

```python
from pathlib import Path

veil = Veil(policy=Path("support-desk.yaml"))       # a policy that tokenises
out = veil.protect("Email ama@example.com about the refund", restore=True)
reply = ask_model(out.text)                         # the model sees [EMAIL_ADDRESS_1]
out.restore(reply)                                   # puts ama@example.com back
```

`protect_all` protects several texts together, such as the messages of one chat, so the same value gets the same placeholder in each. `context={"destination_provider": "openai"}` lets policy rules match on where the text is going. `validate_policy(yaml)` lists every problem in a policy with its path.

## More

The [repository](https://github.com/dekka-cloud/veil) has the full documentation of policies, models, country packs and offsets. Veil is released under the Apache License 2.0, and its models under CC BY 4.0.
