# Policies

A policy decides what happens to each piece of personal information or secret Veil finds. Detection stays separate: a finding is evidence, and the policy turns it into an action.

```yaml
version: 1
name: support-desk
revision: "2026-11-04"
on_failure: closed
default_action: redact

rules:
  - id: block-credentials
    match:
      categories: [CREDENTIAL]
    action: block

  - id: keep-mobile-money-numbers-for-agents
    match:
      entity_types: [GH_MOBILE_NUMBER]
      context_labels: [MOBILE_MONEY]
      destinations: [internal-crm]
    action: mask

  - id: tokenize-for-external-models
    match:
      categories: [PERSONAL_IDENTIFIER]
      destinations: [openai, anthropic]
    action: tokenize
```

## Actions

| Action | What happens |
| --- | --- |
| `detect` | The finding is reported and the text is left alone |
| `allow` | The same as detect, stated as a deliberate decision |
| `mask` | Part of the value stays readable, such as `024 *** 4567` |
| `redact` | The value becomes a typed placeholder, such as `[GH_MOBILE_NUMBER]` |
| `tokenize` | The value becomes a numbered placeholder, such as `[GH_MOBILE_NUMBER_1]`, and the same value gets the same number within one request |
| `block` | The whole input is refused and no output is produced |

Tokenisation is stateless. The library returns the placeholders and their values in an in-memory restore map, so a caller such as an AI gateway can put real values back into a model's reply. The map is never serialised, its debug output hides the values, and it should be dropped when the request ends. Tokenised text is pseudonymised, not anonymised, and remains personal data.

## Matching

Every condition in a `match` must hold. A list condition holds when any of its values does.

| Condition | Matches when |
| --- | --- |
| `entity_types` | The finding is one of these entity codes |
| `categories` | The finding has any of these categories, such as `CREDENTIAL` or `FINANCIAL_INFORMATION` |
| `families` | The finding is `PII`, `SECRET` or `SENSITIVE_CONTENT` |
| `min_sensitivity` | The finding is at least this sensitive, from `PUBLIC` to `HIGHLY_SENSITIVE` |
| `min_validation` | The finding was validated at least this strongly: `UNVERIFIED`, `VALID_FORMAT` or `VALID` |
| `min_confidence` | The finding's confidence is at least this, between 0 and 1 |
| `jurisdictions` | The finding belongs to one of these countries, such as `GH` |
| `detectors` | One of these detectors found it, such as `gh-phone-v1` |
| `context_labels` | The finding carries one of these labels, such as `MOBILE_MONEY` or `SSNIT` |
| `destinations`, `applications`, `environments`, `purposes` | The request's matching attribute is one of these. A request that doesn't say never matches |

A rule must have at least one condition. Use `default_action` for everything no rule matches.

## Precedence

When several rules match one finding, precedence decides, never the order of the file:

1. A matching `block` rule always wins.
2. A rule naming `entity_types` beats any rule that doesn't.
3. A contextual rule, meaning one with context labels, detectors, jurisdictions or request attributes, beats a rule that only looks at categories, families, sensitivity, validation or confidence.
4. Within the same tier, the rule with more conditions wins, then the rule listing fewer entity types.
5. Only when two rules tie on all of that does the one listed first win.
6. When nothing matches, `default_action` applies.

Every decision records which rule made it, by position and `id`, along with the policy's name, schema version and revision. Decisions never contain the values they applied to.

## When a scan can't complete

`on_failure` says what happens when Veil can't finish scanning, for example because the input is over the size limit or a model the profile needs isn't available.

| Setting | What happens |
| --- | --- |
| `closed` | The request is blocked. This is the default and the right choice for anything leaving your systems |
| `open` | The original text passes through, with a warning that it wasn't checked |
| `rules_fallback` | If a model profile is unavailable, the rules run alone and the result says it wasn't a complete hybrid scan. Any other failure blocks |

A rules-only fallback is never reported as a complete scan.

## Built-in policies

`default-protection` blocks credentials and Ghana Card PINs, masks phone numbers and redacts everything else. It is in [`policies/default-protection.yaml`](../policies/default-protection.yaml), with test cases beside it.

## Checking a policy

Each library validates a policy and reports every problem with its path, such as `rules[2].match.min_confidence: must be between 0 and 1`. An empty list means the policy is valid.

```python
from pathlib import Path
from dekka_veil import Veil, validate_policy

problems = validate_policy(Path("my-policy.yaml").read_text())
veil = Veil(policy=Path("my-policy.yaml"))
veil.protect(prompt, context={"destination_provider": "openai"})
```

```js
import { Veil, validatePolicy } from "dekka-veil";

const problems = await validatePolicy(yaml);
const veil = await Veil.load({ policyYaml: yaml });
await veil.protect(prompt, { context: { destinationProvider: "openai" } });
```

Keep test cases beside a policy, as [`policies/default-protection.cases.jsonl`](../policies/default-protection.cases.jsonl) does, with an `input` and the expected `output` or `blocked`, and run them in your own tests.
