# Country packs

A country pack holds everything Veil knows about one country's identifiers: its manifest, the data its detectors read, and the fixtures that test them. Packs are versioned apart from the engine, so a numbering plan change ships as a pack update.

The Ghana pack lives in `country-packs/gh/`:

| File | What it holds |
| --- | --- |
| `manifest.toml` | Pack id, version, entity types, languages and each entity's evidence level |
| `numbering.toml` | Mobile and fixed-line patterns vendored from libphonenumber |
| `ghana-card.toml` | Ghana Card PIN structure and context words |
| `digital-address.toml` | GhanaPost GPS regions and the 261 published district codes |
| `patterns.toml` | Pattern detectors for taxpayer IDs, vehicle plates, and context-only bank account, passport and voter ID numbers, each with its source and validation strength |
| `identifiers.yaml` | Every Ghanaian identifier format Veil knows, with the published sources behind it and how strong they are |
| `fixtures/*.jsonl` | Positive cases and hard negatives |
| `THIRD_PARTY.md` | Licences for vendored data |

## Evidence and validation

Every entity the Ghana pack reports has an evidence level in the identifier registry, [`identifiers.yaml`](../country-packs/gh/identifiers.yaml), which `manifest.toml` copies and every finding carries as `evidence`:

| Level | Meaning |
| --- | --- |
| `ISSUER_CONFIRMED` | The issuing body publishes the format, directly or in a filing it made |
| `INTERNATIONAL_STANDARD` | An international standard such as ICAO Doc 9303 defines it |
| `SECONDARY` | Only maintained secondary references describe it |
| `UNPUBLISHED` | No format is published, so the pack reports a match only beside a word that names it |

Evidence describes the specification behind a detector, while `validation` describes one finding: `VALID` means it passed a published check, `VALID_FORMAT` that it matches the documented shape, and `UNVERIFIED` that nothing more than the pattern and its context was checked. A test in `crates/veil-country-packs/tests/evidence.rs` fails if a detector reports an entity the registry doesn't list, or if the manifest and the registry disagree.

Recognising a format is not verifying an identity. A Ghana Card PIN is reported as `VALID_FORMAT` at most, because the NIA doesn't publish the algorithm behind its check character, so Veil can't tell a real PIN from a well-formed invented one. No code path in the pack returns `VALID` for a Ghana Card PIN, and the same test file checks that for fixed and generated PINs. None of Veil's validation states says that an identifier exists or belongs to anyone.

Data files are compiled into the binary and parsed when the pack loads, and a malformed file fails the test suite. Each one records its source and the date it was checked. Values come from issuing authorities or maintained public metadata; where a format isn't published, the pack doesn't guess.

A new pack adds a folder under `country-packs/`, a module in `crates/veil-country-packs`, and an entry in `PACKS`. Avoid a generic regional pattern that ignores how each country actually formats its identifiers.
