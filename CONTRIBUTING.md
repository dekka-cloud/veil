# Contributing

Thank you for helping. Bugs, missed findings and false positives are most useful as an issue with a short example; please use made-up values, never real personal information.

## Working on the code

The Rust workspace builds with the toolchain pinned in `rust-toolchain.toml`. Before opening a pull request, run:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Changes to the Python or JavaScript library should pass their own tests too; the main README shows how to run them.

## Adding an identifier

Every format Veil detects rests on a published source. Add the format and its source to the country pack's `identifiers.yaml`, with how strong that evidence is, then the detector, then fixtures that cover real shapes and the look-alikes it must leave alone, such as switchboard numbers or invoice codes. Fixtures use synthetic values that follow the documented shape and belong to no one.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, like the rest of the project.
