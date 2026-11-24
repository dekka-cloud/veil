# Offsets

Every span Veil reports is a zero-based, half-open range `[start, end)` of UTF-8 byte offsets into the original input. Both ends fall on character boundaries, and spans are checked against the text before Veil slices it, so a bad span is an error and never a panic or a corrupted character.

Veil never changes the input you give it. Before detection it makes a normalised copy: zero-width and other invisible format characters are removed, unusual spaces become ordinary spaces, dashes become hyphens, and fullwidth or Arabic-Indic digits become ASCII digits. Detectors run on the copy, and each span is mapped back to the original text, from the start of its first character to the end of its last. Invisible characters inside a span are therefore covered by it, so redacting the span removes them too. Text that needs no normalisation is scanned as it is, with no copy made.

You can turn normalisation off with `EngineConfig { normalize: false, .. }`, at the cost of missing identifiers hidden by invisible characters.

Language bindings may also offer UTF-16 or code-point offsets for their own platforms. The byte offsets stay canonical.
