# Ghana fixtures

Each line of a `.jsonl` file is one case: the input `text`, the findings Veil must report
in `expect` (by entity type and exact value, plus any context labels that must be
present), and a `note` saying what the case checks. A case with an empty `expect` is a
hard negative: text that looks like personal information but isn't, which Veil must leave
alone.

Every value here was made up for these tests. None was collected from a real person, and
any match with a real number or card is a coincidence. Real personal information must
never be added to these files.
