"""Builds the tiny model in tests/fixtures/tiny, which the crate's tests load in place of a real
one. It has the same inputs, outputs and files as an exported Veil model, but no encoder: each
token's logits are a fixed row of an embedding table, so its predictions are known in advance.

    python make_tiny.py      (needs torch, onnx and tokenizers)

"Ama" and "Kofi" begin a name and "Mensah" continues one, "Osu" is an address, and a ten-digit
number is a mobile number, which in the hybrid profile the rules must win. "Kwame" is a name
with low confidence, below the manifest's threshold. Every other word is O.
"""

import hashlib
from pathlib import Path

import torch
from tokenizers import Tokenizer, models, pre_tokenizers, processors

HERE = Path(__file__).resolve().parent / "tiny"
LABELS = ["O", "B-PERSON_NAME", "I-PERSON_NAME", "B-ADDRESS", "I-ADDRESS", "B-GH_MOBILE_NUMBER", "I-GH_MOBILE_NUMBER"]
WORDS = ["[PAD]", "[UNK]", "[CLS]", "[SEP]", "Ama", "Mensah", "Kofi", "Kwame", "Osu", "0241234567", "call", "lives", "in", "on", ",", "."]
STRONG = {"Ama": "B-PERSON_NAME", "Kofi": "B-PERSON_NAME", "Mensah": "I-PERSON_NAME", "Osu": "B-ADDRESS", "0241234567": "B-GH_MOBILE_NUMBER"}


def main() -> None:
    HERE.mkdir(parents=True, exist_ok=True)
    vocab = {w: i for i, w in enumerate(WORDS)}
    tok = Tokenizer(models.WordLevel(vocab, unk_token="[UNK]"))
    tok.pre_tokenizer = pre_tokenizers.Whitespace()
    tok.post_processor = processors.TemplateProcessing(single="[CLS] $A [SEP]", special_tokens=[("[CLS]", 2), ("[SEP]", 3)])
    tok.save(str(HERE / "tokenizer.json"))

    table = torch.zeros(len(WORDS), len(LABELS))
    table[:, 0] = 4.0
    for word, label in STRONG.items():
        table[vocab[word], 0] = 0.0
        table[vocab[word], LABELS.index(label)] = 6.0
    table[vocab["Kwame"], 0] = 0.0
    table[vocab["Kwame"], LABELS.index("B-PERSON_NAME")] = 0.3

    class Tiny(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.table = torch.nn.Embedding.from_pretrained(table)

        def forward(self, input_ids, attention_mask):
            return self.table(input_ids) * attention_mask.unsqueeze(-1).to(torch.float32)

    ids = torch.tensor([[2, 4, 5, 3], [2, 4, 3, 0]])
    mask = torch.tensor([[1, 1, 1, 1], [1, 1, 1, 0]])
    torch.onnx.export(
        Tiny().eval(), (ids, mask), str(HERE / "model.onnx"),
        input_names=["input_ids", "attention_mask"], output_names=["logits"],
        dynamic_axes={"input_ids": {0: "batch", 1: "sequence"}, "attention_mask": {0: "batch", 1: "sequence"}, "logits": {0: "batch", 1: "sequence"}},
        opset_version=18, dynamo=False,
    )

    def sha(name: str) -> str:
        return hashlib.sha256((HERE / name).read_bytes()).hexdigest()

    labels = "\n".join(f"  - {label}" for label in LABELS)
    (HERE / "manifest.yaml").write_text(f"""# A test fixture, not a real model: see tests/fixtures/make_tiny.py.
format: 1
id: veil-ner-tiny
version: 0.0.1
model:
  file: model.onnx
  sha256: {sha("model.onnx")}
tokenizer:
  file: tokenizer.json
  sha256: {sha("tokenizer.json")}
  max_length: 8
  stride: 2
labels:
{labels}
threshold: 0.5
runtime:
  veil: 0.1.0
""")


if __name__ == "__main__":
    main()
