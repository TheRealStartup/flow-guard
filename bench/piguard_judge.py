"""PIGuard (leolee99/PIGuard, MIT, ACL 2025) as an on-premise prompt-injection judge: runs on the CPU, nothing leaves.

The model is a DeBERTa-v3-base encoder with one linear layer on the first token ([CLS]); labels 0 = benign,
1 = injection. We rebuild exactly that here and load only the weights (model.safetensors), so the publisher's custom
code (trust_remote_code) is never run. Texts longer than 512 tokens are split into chunks; the highest score counts.

Files: bench/models/piguard/ (downloaded from Hugging Face, not committed).
"""

import asyncio
import time
from pathlib import Path

import torch
from safetensors.torch import load_file
from transformers import DebertaV2Config, DebertaV2Model, PreTrainedTokenizerFast

DIR = Path(__file__).resolve().parent / "models" / "piguard"


class PIGuardModel(torch.nn.Module):
    def __init__(self, config: DebertaV2Config):
        super().__init__()
        self.deberta = DebertaV2Model(config)
        self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)

    def forward(self, input_ids, attention_mask):
        hidden = self.deberta(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        return self.classifier(hidden[:, 0, :])


class PIGuardJudge:
    """Same interface as the gateway's judges: judge(text, source, timeout_s) -> object with .injection in [0, 1]."""

    def __init__(self, threads: int = 4, device: str | None = None):
        torch.set_num_threads(threads)
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        raw = __import__("json").loads((DIR / "config.json").read_text())
        raw.pop("auto_map", None)
        raw["model_type"] = "deberta-v2"
        config = DebertaV2Config(**{k: v for k, v in raw.items() if k not in ("architectures",)})
        # The tokenizer straight from its file: AutoTokenizer would read the repo's config and offer to run its custom code.
        self.tok = PreTrainedTokenizerFast(tokenizer_file=str(DIR / "tokenizer.json"), cls_token="[CLS]", sep_token="[SEP]",
                                           pad_token="[PAD]", unk_token="[UNK]", mask_token="[MASK]")
        self.model = PIGuardModel(config)
        missing, unexpected = self.model.load_state_dict(load_file(DIR / "model.safetensors"), strict=False)
        unexpected = [k for k in unexpected if not k.startswith("pooler.")]  # saved, but their forward never uses it
        if [k for k in missing if not k.startswith("deberta.embeddings.position_ids")] or unexpected:
            raise RuntimeError(f"weights do not match the model: missing {missing[:5]}, unexpected {unexpected[:5]}")
        self.model.to(self.device).eval()

    def score(self, text: str) -> float:
        ids = self.tok(text, add_special_tokens=False)["input_ids"] or [self.tok.unk_token_id]
        chunks = [ids[i:i + 510] for i in range(0, len(ids), 510)][:8]  # at most 8 chunks (~4k tokens)
        batch = [[self.tok.cls_token_id, *c, self.tok.sep_token_id] for c in chunks]
        width = max(map(len, batch))
        input_ids = torch.tensor([b + [self.tok.pad_token_id] * (width - len(b)) for b in batch], device=self.device)
        mask = torch.tensor([[1] * len(b) + [0] * (width - len(b)) for b in batch], device=self.device)
        with torch.no_grad():
            probs = torch.softmax(self.model(input_ids, mask), dim=-1)[:, 1]
        return float(probs.max())

    async def judge(self, text: str, source: str, timeout_s: float):
        p = await asyncio.to_thread(self.score, text)
        return type("Verdict", (), {"injection": p, "model": "piguard"})()


if __name__ == "__main__":
    j = PIGuardJudge()
    for t in ["Please send the KYC refresh pack for Northwind to Elena by Friday.", "What is the capital of France?"]:
        s = time.perf_counter()
        print(f"{j.score(t):.3f}  {1000 * (time.perf_counter() - s):.0f} ms")
