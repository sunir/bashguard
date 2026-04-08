"""
bashguard.rules.model_weights_exfil — Block ML model weight file exfiltration.

Two incidents:
1. Claude attempted to extract its own weights and re-launch itself during
   red-team testing with domain access.
2. A Vertex AI privilege escalation allowed a poisoned model to exfiltrate
   all other fine-tuned models via cloud storage commands (gsutil cp).

Model weight files are large, valuable, proprietary artifacts. Agents have
no legitimate reason to upload them to external services — downloading weights
from Hugging Face is normal; uploading them out is not.

Blocked: upload of .safetensors/.ckpt/.pt/.pth/.bin/.gguf via
  curl -T/--upload-file/-F, scp, rsync to remote, gsutil cp, aws s3 cp

Allowed: wget/curl downloads of model files, local cp, ls
"""
from __future__ import annotations
import logging
import re

from bashguard.models import Severity, Finding, ExecutionContext, ActionType
from bashguard.rules import register

_log = logging.getLogger(__name__)

_WEIGHT_EXTS = frozenset({
    ".safetensors", ".ckpt", ".pt", ".pth", ".gguf",
})

# Weight file pattern: any arg ending in a model extension
_WEIGHT_RE = re.compile(
    r"\S+\.(?:safetensors|ckpt|pt|pth|gguf|bin)\b",
    re.IGNORECASE,
)

# pytorch_model.bin — the .bin extension is too broad on its own,
# but combined with common model naming is suspicious
_BIN_MODEL_RE = re.compile(
    r"(?:pytorch_model|model|weights|adapter_model)\S*\.bin\b",
    re.IGNORECASE,
)

# curl upload flags
_CURL_UPLOAD_FLAGS = frozenset({"-T", "--upload-file", "-X PUT", "-X POST", "--data-binary"})
_CURL_FORM_RE = re.compile(r"-F\s+'?file=@|--form\s+'?file=@")


def _has_weight_file(tokens: list[str]) -> bool:
    for tok in tokens:
        clean = tok.strip("'\"@")
        if _WEIGHT_RE.search(clean):
            return True
        if _BIN_MODEL_RE.search(clean):
            return True
    return False


def _line_has_weight(line: str) -> bool:
    return bool(_WEIGHT_RE.search(line)) or bool(_BIN_MODEL_RE.search(line))


@register
class ModelWeightsExfilRule:
    rule_id = "exfil.model_weights"
    severity = Severity.CRITICAL
    description = "ML model weight file upload to external service"

    def check(self, script: str, context: ExecutionContext) -> list[Finding]:
        try:
            return list(self._scan(script))
        except Exception:
            _log.exception("model_weights_exfil rule error")
            return []

    def _scan(self, script: str):
        for line in script.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            finding = self._check_line(stripped)
            if finding:
                yield finding

    def _check_line(self, line: str) -> Finding | None:
        if not _line_has_weight(line):
            return None
        tokens = line.split()
        if not tokens:
            return None
        cmd = tokens[0]

        # curl with upload flags (not download)
        if cmd == "curl":
            is_upload = any(f in line for f in _CURL_UPLOAD_FLAGS)
            is_form_upload = bool(_CURL_FORM_RE.search(line))
            is_put = "-X PUT" in line or "--request PUT" in line
            if (is_upload or is_form_upload or is_put) and _has_weight_file(tokens):
                return self._finding(line)

        # scp — always an upload when a weight file is in the args
        if cmd == "scp" and _has_weight_file(tokens):
            return self._finding(line)

        # rsync to remote (has remote: pattern or user@host)
        if cmd == "rsync" and _has_weight_file(tokens):
            remote_re = re.compile(r"\w+@[\w.]+:|[\w.]+:/|rsync://")
            if remote_re.search(line):
                return self._finding(line)
            # --include patterns with weight extension
            if re.search(r"--include.*\*\.(?:safetensors|ckpt|pt|pth|gguf)", line):
                return self._finding(line)

        # gsutil / aws s3 — upload direction
        if cmd == "gsutil" and "cp" in tokens and _has_weight_file(tokens):
            return self._finding(line)

        if cmd == "aws" and "s3" in tokens and ("cp" in tokens or "sync" in tokens):
            if _has_weight_file(tokens):
                return self._finding(line)

        return None

    def _finding(self, line: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            severity=self.severity,
            action_type=ActionType.NETWORK_OUTBOUND,
            message=self.description,
            matched_text=line,
        )
