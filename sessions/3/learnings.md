# Learnings — Session 3 (2026-07-09)

1. **A /contract is semantic, not computable.** Natural-language role/owns/boundaries cannot be enforced via static heuristics. Only path-ownership (is this agent's cwd/tool-path inside another agent's repo?) is deterministically computable. Attempted to keyword-match BOUNDARIES items — Sunir caught it immediately.

2. **Two-layer pattern for semantically irreducible classification.** Cheap deterministic check in the hot path (path-ownership, fast, no latency), LLM semantic judgment out-of-band (fire-and-forget, advisory, never blocking). This pattern generalizes beyond contract enforcement.

3. **"Similarity proposes, consequence disposes."** Intel item (Reddit, high signal 6.6). LLM judgment is a proposal; only consequence-bearing signals (success/failure, user correction) validate it. Haiku's semantic check is a proposal — advisory-only by design.

4. **Get the design right before writing code.** Story revised twice before implementation started. Cost: two commits. Savings: an entire wrong implementation. The story discipline works when combined with fast external feedback.

5. **The correction cost nothing because I waited.** No code was written between the first story commit and Sunir's correction. The right moment to accept design feedback is before implementation, not after.
