# Contributing to BD-OSINT

1. Fork, branch (`feature/xyz`), commit with clear messages.
2. Run `pytest` — all tests must pass.
3. Keep the safety invariants:
   - No credential theft, brute force, exploitation, or auth bypass code.
   - Active checks stay gated behind `--profile authorized`.
   - Findings must remain conservative (observed / potential / verified).
   - Redaction must never be weakened.
4. Add tests for any new parsing/detection logic.
5. Open a PR describing scope, motivation, and test evidence.
