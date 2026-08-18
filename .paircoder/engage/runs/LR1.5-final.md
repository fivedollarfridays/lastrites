status: done
ac_verified: true (4/4 checked)

---

Perfect! Let me create a summary of what was accomplished:

## Task LR1.5 Completed: Contract Conformance + CI

### Acceptance Criteria ✅

All 4 acceptance criteria are satisfied:

1. **Conformance suite exists** ✅
   - Created \`tests/test_threat_model_conformance.py\` with 21 executable tests
   - Every THREAT-MODEL sharp-edge (§1–§7) maps to at least one test
   - 51 references to THREAT-MODEL sections by number throughout the file

2. **CI workflow implemented** ✅
   - Created \`.github/workflows/ci.yml\` with three enforcement gates:
     - \`pytest -n auto --dist=worksteal\` (all 354 tests passing)
     - \`ruff check . && ruff format --check .\` (code quality)
     - \`gitleaks detect\` (secret scanning)

3. **README updated** ✅
   - Added CI badge at top of README
   - Added "Threat model conformance" section linking to \`tests/test_threat_model_conformance.py\`
   - Documents verified sections and CI gate requirements

4. **All tests passing** ✅
   - 354 tests pass via \`pytest -n auto --dist=worksteal\`
   - All conformance tests pass (21/21)
   - No ruff violations

### What Was Delivered

**Conformance Test Suite** (\`tests/test_threat_model_conformance.py\`):
- §3: No raw values persisted (3 tests) — verified by planting secrets through store/canary/scan APIs
- §2: Peppered fingerprints only (3 tests) — grep for bare hash calls, verify HMAC usage
- §5: Skip loudness (3 tests) — verify skip_count tracking in store schema
- §7: Heartbeat provenance (3 tests) — verify \`invoked_by\` field, strict reader validation
- §6: Verdict vocabulary (4 tests) — verify 401/403 only classify as DEAD, no response bodies
- §4: No endpoint literals (2 tests) — delegated to existing repo-wide test
- §1,§3: File permissions (3 tests) — verify 0600 mode and WAL mode

**GitHub Actions CI** (\`.github/workflows/ci.yml\`):
- Runs on push to main and on all PRs
- Tests across Python 3.10, 3.11, 3.12
- Three gates that must all pass before merge
- Secret scanning with gitleaks

**Documentation** (README.md):
- CI badge for branch status
- New section explaining threat model conformance
- Lists all verified sections with evidence pointers
- Documents the three CI gates

### Impact

The public repo now enforces its own threat model doctrine: no commit can merge without passing all three CI gates. The conformance suite serves as executable proof that every sharp edge in THREAT-MODEL.md is implemented correctly and continuously verified.