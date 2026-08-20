# LR2 — Delivery receipts: prove the last inch (2026-08-20)

**Base:** main

Opened from THREAT-MODEL §8. Every sharp edge before it concerns detecting
the right thing; this one concerns whether the message ARRIVED — the only
failure mode in the threat model that is silent by construction, because
the owner is definitionally absent when it matters.

Reference implementation to read first: the sibling ops estate's
`lib/email_verify.py` (send-and-verify-or-die-loud), including its
first-day miscalibration — a 45-minute verification window against a
capture rail that synced daily, which alarmed about an email that had
arrived two seconds after sending.

---

### LR2.1 — Split send from arrival in the escalation record | Cx: 2 | P1

**Description:** Today an escalation is one event. Make it two: the
attempt (channel, target, sent_at, transport response) and the receipt
(arrived_at, how it was confirmed). An escalation with an attempt and no
receipt is NOT delivered and must not be reported as such.

**AC:**
- [ ] Escalation records carry attempt + optional receipt, separately timestamped
- [ ] "Delivered" is derived from the receipt, never from transport acceptance
- [ ] Existing §7 escalation tests still green; new tests cover unreceipted state

### LR2.2 — Receipt windows sized to the confirming party | Cx: 2 | P1

**Description:** Per §8: the window is a function of how fast the
confirming signal can physically arrive, not of our impatience. Human
recipients under duress are a days-scale cadence. Windows must be
per-channel and configurable, with a test pinning the relationship
(window > the confirming source's own cadence) so nobody tightens one
without fixing the other first — that pin is exactly what the ops estate
added after its miscalibration.

**AC:**
- [ ] Per-channel window config; defaults documented with their reasoning
- [ ] Test pins window > confirming-source cadence
- [ ] A too-tight window is a config error at startup, not a runtime false alarm

### LR2.3 — Unreceipted escalation fails over, then screams | Cx: 3 | P1

**Description:** A send with no receipt inside its window fails over to
the next channel rather than counting as done. All channels unreceipted
is the loudest verdict the system has — the estate's last words went
nowhere.

**AC:**
- [ ] Failover on unreceipted window expiry (tested, per channel)
- [ ] All-channels-unreceipted is a distinct, highest-severity verdict
- [ ] Idempotent: one alarm per lost escalation, never a re-alarm loop

### LR2.4 — Receipt ≠ consent, in the model and in the words | Cx: 1 | P2

**Description:** An arrival proves arrival. It does not prove an heir
understands what they now hold. Record arrival; never phrase it as
acknowledgement or acceptance of custody. Any stronger claim requires a
separate explicit human act.

**AC:**
- [ ] Vocabulary audit: no code or report says "acknowledged"/"accepted" on a receipt
- [ ] THREAT-MODEL §8 status line updated when LR2.1-2.3 land (design intent → verified, with command + date + output)
