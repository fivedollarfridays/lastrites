# Watch topology: lastrites in the dead-man triangle

Status: design contract. lastrites does not run yet; this document commits
how it joins an existing mutual-watch estate the day it does, so the
integration is designed in rather than bolted on.

## The existing triangle (the estate this joins)

The author's estate already runs a mutual watch: a comms **freshness
monitor** (rails over capture-based heartbeats, alarms via push), a
**deadman** service (evidence-based board + collector, alarms via email)
— each watching the other, with scheduled duties as watched surfaces.
Two properties are non-negotiable and inherited by lastrites:

1. **Capture-based heartbeats.** A heartbeat is written only on verified
   success of the real work — never because a process ran. A dead worker
   must look dead.
2. **Provenance-stamped heartbeats.** Writers stamp how they were invoked
   (scheduler vs hand-run); strict readers refuse hand-run evidence, so a
   human diagnosing a broken schedule cannot accidentally mask it.
   lastrites is born after this lesson: its heartbeats are strict from
   day one — a missing stamp fails closed, no legacy tolerance.

## Edge 1 — deadman watches lastrites

- Surface `cred:lastrites-daemon`: a json-heartbeat probe on the lastrites
  sweep heartbeat. Stamped only when a full canary sweep completes;
  carries `invoked_by`; window sized to sweep cadence plus slack.
- Later, per-credential surfaces (`cred:<name>`) ride the same collector
  as evidence rows: last-verified time, expiry, verdict — so a dying key
  is a board fault like any other estate failure.
- Operational rule inherited from the estate: the deadman service REJECTS
  batches carrying undeclared surfaces. Declaring a new `cred:` surface
  means updating the service's collector declaration and redeploying it
  BEFORE the local collector names the probe. Ordering matters; it is a
  deploy step, not a config edit.

## Edge 2 — lastrites watches the watchers (the reciprocal duty)

The first credentials registered in the graph are the watch system's own:

- the push-notification topic the freshness monitor pages through (an
  unauthenticated-broadcast channel whose name is the only secret — the
  original motivating finding, and rotation candidate #1),
- the deadman ingest secret (the credential that authenticates evidence),
- the SMTP credentials the alarm email rail sends with.

This closes the nastiest loop in the estate: today, if the alarm
channel's own credential dies, alarms die with it — silently. Under this
topology, the paging channel's credential has a canary, and its failure
routes out the *other* watcher's channel.

## Edge 3 — the freshness monitor gains a `lastrites` rail

A rail over the same sweep heartbeat, capped at canary cadence plus
slack, strict provenance from birth. Result: monitor ⇄ deadman ⇄
lastrites each observed by another; no watcher in the estate is
unwatched, including the new one.

## Failure semantics summary

| Event | Reads as | Pages via |
|---|---|---|
| lastrites sweep stops | `cred:lastrites-daemon` stale on deadman + `lastrites` rail stale on monitor | both channels |
| a watched credential dies | `cred:<name>` fault | deadman alarm rail |
| the paging topic's credential dies | lastrites canary fault | the *other* watcher's channel |
| hand-run sweep while scheduler is dead | strict provenance rejects it — rail keeps aging | honest alarm, by design |
