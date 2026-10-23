# Audit log — llabyrinth

## v1.1.0 (2026-10-23) — Nmap importer + web export

A staged self-audit of the 1.1.0 feature work (the 1.0 audit lives in the
git history and README notes). Three rounds: **round 1** adversarial
probes against the importer and renderer; **round 2** attacked the
round-1 fixes and cross-checked README claims; **round 3** froze the
result with a fresh-copy full-suite run (this file).

Test counts: unit suite 31 (v1.0) → **61 tests**; jsdom real-click smoke
for the web export: **21 checks**. Everything green at the time of
writing.

### Round 1 — adversarial probes (1 crash found, fixed)

1. **Deeply-nested NSE `<table>` crashed the importer with
   `RecursionError`.** A hostile scan whose `<script>` output nests
   `<table>` 5,000 deep recursed once per level in the structured-output
   flattener, producing a raw traceback. Fixed: flattening is capped at
   depth 64 (`SCRIPT_MAX_DEPTH`); deeper elements are skipped.
   Regression test included.
2. **XXE**: an external-entity hostname (`file:///etc/passwd`) is refused
   by expat as a clean `InfraError` — no file content is read.
   Regression test included.
3. **Billion laughs**: expat's amplification limit rejects the 10^8
   expansion with a clean `InfraError` in <0.1 s. A mild 10^4 expansion
   under the limit passes through as data — acceptable, it is bounded
   by expat's accounting (100× / 8 MB), not by luck.
4. **Cosmetic**: a `<port>` without `portid` rendered as `None/tcp` in
   the detail table; now `?/tcp`, and such ports never become service
   nodes. Regression test included.
5. Clean behaviour confirmed for: empty `<nmaprun>`, truncated XML,
   non-Nmap XML, missing file (>32 MB input is also refused up front).

### Round 2 — attacking the fixes + claim checks (1 real bug found)

1. **Template-token collision corrupted `<title>`.** The web renderer
   substituted `__TITLE__` then `__MODEL_JSON__` with global replaces.
   Scan args are attacker-controlled and can contain both literals —
   the second replace then injected the entire JSON model into the
   `<title>` element (inert, but wrong and bloated). Fixed: the
   template is assembled with `partition("__MODEL_JSON__")`, so the
   JSON is inserted verbatim and never rescanned, and the title
   substitution only touches the head segment. Regression test
   included (title round-trips, no JSON in `<head>`).
2. **Path overlay direction.** Model paths walk host → subnet, but
   display edges run subnet → host; the overlay now matches edge pairs
   in either direction and only paints edges that actually exist in the
   display graph (caught by the jsdom smoke: 2 of 3 path edges painted
   before the fix, 3 of 3 after).
3. **Duplicate-IP hosts** (same IP, different MACs) import without
   crashing; the second record's details win, the first record's
   service nodes remain in the model but are not drawn. Documented in
   README "Batasan" rather than silently "handled".
4. Depth-cap boundary verified: tables nested 30 deep still flatten
   with dotted keys; only beyond 64 are elements skipped.
5. `tree` and `dot` (with red path highlight) verified against
   `--from-nmap` models, not just JSON infra.

### Round 3 — fresh-copy verification

Full suite from a clean copy of the repo (no `__pycache__`, no
`node_modules` carried over): 61 unit tests green, jsdom smoke 21/21
green, and the README examples were run verbatim (paths/tree/dot/
validate/web over both `examples/corp.json` and
`examples/scan-sample.xml`).

### Honest limitations

- Cross-subnet attack paths exist only when a multi-homed host (same
  MAC in two subnets) bridges them. That is deliberate: a scan alone
  does not prove routing, and llabyrinth will not invent it.
- The web export draws at most 30 port nodes per host; the detail
  table is always complete. A 500-host × 10-port synthetic scan
  imports + renders server-side in ~0.2 s but produces a ~2.7 MB HTML
  file whose 5.5k-node SVG is heavy in a browser.
- Structured NSE output deeper than 64 levels is dropped, not shown.
- The jsdom smoke cannot exercise canvas/PNG paths (the web export
  has none — it *is* the artifact) or real pointer geometry; pan/zoom
  math is the same code pattern as sibling tools but is only
  click-verified for node selection, search, and detail rendering.

### Verdict

v1.1.0 is solid as an importer + offline web viewer on top of the
unchanged BFS engine: every scan-derived string reaches the page only
as escaped JSON data rendered through `textContent`, malformed or
hostile scan files fail with clean one-line errors, and the two real
bugs the audit found (recursion crash, title injection of the model
JSON) are fixed with regression tests. It is a triage/teaching tool —
for live collection, run Nmap and your usual AD tooling.
