# Audit log — llabyrinth

## Audit Minggu 2026-10-25 — pendalaman ekstra (verdict Sabtu sudah final)

Ronde lanjutan untuk repo Web Jumat yang sama (skema 3 build/minggu:
Sabtu = ronde fungsional + adversarial, Minggu = fresh-copy re-run +
kasus baru). Basis: fresh clone dari GitHub (`8c0a321`), bukan salinan
kerja lokal. Regresi: **68/68 unit tests** hijau (64 bawaan + 4 regresi
baru) dan **jsdom real-click smoke** hijau di salinan fresh.

Kasus adversarial/perf baru yang diuji:

1. **`paths --all` meledak kombinatorial: TEMUAN, diperbaiki.** Graf
   clique 12 node tanpa cap menghasilkan **792.101 path / 214 MB
   stdout dalam 36,7 detik** — dan clique yang sedikit lebih besar
   praktis tidak pernah selesai. Fix: `all_paths()` menerima `limit`
   dan CLI `--limit` default **10.000** (0 = tanpa batas); bila
   terpotong, peringatan jelas ke stderr. Flag `truncated` dibuat
   eksak (enumerasi berjalan sampai limit+1, jadi warning hanya muncul
   bila benar-benar ada path ke-(limit+1); cap tepat di jumlah total
   tidak memicu warning). Verifikasi sesudah fix: clique 12 selesai
   0,27 detik / 10.000 path + warning; `--limit 0` di clique 8 tetap
   mengembalikan seluruh 1.957 path tanpa warning.
2. **Karakter kontrol mentah di output DOT: TEMUAN, diperbaiki.** Id
   berisi `\x1b[31m` lolos ke file DOT apa adanya (kelas yang sama
   dengan injeksi terminal yang diperbaiki Sabtu, hanya jalur
   keluarnya DOT). Fix: `_dot_escape()` membuang sisa karakter
   kontrol C0/DEL setelah escaping quote/backslash/newline; tes
   regresi memastikan tidak ada byte `\x1b`/`\x07` di output dan
   newline tetap jadi escape `\n`.
3. **`extraports` ber-count bukan angka: TEMUAN, diperbaiki.**
   `<extraports count="abc"/>` membuat importer crash dengan
   `ValueError` mentah (traceback), bukan error bersih — satu-satunya
   `int()` tanpa pelindung di jalur impor (portid sudah dilindungi,
   uptime sudah dilindungi). Fix: entri `extraports` ber-count tak
   ter-parse dilewati, konsisten dengan toleransi port tanpa portid;
   entri valid di file yang sama tetap tercatat. Tes regresi
   memastikan impor sukses + `extraPorts` hanya berisi entri valid.
4. **Klaim perf scan besar: TERVERIFIKASI.** Scan sintetis 500 host ×
   10 port: impor 0,06 dtk + render web 0,12 dtk (total ~0,2 dtk,
   sesuai klaim README), HTML 2,92 MB / 5.502 node.
5. **Cap node port di web: TERVERIFIKASI.** Host 35 port menggambar
   tepat 30 node port + 1 node `+5 ports` dengan detail `+5 more
   ports`, sementara tabel detail host tetap memuat ke-35 port.

Perubahan: commit `afca0fe` ("audit: cap hasil paths --all,
netralkan kontrol di DOT, lewati extraports count bukan angka; 68/68
tes"), ter-push dan remote == lokal. README: jumlah tes 64 -> 68 +
dokumentasi `--limit` dan pembuangan karakter kontrol DOT.

### Verdict ronde ini

v1.1.0 tetap solid, kini dengan tiga lubang kecil yang ditutup: satu
perf (ledakan `--all`), satu sanitasi (byte kontrol di DOT), dan satu
ketahanan parser (count bukan angka). Tidak ada temuan XSS baru —
seluruh sink web tetap lewat `textContent` + JSON ter-escape.

## Audit Sabtu 2026-10-24 — ronde fungsional + adversarial (independen)

Ronde audit terjadwal untuk repo Web Jumat (skema 3 build/minggu).
Basis: fresh clone dari GitHub (`1c29ff4`), bukan salinan kerja lokal.
Regresi: **64/64 unit tests** hijau (61 bawaan + 3 regresi baru) dan
**21/21 jsdom real-click smoke** hijau di salinan fresh.

Kasus adversarial baru yang diuji (belum ada di ronde Jumat):

1. **Terminal injection via infra JSON: TEMUAN, diperbaiki.** Id node
   berisi `\x1b[31m` + `\nFAKE: owned` tercetak mentah oleh `tree`
   (dan `paths` via `render_path`) — ANSI escape aktif + baris palsu
   bisa disuntikkan ke terminal. Jalur impor Nmap aman secara
   struktural (karakter kontrol ilegal membuat XML tidak valid ->
   `InfraError` bersih; tab/newline dinormalisasi expat jadi spasi).
   Fix: helper `_term_safe()` — karakter kontrol C0/DEL dibuang,
   newline -> spasi agar layout tree satu baris utuh — dipakai di
   `reachable_tree`, `render_path`, catatan `validate`, dan warning
   stderr `web`. 3 tes regresi ditambahkan. Severity: rendah
   (infra JSON ditulis user sendiri = self-injection), tapi kelas
   yang sama diperbaiki di audit llumen, jadi disamakan di sini.
2. **`</script>` breakout di blok JSON model: AMAN.** Payload
   `</script><script>alert(9)</script>` sebagai service product:
   `_json_for_html` meng-escape `<`/`>`/`&` jadi `\uXXXX`, sehingga
   tidak ada literal `</script>` di dalam blok
   `<script type="application/json">` (tepat 2 penutup `</script>`
   di seluruh file) dan jsdom mengeksekusi halaman tanpa error
   dengan tepat 2 elemen script — payload hanya teks inert.
3. **Token `__MODEL_JSON__` di judul: AMAN.** `args` nmaprun berisi
   literal `__MODEL_JSON__` + `"injeksi"` -> `<title>` hanya teks
   ter-escape, tidak ada JSON model yang bocor (partition, bukan
   replace berantai — regresi ronde-2 Jumat tetap berlaku).
4. **Model kosong di browser: AMAN.** Ekspor `web` dari `<nmaprun/>`
   kosong dibuka di jsdom: nol JS error (`fit()` sudah guard
   `Math.max(1, …)`), nol node ter-render.
5. **portid aneh: AMAN.** `portid="abc"/"-1"/"0"/"70000"` diimpor
   tanpa crash (`"abc"` -> `None`, tampil `?/tcp`); `tree`/`paths`
   jalan normal.
6. **U+2028 di hostname: AMAN.** Lolos JSON round-trip
   (`\u2028` ter-escape lalu ter-parse kembali utuh), tampil sebagai
   teks, nol JS error.
7. **`--from-nmap` menunjuk direktori: AMAN.** Error satu baris
   bersih, tanpa traceback.

Perubahan: commit `4f82302` ("audit: netralkan karakter kontrol di
output terminal tree/paths/validate; 64/64 tes"), ter-push dan
remote == lokal. README: jumlah tes 61 -> 64.

### Verdict ronde ini

v1.1.0 tetap solid: satu-satunya temuan nyata adalah injeksi
terminal via infra JSON buatan tangan (severity rendah), sudah
diperbaiki dengan regresi. Seluruh vektor XSS/parse/edge-case baru
yang diuji lolos tanpa temuan.

## v1.1.0 design iteration 2 (2026-10-23) — responsive / mobile pass

The redesigned export was reviewed on a phone (portrait) and still
failed there — this iteration fixes the responsive behaviour. Only
`WEB_TEMPLATE` changed; behaviour, data flow, and the security model
are untouched.

What was wrong and what changed:

- **Miniature graph on narrow screens.** The structured layout always
  packed hosts 3-per-row inside ~1150px-wide subnet rows, and `fit()`
  scaled to the *height* of the tall result — on a 390px phone the
  whole topology shrank to ~163px wide with illegible labels. Now the
  layout adapts to the real stage width (hosts per subnet: 3 / 2 / 1
  columns at ≥1020 / ≥600 / <600px; infra-JSON columns stack
  vertically under 600px), and when the content is taller than the
  stage on a narrow screen, `fit()` scales to **fill the width**
  (up to 1.25×) and top-aligns — the rest of the graph is one pan
  away. Measured result at 390×844: graph 315px wide in a 390px
  stage, host chips render 260×50px (labels ≈14px effective).
- **Legend/footer overlap (real CSS bug).** The legend (bottom-left)
  and the credit line (bottom-right) were both absolutely positioned
  inside the graph area and collided into garbled overlapping text on
  narrow widths. Both now live in a `.graph-foot` bar in normal flow
  below the stage; the row wraps instead of ever overlapping.
- **Dead details block on mobile.** With nothing selected, the detail
  panel was a huge empty black block eating the bottom half of the
  phone screen. Under 900px the layout stacks (graph on top, details
  below); with no selection the panel collapses to a slim
  "Tap a node for details" bar (~42px), and on selection it becomes a
  section below the graph (max-height 48%, own scroll). Selecting a
  node also nudges the view so the node stays visible after the
  panel resizes the stage. Desktop keeps the right-side panel.
- **Header collisions.** The top bar's tools row had a content-based
  minimum size that forced the page to 496px wide on a 390px screen
  (horizontal overflow), the mono title could not ellipsize (missing
  `min-width: 0`), and the search field was squeezed while
  "Fit view" wrapped mid-label. The bar now wraps cleanly: brand row,
  stats + Fit button row, full-width search row on small screens;
  buttons never wrap mid-label.
- **Touch.** Pinch-zoom (two-pointer) and +/− zoom buttons added;
  the graph uses `touch-action: none` so pointer gestures are not
  hijacked by the browser. Drags no longer select header/strip text.

Verification: full unit suite **61/61 green** and jsdom real-click
smoke **21/21 green** (unchanged selectors; all XSS assertions hold).
On top of that, headless-Chromium screenshots at **both** viewports —
phone portrait **390×844** and desktop **1440×900** — in three states
each (initial, host selected, port on the attack path selected) were
**visually reviewed**, and geometry was asserted programmatically:
no legend/credit overlap at either width, no horizontal overflow
(`scrollWidth == clientWidth`), the SVG fills its stage, and real
clicks (with user-style pans to bring off-screen nodes into view)
landed in every state with zero JS errors. Two defects found during
this verification — the first `fit()` width branch not actually
applying the width scale, and the flex min-content overflow — were
fixed and re-verified before this note was written.

## v1.1.0 design overhaul (2026-10-23) — web export visual redesign

The v1.1.0 web export's visuals were rejected by the user as cluttered
("jelek banget") and were redesigned against the house principle —
**clean, minimalist, modern**. Behaviour, data flow, and the security
model are unchanged; only `WEB_TEMPLATE` (CSS + layout/render JS) was
rewritten.

What changed:

- **Palette**: near-black neutral canvas (`#0a0a0b`) and panels, 1px
  low-contrast hairlines (`#1e1e22`/`#26262b`), neutral grays for all
  node states. The old rainbow fills (lime subnet circles, sky-blue
  hosts, green/yellow/red port dots) are gone. Lime (`#a3e635`) now
  appears only as the selection ring (and the tiny brand mark /
  open-state dot); red (`#f87171`) is reserved for the attack path.
- **Layout**: the circular force-style sprawl is replaced by a
  deterministic structured layout — subnets are subtle outline
  containers with a small uppercase mono CIDR label and host count,
  hosts are quiet neutral chips (hostname + IP sub-line) arranged in a
  grid inside their subnet, ports are small muted dots with tiny mono
  numbers in rows under their host. Infra-JSON models render as
  labelled columns per node kind. Structural (containment) edges are
  nearly invisible; relationship edges are hairline gray.
- **Chrome**: slim top bar (brand mark + mono scan title left; mono
  stats, quiet search field, ghost "Fit view" button right), a thin
  path summary strip, a right detail panel with hairline-divided
  sections and a fixed-layout port table (state shown as a small dot +
  text), a minimal legend, and a subtle dot-grid canvas texture.
  Typography: Inter/system sans for UI, monospace for IPs, banners,
  and other scan data.
- **Hit targets**: port dots gained an invisible 12px-radius hit area —
  the first screenshot round (real Chromium clicks via Playwright)
  showed the bare 4px dot's bbox centre falls on unpainted space and
  the subnet container intercepted the click. Real-mouse clicking a
  port now works, not just synthetic events.

Verification: full unit suite **61/61 green** and jsdom real-click
smoke **21/21 green** (including all XSS payload assertions — payloads
still render only as inert text, exactly 2 script tags, no injected
elements). On top of that, the redesigned export was rendered in
headless Chromium at 1440×900 and **the screenshots were visually
reviewed** in three states (initial graph, host selected with detail
panel, port on the attack path) across two design iterations; the
infra-JSON column layout was screenshot-checked too.

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
