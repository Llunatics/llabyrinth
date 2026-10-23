# llabyrinth

Attack-path mapper ala BloodHound: dari daftar host, user, grup, dan relasinya, hitung jalur lateral movement tercepat (BFS) seorang attacker menuju target.

- **Stdlib-only** — tanpa dependensi pihak ketiga
- **5 subcommand**: `paths`, `tree`, `dot`, `web`, `validate`
- Output: ASCII tree, panah berlabel relasi, JSON, DOT (Graphviz), dan satu file HTML interaktif
- **Impor Nmap** (sejak 1.1.0): model bisa dibangun langsung dari hasil scan `nmap -oX` lewat `--from-nmap` — tidak perlu menulis JSON infra dengan tangan

## Baru di 1.1.0

- `--from-nmap scan.xml` di semua subcommand: host → node `host`, subnet → node `group`, port terbuka → node `service`. Host multi-homed (MAC sama) digabung jadi satu node.
- Subcommand `web`: ekspor graf sebagai **satu file HTML mandiri** (CSS/JS inline, model JSON tertanam, nol request eksternal — buka file-nya langsung, offline jalan). Klik node untuk detail; `--from/--to` menyorot jalur serangan di topologi.
- Contoh scan siap pakai: `examples/scan-sample.xml`.

## Instalasi

```bash
git clone https://github.com/Llunatics/llabyrinth
cd llabyrinth
chmod +x llabyrinth.py
./llabyrinth.py --help
```

Butuh Python 3.8+.

## Format input

Satu file JSON dengan `nodes` dan `edges`:

```json
{
  "nodes": [
    {"id": "alice", "type": "user"},
    {"id": "ws01", "type": "host"},
    {"id": "domain-admins", "type": "group"}
  ],
  "edges": [
    {"from": "attacker", "to": "alice", "rel": "phished"},
    {"from": "alice", "to": "ws01", "rel": "local-admin"}
  ]
}
```

| Field | Keterangan |
|---|---|
| `id` | Unik per node, string tidak kosong |
| `type` | `principal` (attacker) · `user` · `host` · `group` · `service` (default: `user`) |
| `from` / `to` | Harus merujuk ke `id` yang ada di `nodes` |
| `rel` | String bebas; kosakata yang disarankan ada di bawah |

Relasi yang disarankan: `phished`, `password-sprayed`, `local-admin`, `has-session`, `rdp`, `smb`, `winrm`, `ssh`, `member-of`, `admin-on`, `can-read-laps`, `gpo-control`, `password-reset`, `kerberoastable`, `asrep-roastable`, `unconstrained-delegation`, `owns`, plus relasi hasil impor Nmap: `contains`, `exposes`.

Contoh siap pakai: `examples/corp.json` (korporasi fiktif "PT Maju Mundur", 13 node, 14 edge, termasuk satu cycle).

### Impor dari Nmap

File hasil `nmap -sV -O -oX scan.xml` bisa langsung dipakai di subcommand apa pun dengan mengganti argumen file JSON menjadi `--from-nmap scan.xml`:

| Hasil scan | Jadi |
|---|---|
| Host `up` | Node `host`, id = alamat IPv4/IPv6/MAC pertamanya |
| Subnet host (IPv4 /24, IPv6 /64) | Node `group`; edge `host -member-of-> subnet` dan `subnet -contains-> host` |
| Port `open` / `open\|filtered` / `unfiltered` | Node `service`, id `IP:port/proto`; edge `host -exposes-> service` |
| Host `down` | Dilewati (ada catatan di stderr) — sertakan dengan `--include-down` |
| Port `closed` / `filtered` | Bukan node — sertakan dengan `--include-closed` |

Seluruh data scan (banner, product/version, OS guess, hostname, MAC/vendor, output script NSE) disimpan sebagai detail dan tampil di panel detail ekspor `web`. Host dengan MAC yang sama digabung (multi-homed), jadi dua subnet yang berbagi satu host fisik tetap terhubung dalam graf.

Catatan kejujuran topologi: scan saja tidak membuktikan routing antar-subnet. Tanpa host multi-homed yang menjembatani, dua subnet adalah dua pulau — `paths` akan menjawab "tidak ada path", dan itu memang jawaban yang benar dari data yang ada.

## Perintah

| Perintah | Fungsi |
|---|---|
| `paths INFRA --from S --to T` | Jalur tercepat S → T (BFS) |
| `paths ... --all` | Semua simple path S → T, terurut dari terpendek |
| `tree INFRA --from S` | Peta serangan ASCII dari S (tandai cycle & node yang sudah digambar) |
| `dot INFRA --from S --to T -o lab.dot` | Ekspor Graphviz DOT; jalur tercepat disorot merah |
| `web INFRA --from S --to T -o peta.html` | Ekspor satu file HTML interaktif; jalur tercepat disorot merah |
| `validate INFRA` | Validasi skema + peringatan (relasi asing, node yatim) |

`INFRA` bisa diganti `--from-nmap scan.xml` di semua perintah di atas. Flag umum: `--max-depth N` (default 8), `--json` (untuk `paths`), `--include-down` / `--include-closed` (untuk `--from-nmap`).

```bash
./llabyrinth.py paths examples/corp.json --from attacker --to dc01
./llabyrinth.py paths examples/corp.json --from attacker --to dc01 --all --max-depth 8
./llabyrinth.py tree examples/corp.json --from attacker
./llabyrinth.py dot examples/corp.json --from attacker --to dc01 -o lab.dot
dot -Tpng lab.dot -o lab.png   # butuh Graphviz terinstal
./llabyrinth.py validate examples/corp.json

# Dari hasil scan Nmap langsung:
./llabyrinth.py paths --from-nmap examples/scan-sample.xml \
    --from 192.168.1.1 --to 192.168.1.20:3306/tcp
./llabyrinth.py web --from-nmap examples/scan-sample.xml \
    --from 192.168.1.1 --to 192.168.1.20:3306/tcp -o peta.html
./llabyrinth.py validate --from-nmap examples/scan-sample.xml
```

### Ekspor web

`web` menghasilkan SATU file HTML: semua CSS/JS inline dan model tertanam sebagai JSON — tanpa request eksternal sama sekali, jadi file-nya bisa dibuka dari disk dalam keadaan offline. Isinya:

- Topologi subnet → host → port untuk model impor Nmap (untuk infra JSON: graf node/edge apa adanya), dengan pan/zoom, geser node, dan pencarian (IP, hostname, port, service).
- Tata letak terstruktur (bukan force-directed): subnet digambar sebagai kontainer berlabel dengan host tersusun grid di dalamnya dan port sebagai titik kecil di bawah host; model infra JSON digambar sebagai kolom per jenis node. Tema gelap netral — aksen lime hanya untuk seleksi, merah hanya untuk jalur serangan.
- Klik node → panel detail: tabel port lengkap (tanpa batas tampilan), banner service, OS guess, hostname, MAC/vendor, dan output script NSE.
- Bila `--from/--to` diberikan dan jalurnya ada, jalur serangan disorot merah di graf dan diringkas di strip atas.
- Semua teks hasil scan dirender sebagai teks inert (`textContent` + JSON yang di-escape) — banner jahat dari host yang di-scan tidak bisa menyuntikkan markup.

Contoh output `paths`:

```
jalur tercepat: 7 hop

attacker
  --[phished]--> alice
  --[local-admin]--> ws01
  --[has-session]--> svc-deploy
  --[member-of]--> server-admins
  --[admin-on]--> srv-db
  --[has-session]--> budi
  --[local-admin]--> dc01
```

## Exit code

| Kode | Arti |
|---|---|
| 0 | Sukses / path ditemukan |
| 1 | Error input (file rusak, node tidak ada, dsb.) |
| 2 | Tidak ada path dalam `--max-depth` hop |

## Tes

```bash
python3 -m unittest discover -s tests
```

61 tes: validasi skema, BFS/DFS path, deteksi cycle, render DOT, end-to-end CLI, regresi audit 1.0 (escaping DOT, dedup tree di batas depth, default max-depth), plus suite 1.1.0 — impor Nmap (host down, IPv6, port filtered/closed, merge MAC, XML rusak/bukan Nmap, XXE, `<table>` bersarang dalam), ekspor web (overlay jalur, escaping JSON, batas node port), dan regresi audit 1.1.0.

Smoke test klik-sungguhan untuk ekspor web (jsdom, hanya untuk tes — tool-nya sendiri tetap stdlib-only):

```bash
cd tests && npm install   # sekali saja, mengambil jsdom
node tests/web-smoke.js
```

## Catatan perilaku

- `dot --to T` tanpa `--from` mencetak peringatan ke stderr dan mengabaikan sorotan (sorotan jalur butuh keduanya).
- Karakter `"`, `\`, dan newline di dalam id node / label relasi di-escape otomatis supaya output DOT tetap valid.

## Batasan

- Graf statis dari satu file — bukan kolektor live (padanannya BloodHound collector).
- Relasi adalah label bebas; tidak ada pembobotan "biaya" per teknik.
- Impor Nmap: jalur antar-subnet hanya ada bila ada host multi-homed (MAC sama) yang menjembatani — llabyrinth tidak mengarang routing.
- Tampilan web menggambar maks 30 node port per host (sisanya diringkas node `+N ports`); tabel detail di panel selalu lengkap. Scan raksasa (ribuan node) menghasilkan HTML beberapa MB dan graf yang berat dirender browser.
- Output script NSE terstruktur (`<table>`/`<elem>`) diratakan sampai kedalaman 64; yang lebih dalam dilewati.
- Dua elemen `<host>` dengan IP sama tapi MAC berbeda tidak digabung; detail yang tersimpan adalah elemen terakhir (node service elemen pertama tetap ada di model, tapi tidak digambar di tampilan web).

## Lisensi

MIT — lihat `LICENSE`.
