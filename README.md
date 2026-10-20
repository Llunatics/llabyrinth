# llabyrinth

Attack-path mapper ala BloodHound: dari daftar host, user, grup, dan relasinya, hitung jalur lateral movement tercepat (BFS) seorang attacker menuju target.

- **Stdlib-only** — tanpa dependensi pihak ketiga
- **4 subcommand**: `paths`, `tree`, `dot`, `validate`
- Output: ASCII tree, panah berlabel relasi, JSON, dan DOT (Graphviz)

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

Relasi yang disarankan: `phished`, `password-sprayed`, `local-admin`, `has-session`, `rdp`, `smb`, `winrm`, `ssh`, `member-of`, `admin-on`, `can-read-laps`, `gpo-control`, `password-reset`, `kerberoastable`, `asrep-roastable`, `unconstrained-delegation`, `owns`.

Contoh siap pakai: `examples/corp.json` (korporasi fiktif "PT Maju Mundur", 13 node, 14 edge, termasuk satu cycle).

## Perintah

| Perintah | Fungsi |
|---|---|
| `paths INFRA --from S --to T` | Jalur tercepat S → T (BFS) |
| `paths ... --all` | Semua simple path S → T, terurut dari terpendek |
| `tree INFRA --from S` | Peta serangan ASCII dari S (tandai cycle & node yang sudah digambar) |
| `dot INFRA --from S --to T -o lab.dot` | Ekspor Graphviz DOT; jalur tercepat disorot merah |
| `validate INFRA` | Validasi skema + peringatan (relasi asing, node yatim) |

Flag umum: `--max-depth N` (default 8), `--json` (untuk `paths`).

```bash
./llabyrinth.py paths examples/corp.json --from attacker --to dc01
./llabyrinth.py paths examples/corp.json --from attacker --to dc01 --all --max-depth 8
./llabyrinth.py tree examples/corp.json --from attacker
./llabyrinth.py dot examples/corp.json --from attacker --to dc01 -o lab.dot
dot -Tpng lab.dot -o lab.png   # butuh Graphviz terinstal
./llabyrinth.py validate examples/corp.json
```

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

27 tes: validasi skema, BFS/DFS path, deteksi cycle, render DOT, dan end-to-end CLI.

## Batasan

- Graf statis dari satu file — bukan kolektor live (padanannya BloodHound collector).
- Relasi adalah label bebas; tidak ada pembobotan "biaya" per teknik.

## Lisensi

MIT — lihat `LICENSE`.
