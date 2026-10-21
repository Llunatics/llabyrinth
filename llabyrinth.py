#!/usr/bin/env python3
"""
llabyrinth — labirin jalur serangan.

Attack-path mapper ala BloodHound buat latihan AD/offensive security:
kasih daftar host, user, grup, dan relasinya dalam satu file JSON,
llabyrinth menghitung jalur lateral movement tercepat (BFS) dari titik
masuk attacker ke target, menggambarnya sebagai ASCII tree, dan
mengekspornya ke format DOT (Graphviz).

Stdlib-only: tanpa dependensi pihak ketiga.

Contoh:
    llabyrinth.py paths examples/corp.json --from attacker --to dc01
    llabyrinth.py tree examples/corp.json --from attacker
    llabyrinth.py dot examples/corp.json --from attacker --to dc01 -o lab.dot
    llabyrinth.py validate examples/corp.json
"""

import argparse
import json
import os
import sys

VERSION = "1.0.1"

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

NODE_TYPES = {"principal", "user", "host", "group", "service"}

# Kosakata relasi yang disarankan (bebas pakai string lain, tapi daftar ini
# yang dipakai di contoh + didokumentasikan di README).
KNOWN_RELS = {
    "phished", "password-sprayed", "local-admin", "has-session", "rdp",
    "smb", "winrm", "ssh", "member-of", "admin-on", "can-read-laps",
    "gpo-control", "password-reset", "kerberoastable", "asrep-roastable",
    "unconstrained-delegation", "owns",
}


class InfraError(Exception):
    """File infra tidak valid."""


def load_infra(path):
    """Baca + validasi file infra JSON. Return (nodes, edges).

    nodes: dict id -> {"id": str, "type": str}
    edges: list {"from": str, "to": str, "rel": str}
    """
    if not os.path.isfile(path):
        raise InfraError("file tidak ditemukan: %s" % path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise InfraError("JSON tidak valid: %s" % exc)
    except OSError as exc:
        raise InfraError("gagal membaca file: %s" % exc)

    if not isinstance(data, dict):
        raise InfraError("root JSON harus object dengan key 'nodes' dan 'edges'")
    raw_nodes = data.get("nodes")
    raw_edges = data.get("edges")
    if not isinstance(raw_nodes, list):
        raise InfraError("'nodes' harus berupa list")
    if not isinstance(raw_edges, list):
        raise InfraError("'edges' harus berupa list")

    nodes = {}
    for i, n in enumerate(raw_nodes):
        if not isinstance(n, dict):
            raise InfraError("nodes[%d] harus object" % i)
        nid = n.get("id")
        if not nid or not isinstance(nid, str):
            raise InfraError("nodes[%d] butuh 'id' string yang tidak kosong" % i)
        if nid in nodes:
            raise InfraError("node id duplikat: %r" % nid)
        ntype = n.get("type", "user")
        if ntype not in NODE_TYPES:
            raise InfraError(
                "nodes[%d] type %r tidak dikenal (pilih: %s)"
                % (i, ntype, ", ".join(sorted(NODE_TYPES)))
            )
        nodes[nid] = {"id": nid, "type": ntype}

    edges = []
    seen_edges = set()
    for i, e in enumerate(raw_edges):
        if not isinstance(e, dict):
            raise InfraError("edges[%d] harus object" % i)
        src, dst, rel = e.get("from"), e.get("to"), e.get("rel")
        for key, val in (("from", src), ("to", dst), ("rel", rel)):
            if not val or not isinstance(val, str):
                raise InfraError("edges[%d] butuh '%s' string yang tidak kosong" % (i, key))
        if src not in nodes:
            raise InfraError("edges[%d]: node 'from' %r tidak ada di nodes" % (i, src))
        if dst not in nodes:
            raise InfraError("edges[%d]: node 'to' %r tidak ada di nodes" % (i, dst))
        key = (src, dst, rel)
        if key in seen_edges:
            raise InfraError("edges[%d]: edge duplikat %r -[%s]-> %r" % (i, src, rel, dst))
        seen_edges.add(key)
        edges.append({"from": src, "to": dst, "rel": rel})

    return nodes, edges


def build_graph(nodes, edges):
    """Adjacency list: {src: [(dst, rel), ...]}. Urutan deterministik."""
    adj = {nid: [] for nid in nodes}
    for e in edges:
        adj[e["from"]].append((e["to"], e["rel"]))
    for nid in adj:
        adj[nid].sort()
    return adj


# ---------------------------------------------------------------------------
# Analisis path
# ---------------------------------------------------------------------------

def shortest_path(adj, start, goal, max_depth=8):
    """BFS: path terpendek start -> goal.

    Return list [(node, rel_masuk), ...] dimulai dari (start, None),
    atau None bila tidak ada path dalam max_depth hop.
    """
    if start == goal:
        return [(start, None)]
    queue = [(start, [(start, None)])]
    visited = {start}
    while queue:
        node, path = queue.pop(0)
        if len(path) - 1 >= max_depth:
            continue
        for dst, rel in adj.get(node, []):
            if dst in visited:
                continue
            new_path = path + [(dst, rel)]
            if dst == goal:
                return new_path
            visited.add(dst)
            queue.append((dst, new_path))
    return None


def all_paths(adj, start, goal, max_depth=8):
    """Semua simple path (tanpa node berulang) start -> goal, maks max_depth hop."""
    results = []

    def dfs(node, path, on_stack):
        if len(path) - 1 > max_depth:
            return
        if node == goal:
            results.append(list(path))
            return
        for dst, rel in adj.get(node, []):
            if dst in on_stack:
                continue  # hindari cycle
            on_stack.add(dst)
            path.append((dst, rel))
            dfs(dst, path, on_stack)
            path.pop()
            on_stack.remove(dst)

    dfs(start, [(start, None)], {start})
    # start == goal -> satu path trivial 0 hop, bukan duplikat.
    return sorted(results, key=lambda p: (len(p), [n for n, _ in p]))


def reachable_tree(adj, nodes, start, max_depth=8):
    """BFS layered tree dari start. Return list baris ASCII tree."""
    lines = []
    ntype = nodes[start]["type"]
    lines.append("%s [%s]" % (start, ntype))
    visited_global = {start}

    def walk(node, prefix, depth, on_stack):
        children = adj.get(node, [])
        for i, (dst, rel) in enumerate(children):
            last = i == len(children) - 1
            branch = "└── " if last else "├── "
            cont = "    " if last else "│   "
            dtype = nodes[dst]["type"]
            if dst in on_stack:
                lines.append("%s%s%s [%s]  (%s)  ↩ cycle" % (prefix, branch, dst, dtype, rel))
            elif dst in visited_global:
                lines.append("%s%s%s [%s]  (%s)  … sudah digambar" % (prefix, branch, dst, dtype, rel))
            else:
                lines.append("%s%s%s [%s]  (%s)" % (prefix, branch, dst, dtype, rel))
                visited_global.add(dst)  # tandai walau tidak direkursi (batas depth)
                if depth + 1 < max_depth:
                    on_stack.add(dst)
                    walk(dst, prefix + cont, depth + 1, on_stack)
                    on_stack.discard(dst)

    walk(start, "", 0, {start})
    return lines


def render_path(path):
    """Satu path -> string multi-baris dengan panah berlabel relasi."""
    out = []
    for i, (node, rel) in enumerate(path):
        if i == 0:
            out.append(node)
        else:
            out.append("  --[%s]--> %s" % (rel, node))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Export DOT
# ---------------------------------------------------------------------------

_DOT_SHAPES = {
    "principal": "plaintext",
    "user": "ellipse",
    "host": "box",
    "group": "diamond",
    "service": "octagon",
}


def _dot_escape(text):
    """Escape string untuk label/id DOT: backslash, quote, newline."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


def render_dot(nodes, edges, highlight=()):
    """DOT (Graphviz). highlight = set of (from, to) edge yang diwarnai merah.

    Semua id/type/rel di-escape supaya id yang mengandung quote atau
    backslash tidak merusak sintaks DOT.
    """
    hl = set(highlight)
    lines = ["digraph attack_paths {", '  rankdir=LR;', '  node [fontname="monospace"];']
    for nid in sorted(nodes):
        ntype = nodes[nid]["type"]
        shape = _DOT_SHAPES.get(ntype, "ellipse")
        lines.append(
            '  "%s" [shape=%s, label="%s\\n[%s]"];'
            % (_dot_escape(nid), shape, _dot_escape(nid), _dot_escape(ntype))
        )
    for e in edges:
        attrs = 'label="%s"' % _dot_escape(e["rel"])
        if (e["from"], e["to"]) in hl:
            attrs += ", color=red, penwidth=2.5, fontcolor=red"
        lines.append(
            '  "%s" -> "%s" [%s];'
            % (_dot_escape(e["from"]), _dot_escape(e["to"]), attrs)
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def path_edges(path):
    """Edge-edge (from, to) di sepanjang sebuah path."""
    return [(path[i][0], path[i + 1][0]) for i in range(len(path) - 1)]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _die(msg, code=1):
    print("llabyrinth: error: %s" % msg, file=sys.stderr)
    return code


def cmd_paths(args):
    try:
        nodes, edges = load_infra(args.infra)
    except InfraError as exc:
        return _die(exc)
    adj = build_graph(nodes, edges)
    if args.source not in nodes:
        return _die("node --from %r tidak ada di infra" % args.source)
    if args.target not in nodes:
        return _die("node --to %r tidak ada di infra" % args.target)

    if args.all:
        paths = all_paths(adj, args.source, args.target, args.max_depth)
        if not paths:
            print("tidak ada path %s -> %s (maks %d hop)" % (args.source, args.target, args.max_depth))
            return 2
        if args.json:
            print(json.dumps(
                [{"hops": len(p) - 1,
                  "nodes": [n for n, _ in p],
                  "rels": [r for _, r in p[1:]]} for p in paths],
                indent=2))
        else:
            print("%d path ditemukan (maks %d hop), terurut dari terpendek:\n" % (len(paths), args.max_depth))
            for i, p in enumerate(paths, 1):
                print("path %d — %d hop:" % (i, len(p) - 1))
                print(render_path(p))
                print()
        return 0

    path = shortest_path(adj, args.source, args.target, args.max_depth)
    if path is None:
        print("tidak ada path %s -> %s (maks %d hop)" % (args.source, args.target, args.max_depth))
        return 2
    if args.json:
        print(json.dumps({
            "hops": len(path) - 1,
            "nodes": [n for n, _ in path],
            "rels": [r for _, r in path[1:]],
        }, indent=2))
    else:
        print("jalur tercepat: %d hop\n" % (len(path) - 1))
        print(render_path(path))
    return 0


def cmd_tree(args):
    try:
        nodes, edges = load_infra(args.infra)
    except InfraError as exc:
        return _die(exc)
    adj = build_graph(nodes, edges)
    if args.source not in nodes:
        return _die("node --from %r tidak ada di infra" % args.source)
    print("peta serangan dari %s (maks %d hop):\n" % (args.source, args.max_depth))
    print("\n".join(reachable_tree(adj, nodes, args.source, args.max_depth)))
    return 0


def cmd_dot(args):
    try:
        nodes, edges = load_infra(args.infra)
    except InfraError as exc:
        return _die(exc)
    adj = build_graph(nodes, edges)
    highlight = set()
    if args.target and not args.source:
        print("llabyrinth: peringatan: --to diabaikan tanpa --from "
              "(sorotan jalur butuh keduanya)", file=sys.stderr)
    if args.source and args.target:
        if args.source not in nodes:
            return _die("node --from %r tidak ada di infra" % args.source)
        if args.target not in nodes:
            return _die("node --to %r tidak ada di infra" % args.target)
        path = shortest_path(adj, args.source, args.target, args.max_depth)
        if path:
            highlight = set(path_edges(path))
    dot = render_dot(nodes, edges, highlight)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(dot)
        except OSError as exc:
            return _die("gagal menulis %s: %s" % (args.out, exc))
        print("DOT ditulis ke %s" % args.out)
    else:
        print(dot, end="")
    return 0


def cmd_validate(args):
    try:
        nodes, edges = load_infra(args.infra)
    except InfraError as exc:
        return _die(exc)
    problems = []
    unknown_rels = sorted({e["rel"] for e in edges} - KNOWN_RELS)
    if unknown_rels:
        problems.append("relasi di luar kosakata dikenal: %s" % ", ".join(unknown_rels))
    referenced = {e["from"] for e in edges} | {e["to"] for e in edges}
    orphans = sorted(set(nodes) - referenced)
    if orphans:
        problems.append("node yatim (tanpa edge): %s" % ", ".join(orphans))
    if problems:
        print("valid, tapi ada catatan:")
        for p in problems:
            print("  - %s" % p)
    else:
        print("valid: %d node, %d edge, tidak ada catatan." % (len(nodes), len(edges)))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="llabyrinth",
        description="Pemeta attack path: BFS jalur lateral movement dari infra JSON, "
                    "render ASCII tree, ekspor DOT.",
    )
    p.add_argument("--version", action="version", version="llabyrinth " + VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("paths", help="cari jalur serangan start -> target (BFS)")
    sp.add_argument("infra", help="file infra JSON")
    sp.add_argument("--from", dest="source", required=True, help="node awal (titik masuk attacker)")
    sp.add_argument("--to", dest="target", required=True, help="node target")
    sp.add_argument("--all", action="store_true", help="tampilkan SEMUA simple path, bukan cuma tercepat")
    sp.add_argument("--max-depth", type=int, default=8, help="maks hop (default 8)")
    sp.add_argument("--json", action="store_true", help="output JSON")
    sp.set_defaults(func=cmd_paths)

    st = sub.add_parser("tree", help="gambar peta serangan ASCII dari satu titik")
    st.add_argument("infra", help="file infra JSON")
    st.add_argument("--from", dest="source", required=True, help="node awal")
    st.add_argument("--max-depth", type=int, default=8, help="maks kedalaman (default 8)")
    st.set_defaults(func=cmd_tree)

    sd = sub.add_parser("dot", help="ekspor graf ke DOT (Graphviz)")
    sd.add_argument("infra", help="file infra JSON")
    sd.add_argument("--from", dest="source", default=None, help="sorot jalur tercepat dari node ini")
    sd.add_argument("--to", dest="target", default=None, help="sorot jalur tercepat ke node ini")
    sd.add_argument("--max-depth", type=int, default=8, help="maks hop jalur sorotan (default 8)")
    sd.add_argument("-o", "--out", default=None, help="tulis ke file (default: stdout)")
    sd.set_defaults(func=cmd_dot)

    sv = sub.add_parser("validate", help="validasi file infra JSON")
    sv.add_argument("infra", help="file infra JSON")
    sv.set_defaults(func=cmd_validate)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "max_depth", 6) < 1:
        return _die("--max-depth harus >= 1")
    # Broken pipe: `llabyrinth ... | head` keluar bersih, bukan traceback.
    try:
        return args.func(args)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        try:
            sys.stderr.close()
        except Exception:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
