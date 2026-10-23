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

Sejak 1.1.0 model juga bisa diimpor langsung dari hasil scan Nmap
(`nmap -oX`): host -> node host, subnet -> node group, port terbuka ->
node service. Flag --from-nmap menggantikan file infra JSON di semua
subcommand, dan subcommand `web` mengekspor graf sebagai SATU file HTML
interaktif (offline, tanpa request eksternal):

    llabyrinth.py paths --from-nmap examples/scan-sample.xml \
        --from 192.168.1.1 --to 192.168.1.20:3306/tcp
    llabyrinth.py web --from-nmap examples/scan-sample.xml \
        --from 192.168.1.1 --to 192.168.1.20:3306/tcp -o peta.html
"""

import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

VERSION = "1.1.0"

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
    # Relasi hasil impor Nmap: host -member-of-> subnet, subnet -contains->
    # host, host -exposes-> service.
    "contains", "exposes",
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
# Impor Nmap (-oX)
# ---------------------------------------------------------------------------

NMAP_MAX_BYTES = 32 * 1024 * 1024
SCRIPT_MAX_DEPTH = 64
# State port yang jadi node service secara default; closed/filtered hanya
# bila diminta (--include-closed), karena biasanya cuma noise.
NMAP_DEFAULT_PORT_STATES = {"open", "open|filtered", "unfiltered"}
NMAP_CLOSED_PORT_STATES = {"closed", "filtered", "closed|filtered"}
WEB_PORT_CAP = 30  # maks node port per host di tampilan web


def _subnet_key(ipv4, ipv6):
    """Kunci grup subnet: IPv4 -> /24, IPv6 -> /64, selain itu None."""
    if ipv4:
        parts = ipv4.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3]) + ".0/24"
    if ipv6:
        head = ipv6.lower().split("::")[0].split(":") if ipv6 else []
        head = [g for g in head if g != ""]
        while len(head) < 4:
            head.append("0")
        return ":".join(head[:4]) + "::/64"
    return None


def _script_model(script_el):
    """<script> NSE -> {id, output, elements:[{key, value}]} (table/elem
    terstruktur diratakan dengan kunci bertitik). Kedalaman perataan
    dibatasi (SCRIPT_MAX_DEPTH): file jahat dengan <table> bersarang
    ribuan lapis tidak boleh membuat importer crash RecursionError —
    elemen di bawah batas itu dilewati."""
    elements = []

    def walk(el, prefix, depth):
        if depth > SCRIPT_MAX_DEPTH:
            return
        for child in el:
            key = child.get("key") or child.tag
            if child.tag == "elem":
                elements.append({
                    "key": (prefix + "." + key) if prefix else key,
                    "value": (child.text or "").strip(),
                })
            else:
                walk(child, (prefix + "." + key) if prefix else key, depth + 1)

    walk(script_el, "", 0)
    return {
        "id": script_el.get("id", ""),
        "output": script_el.get("output", ""),
        "elements": elements,
    }


def _port_model(port_el):
    state_el = port_el.find("state")
    svc_el = port_el.find("service")
    service = None
    if svc_el is not None:
        service = {
            "name": svc_el.get("name", ""),
            "product": svc_el.get("product", ""),
            "version": svc_el.get("version", ""),
            "extrainfo": svc_el.get("extrainfo", ""),
            "hostname": svc_el.get("hostname", ""),
            "ostype": svc_el.get("ostype", ""),
            "tunnel": svc_el.get("tunnel", ""),
            "method": svc_el.get("method", ""),
            "conf": svc_el.get("conf", ""),
            "cpes": [(c.text or "").strip() for c in svc_el.findall("cpe")],
        }
    try:
        portid = int(port_el.get("portid"))
    except (TypeError, ValueError):
        portid = None
    return {
        "protocol": port_el.get("protocol", ""),
        "portid": portid,
        "state": state_el.get("state", "") if state_el is not None else "",
        "stateReason": state_el.get("reason", "") if state_el is not None else "",
        "service": service,
        "scripts": [_script_model(s) for s in port_el.findall("script")],
    }


def service_banner(port):
    """Banner ringkas dari field service: 'Apache httpd 2.4.49 ((Unix))'."""
    svc = port.get("service")
    if not svc:
        return ""
    parts = []
    if svc.get("product"):
        parts.append(svc["product"])
    if svc.get("version"):
        parts.append(svc["version"])
    if svc.get("extrainfo"):
        parts.append("(%s)" % svc["extrainfo"])
    return " ".join(parts)


def _host_record(host_el):
    status_el = host_el.find("status")
    addresses = []
    ipv4 = ipv6 = mac = vendor = ""
    for a in host_el.findall("address"):
        rec = {
            "addr": a.get("addr", ""),
            "addrtype": a.get("addrtype", ""),
            "vendor": a.get("vendor", ""),
        }
        addresses.append(rec)
        if rec["addrtype"] == "ipv4" and not ipv4:
            ipv4 = rec["addr"]
        elif rec["addrtype"] == "ipv6" and not ipv6:
            ipv6 = rec["addr"]
        elif rec["addrtype"] == "mac" and not mac:
            mac, vendor = rec["addr"], rec["vendor"]
    hostnames = []
    hn_el = host_el.find("hostnames")
    if hn_el is not None:
        hostnames = [
            {"name": h.get("name", ""), "type": h.get("type", "")}
            for h in hn_el.findall("hostname")
        ]
    ports = []
    extra_ports = []
    ports_el = host_el.find("ports")
    if ports_el is not None:
        ports = [_port_model(p) for p in ports_el.findall("port")]
        extra_ports = [
            {"state": e.get("state", ""), "count": int(e.get("count", "0") or 0)}
            for e in ports_el.findall("extraports")
        ]
    os_matches = []
    os_el = host_el.find("os")
    if os_el is not None:
        for m in os_el.findall("osmatch"):
            os_matches.append({
                "name": m.get("name", ""),
                "accuracy": m.get("accuracy", ""),
                "osClasses": [
                    {
                        "vendor": c.get("vendor", ""),
                        "osfamily": c.get("osfamily", ""),
                        "osgen": c.get("osgen", ""),
                        "type": c.get("type", ""),
                    }
                    for c in m.findall("osclass")
                ],
            })
    hostscript_el = host_el.find("hostscript")
    uptime_el = host_el.find("uptime")
    distance_el = host_el.find("distance")
    return {
        "status": status_el.get("state", "") if status_el is not None else "",
        "statusReason": status_el.get("reason", "") if status_el is not None else "",
        "addresses": addresses,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "mac": mac,
        "macVendor": vendor,
        "hostnames": hostnames,
        "ports": ports,
        "extraPorts": extra_ports,
        "osMatches": os_matches,
        "hostScripts": (
            [_script_model(s) for s in hostscript_el.findall("script")]
            if hostscript_el is not None else []
        ),
        "uptimeSeconds": uptime_el.get("seconds", "") if uptime_el is not None else "",
        "distance": distance_el.get("value", "") if distance_el is not None else "",
    }


def import_nmap(path, include_down=False, include_closed=False):
    """Impor file Nmap XML (-oX) menjadi model llabyrinth.

    Return dict {nodes, edges, details, meta, warnings, source: "nmap"}:
    - host up -> node "host" (id = IPv4/IPv6/MAC pertamanya)
    - subnet -> node "group" (id = kunci subnet); edge dua arah logis:
      host -member-of-> subnet dan subnet -contains-> host, supaya BFS bisa
      berjalan host -> subnet -> host lain -> service-nya.
    - port yang termasuk -> node "service" (id "IP:port/proto"),
      edge host -exposes-> service.
    - host dengan MAC yang sama digabung (multi-homed): alamat, hostname,
      dan port dari elemen <host> kedua dilebur ke node pertama.
    details[host_id] / details[service_id] menyimpan seluruh data scan
    (banner, script, OS, dst.) untuk panel detail ekspor web. Semua string
    di details adalah data mentah dari file — WAJIB diperlakukan sebagai
    input tak tepercaya oleh renderer.
    """
    if not os.path.isfile(path):
        raise InfraError("file tidak ditemukan: %s" % path)
    if os.path.getsize(path) > NMAP_MAX_BYTES:
        raise InfraError("file Nmap terlalu besar (>32 MB): %s" % path)
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise InfraError("XML tidak valid: %s" % exc)
    except OSError as exc:
        raise InfraError("gagal membaca file: %s" % exc)
    root = tree.getroot()
    if root.tag != "nmaprun":
        raise InfraError(
            "root element <%s> bukan <nmaprun> — ini bukan output Nmap -oX"
            % root.tag
        )

    wanted_states = set(NMAP_DEFAULT_PORT_STATES)
    if include_closed:
        wanted_states |= NMAP_CLOSED_PORT_STATES

    nodes = {}
    edges = []
    seen_edges = set()
    details = {}
    warnings = []

    def add_node(nid, ntype):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype}

    def add_edge(frm, to, rel):
        key = (frm, to, rel)
        if key not in seen_edges:
            seen_edges.add(key)
            edges.append({"from": frm, "to": to, "rel": rel})

    skipped_down = 0
    mac_owner = {}  # mac.lower() -> host_id (untuk merge multi-homed)

    for host_el in root.findall("host"):
        rec = _host_record(host_el)
        if rec["status"] != "up":
            if not include_down:
                skipped_down += 1
                continue
        host_id = rec["ipv4"] or rec["ipv6"] or rec["mac"]
        if not host_id:
            warnings.append("satu host tanpa alamat dilewati")
            continue

        merged = False
        if rec["mac"] and rec["mac"].lower() in mac_owner:
            host_id = mac_owner[rec["mac"].lower()]
            merged = True
        elif rec["mac"]:
            mac_owner[rec["mac"].lower()] = host_id

        add_node(host_id, "host")
        if merged and host_id in details:
            base = details[host_id]
            known_addr = {(a["addr"], a["addrtype"]) for a in base["addresses"]}
            for a in rec["addresses"]:
                if (a["addr"], a["addrtype"]) not in known_addr:
                    base["addresses"].append(a)
            known_hn = {h["name"] for h in base["hostnames"]}
            for hn in rec["hostnames"]:
                if hn["name"] not in known_hn:
                    base["hostnames"].append(hn)
            base["ports"].extend(rec["ports"])
            base["hostScripts"].extend(rec["hostScripts"])
            if not base["ipv4"]:
                base["ipv4"] = rec["ipv4"]
            if not base["ipv6"]:
                base["ipv6"] = rec["ipv6"]
        else:
            details[host_id] = dict(rec, kind="host", serviceIds=[], subnets=[])
            details[host_id]["primaryIp"] = host_id

        det = details[host_id]
        subnet = _subnet_key(rec["ipv4"] or det["ipv4"], rec["ipv6"] or det["ipv6"])
        if subnet:
            add_node(subnet, "group")
            add_edge(host_id, subnet, "member-of")
            add_edge(subnet, host_id, "contains")
            if subnet not in det["subnets"]:
                det["subnets"].append(subnet)

        for port in rec["ports"]:
            if port["portid"] is None or port["state"] not in wanted_states:
                continue
            svc_id = "%s:%s/%s" % (host_id, port["portid"], port["protocol"])
            add_node(svc_id, "service")
            add_edge(host_id, svc_id, "exposes")
            if svc_id not in det["serviceIds"]:
                det["serviceIds"].append(svc_id)
            details[svc_id] = {"kind": "service", "host": host_id, "port": port}

    if skipped_down:
        warnings.append(
            "%d host down dilewati (pakai --include-down untuk menyertakan)"
            % skipped_down
        )

    runstats = root.find("runstats")
    finished = runstats.find("finished") if runstats is not None else None
    meta = {
        "scanner": root.get("scanner", ""),
        "version": root.get("version", ""),
        "args": root.get("args", ""),
        "startstr": root.get("startstr", ""),
        "summary": finished.get("summary", "") if finished is not None else "",
    }
    return {
        "nodes": nodes,
        "edges": edges,
        "details": details,
        "meta": meta,
        "warnings": warnings,
        "source": "nmap",
    }


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
# Ekspor web (satu file HTML mandiri)
# ---------------------------------------------------------------------------

# Template halaman web: CSS + JS seluruhnya inline. __MODEL_JSON__ diganti
# dengan JSON model yang sudah di-escape (_json_for_html), __TITLE__ dengan
# judul yang sudah di-escape HTML. Renderer di bawah TIDAK PERNAH memasukkan
# string model ke innerHTML — semua lewat textContent, karena banner,
# hostname, dan output script Nmap adalah data tak tepercaya.
WEB_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__ — llabyrinth</title>
<style>
:root{--bg:#0b0f14;--panel:#111826;--panel2:#0e1420;--line:#22304a;--text:#dbe4f3;--muted:#8494ad;--accent:#a3e635;--accentdim:#65a30d;--open:#4ade80;--warn:#fbbf24;--bad:#f87171;--host:#7dd3fc}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 "Segoe UI",system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.topbar{padding:16px 22px 6px;display:flex;flex-wrap:wrap;gap:8px 24px;justify-content:space-between;align-items:flex-start}
.topbar h1{margin:0;font-size:26px;color:var(--accent)}
.topbar .sub{color:var(--muted);margin:2px 0 0;max-width:760px;word-break:break-word}
.controls{display:flex;flex-wrap:wrap;gap:10px 16px;align-items:center;padding:6px 22px}
.controls input[type=search]{background:var(--panel2);border:1px solid var(--line);border-radius:8px;color:var(--text);padding:8px 12px;min-width:280px;font-size:14px}
.btn{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:6px 12px;font-size:13.5px;cursor:pointer}
.btn:hover{border-color:var(--accentdim);color:#fff}
.stats{padding:2px 22px 8px;color:var(--muted);font-size:14px}
.pathstrip{margin:2px 22px 10px;padding:9px 13px;border:1px solid var(--bad);border-radius:8px;background:rgba(248,113,113,.08);color:#fecaca;word-break:break-word}
.layout{flex:1;display:grid;grid-template-columns:1fr 360px;gap:14px;padding:0 22px 14px;min-height:0}
@media (max-width:900px){.layout{grid-template-columns:1fr}}
.graph-wrap{position:relative;background:var(--panel2);border:1px solid var(--line);border-radius:12px;min-height:520px;overflow:hidden}
#graph{width:100%;height:100%;min-height:520px;display:block;cursor:grab}
.legend{position:absolute;right:12px;bottom:10px;display:flex;gap:12px;color:var(--muted);font-size:12.5px;pointer-events:none}
.legend .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
.node{cursor:pointer}
.node text{fill:var(--text);text-anchor:middle;pointer-events:none}
.node.selected circle.body{stroke:#fff;stroke-width:2.5}
.node.onpath circle.body{stroke:#f87171;stroke-width:3}
.node.dim{opacity:.14}
.edge{stroke:#2b3c5c;stroke-width:1.2}
.edge.path{stroke:#f87171;stroke-width:3}
.edge.dim{opacity:.12}
.detail{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 16px;overflow-y:auto;max-height:calc(100vh - 170px)}
.detail h2{margin:0 0 4px;font-size:18px;word-break:break-all}
.detail h3{margin:16px 0 6px;font-size:13.5px;color:var(--accent);text-transform:uppercase;letter-spacing:.6px}
.muted{color:var(--muted)}
dl.fields{margin:8px 0;display:grid;grid-template-columns:104px 1fr;gap:3px 10px;font-size:14px}
dl.fields dt{color:var(--muted)}
dl.fields dd{margin:0;word-break:break-word}
table.ports{width:100%;border-collapse:collapse;font-size:13px}
table.ports th,table.ports td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);vertical-align:top}
table.ports th{color:var(--muted)}
.state-open{color:var(--open)}.state-closed{color:var(--bad)}.state-filtered,.state-openfiltered{color:var(--warn)}
.script-block{margin:6px 0;font-size:13px}
.script-block .sid{color:var(--host);font-family:ui-monospace,Consolas,monospace}
.script-block pre{margin:3px 0 0;white-space:pre-wrap;word-break:break-word;background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:6px 8px;font-size:12.5px;max-height:180px;overflow-y:auto}
.link-row{display:block;width:100%;text-align:left;background:var(--panel2);border:1px solid var(--line);border-radius:6px;color:var(--text);padding:6px 9px;margin:4px 0;cursor:pointer;font-size:13.5px}
.link-row:hover{border-color:var(--accentdim)}
.foot{padding:0 22px 16px;color:var(--muted);font-size:13px}
</style>
</head>
<body>
<header class="topbar">
  <div>
    <h1>llabyrinth</h1>
    <p class="sub" id="title-line"></p>
  </div>
</header>
<section class="controls">
  <input type="search" id="search" placeholder="Search IP, hostname, port, service, node…" autocomplete="off">
  <button class="btn" id="btn-fit" type="button">Fit view</button>
  <span class="muted" id="stats-line"></span>
</section>
<div class="pathstrip" id="path-strip" hidden></div>
<main class="layout">
  <section class="graph-wrap">
    <svg id="graph" role="group" aria-label="Topology graph"></svg>
    <div class="legend"><span><i class="dot" style="background:#a3e635"></i>subnet/group</span><span><i class="dot" style="background:#7dd3fc"></i>host/node</span><span><i class="dot" style="background:#4ade80"></i>port/service</span><span><i class="dot" style="background:#f87171"></i>attack path</span></div>
  </section>
  <aside class="detail" id="detail-panel">
    <h2 id="detail-title">Details</h2>
    <div id="detail-body"><p class="muted">Click a node to inspect it. Drag to pan, scroll to zoom, drag a node to move it.</p></div>
  </aside>
</main>
<footer class="foot">Generated by llabyrinth. This file is fully self-contained and works offline; scan-derived text is shown as inert text.</footer>
<script type="application/json" id="model">__MODEL_JSON__</script>
<script>
(function(){
'use strict';
var model = JSON.parse(document.getElementById('model').textContent);
var SVGNS = 'http://www.w3.org/2000/svg';
function el(id){return document.getElementById(id);}
function h(tag, cls, text){var n=document.createElement(tag);if(cls)n.className=cls;if(text!==undefined&&text!==null)n.textContent=text;return n;}
function svgEl(tag, attrs){var n=document.createElementNS(SVGNS, tag);for(var k in attrs)n.setAttribute(k, attrs[k]);return n;}
var svg = el('graph'), detailTitle = el('detail-title'), detailBody = el('detail-body');
el('title-line').textContent = model.title + ' · ' + (model.meta && model.meta.summary ? model.meta.summary : '');
el('stats-line').textContent = model.statsLine || '';
var byId = {}; model.nodes.forEach(function(n){byId[n.id]=n;});
var childrenOf = {}, parentsOf = {};
model.edges.forEach(function(e){
  (childrenOf[e.from] = childrenOf[e.from] || []).push(e.to);
  (parentsOf[e.to] = parentsOf[e.to] || []).push(e.from);
});
/* ---- layout ---- */
function circle(cx, cy, r, items, start){
  items.forEach(function(n, i){
    var a = start + (items.length === 1 ? 0 : (i / items.length) * Math.PI * 2);
    n.x = cx + Math.cos(a) * r; n.y = cy + Math.sin(a) * r;
  });
}
function layout(){
  var subnets = model.nodes.filter(function(n){return n.kind==='subnet';});
  if(subnets.length){
    if(subnets.length === 1){ subnets[0].x = 0; subnets[0].y = 0; }
    else {
      var cols = Math.ceil(Math.sqrt(subnets.length)), sp = 640;
      subnets.forEach(function(s, i){
        s.x = (i % cols - (cols - 1) / 2) * sp;
        s.y = (Math.floor(i / cols) - (Math.ceil(subnets.length / cols) - 1) / 2) * sp;
      });
    }
    subnets.forEach(function(s, si){
      var hosts = (childrenOf[s.id] || []).map(function(id){return byId[id];});
      circle(s.x, s.y, hosts.length === 1 ? 0 : Math.max(95, hosts.length * 27), hosts, si * 0.7);
      hosts.forEach(function(hn, hi){
        var ports = (childrenOf[hn.id] || []).map(function(id){return byId[id];});
        circle(hn.x, hn.y, ports.length > 1 ? 54 : 42, ports, hi * 1.3);
      });
    });
  } else {
    var kinds = {};
    model.nodes.forEach(function(n){ (kinds[n.kind] = kinds[n.kind] || []).push(n); });
    var kindNames = Object.keys(kinds).sort();
    if(kindNames.length === 1){
      circle(0, 0, Math.max(160, model.nodes.length * 22), model.nodes, 0);
    } else {
      kindNames.forEach(function(kind, ki){
        var items = kinds[kind];
        var a = (ki / kindNames.length) * Math.PI * 2;
        var cx = Math.cos(a) * 320, cy = Math.sin(a) * 320;
        circle(cx, cy, Math.max(70, items.length * 20), items, ki);
      });
    }
  }
}
/* ---- render ---- */
var view = {k:1, tx:0, ty:0}, viewport = null, selectedId = null;
var pathNodes = {}, pathEdges = {};
if(model.path){
  model.path.nodes.forEach(function(id){ pathNodes[id] = true; });
  model.path.edges.forEach(function(pair){ pathEdges[pair[0] + '\n' + pair[1]] = true; });
  var strip = el('path-strip');
  strip.hidden = false;
  strip.textContent = 'Attack path (' + (model.path.edges.length) + ' hops): ' + model.path.summary;
}
var PORT_FILL = {'open':'#4ade80','open|filtered':'#fbbf24','closed':'#f87171','filtered':'#fb923c','closed|filtered':'#fb923c','unfiltered':'#94a3b8'};
function render(){
  while(svg.firstChild) svg.removeChild(svg.firstChild);
  viewport = svgEl('g', {id:'viewport'});
  svg.appendChild(viewport);
  var gE = svgEl('g', {}), gN = svgEl('g', {});
  viewport.appendChild(gE); viewport.appendChild(gN);
  model.edges.forEach(function(e){
    var a = byId[e.from], b = byId[e.to]; if(!a || !b) return;
    var cls = 'edge' + (pathEdges[e.from + '\n' + e.to] ? ' path' : '');
    gE.appendChild(svgEl('line', {'class': cls, x1:a.x, y1:a.y, x2:b.x, y2:b.y, 'data-from':e.from, 'data-to':e.to}));
  });
  model.nodes.forEach(function(n){
    var g = svgEl('g', {'class':'node node-' + n.kind + (pathNodes[n.id] ? ' onpath' : ''), 'data-node-id': n.id, transform:'translate(' + n.x + ',' + n.y + ')'});
    var r, fill, stroke;
    if(n.kind === 'subnet' || n.kind === 'group'){ r = 24; fill = '#1a2b12'; stroke = '#a3e635'; }
    else if(n.kind === 'port' || n.kind === 'service'){ r = 9; fill = PORT_FILL[n.state] || '#7dd3fc'; stroke = '#0b0f14'; }
    else if(n.kind === 'more'){ r = 9; fill = '#111826'; stroke = '#8494ad'; }
    else { r = 15; fill = '#12283d'; stroke = '#7dd3fc'; if(n.status && n.status !== 'up'){ fill = '#1c2536'; stroke = '#5b6b84'; } }
    g.appendChild(svgEl('circle', {'class':'body', r:r, cx:0, cy:0, fill:fill, stroke:stroke, 'stroke-width':1.6}));
    var label = svgEl('text', {x:0, y:r + 14, 'font-size': (n.kind === 'port' || n.kind === 'service') ? 9.5 : 11});
    label.textContent = n.label.length > 30 ? n.label.slice(0, 29) + '…' : n.label;
    g.appendChild(label);
    g.addEventListener('click', function(evt){ evt.stopPropagation(); select(n.id); });
    g.addEventListener('pointerdown', function(evt){ startDrag(evt, n, g); });
    gN.appendChild(g);
  });
  applyView();
}
function applyView(){ if(viewport) viewport.setAttribute('transform', 'translate(' + view.tx + ',' + view.ty + ') scale(' + view.k + ')'); }
function fit(){
  if(!model.nodes.length) return;
  var minX=1e18, minY=1e18, maxX=-1e18, maxY=-1e18;
  model.nodes.forEach(function(n){ minX=Math.min(minX,n.x); maxX=Math.max(maxX,n.x); minY=Math.min(minY,n.y); maxY=Math.max(maxY,n.y); });
  var rect = svg.getBoundingClientRect(), W = rect.width || 1000, H = rect.height || 560, pad = 90;
  var k = Math.min(W / Math.max(1, maxX - minX + pad * 2), H / Math.max(1, maxY - minY + pad * 2), 1.6);
  view.k = k; view.tx = W / 2 - k * (minX + maxX) / 2; view.ty = H / 2 - k * (minY + maxY) / 2;
  applyView();
}
/* ---- pan / zoom / drag ---- */
var drag = null;
function toGraph(cx, cy){ var r = svg.getBoundingClientRect(); return {x:(cx - r.left - view.tx) / view.k, y:(cy - r.top - view.ty) / view.k}; }
function startDrag(evt, node, g){
  if(evt.button !== undefined && evt.button !== 0) return;
  var p = toGraph(evt.clientX, evt.clientY);
  drag = {kind:'node', node:node, el:g, dx:node.x - p.x, dy:node.y - p.y};
  evt.preventDefault();
}
svg.addEventListener('pointerdown', function(evt){ if(!drag) drag = {kind:'pan', sx:evt.clientX, sy:evt.clientY, tx:view.tx, ty:view.ty}; });
svg.addEventListener('pointermove', function(evt){
  if(!drag) return;
  if(drag.kind === 'pan'){ view.tx = drag.tx + evt.clientX - drag.sx; view.ty = drag.ty + evt.clientY - drag.sy; applyView(); }
  else { var p = toGraph(evt.clientX, evt.clientY); drag.node.x = p.x + drag.dx; drag.node.y = p.y + drag.dy;
    drag.el.setAttribute('transform', 'translate(' + drag.node.x + ',' + drag.node.y + ')');
    var lines = svg.querySelectorAll('line.edge');
    for(var i = 0; i < lines.length; i++){ var L = lines[i];
      if(L.getAttribute('data-from') === drag.node.id){ L.setAttribute('x1', drag.node.x); L.setAttribute('y1', drag.node.y); }
      if(L.getAttribute('data-to') === drag.node.id){ L.setAttribute('x2', drag.node.x); L.setAttribute('y2', drag.node.y); } } }
});
svg.addEventListener('pointerup', function(){ drag = null; });
svg.addEventListener('pointerleave', function(){ drag = null; });
svg.addEventListener('click', function(){ selectedId = null; markSelected(); showPlaceholder(); });
svg.addEventListener('wheel', function(evt){
  evt.preventDefault();
  var r = svg.getBoundingClientRect(), mx = evt.clientX - r.left, my = evt.clientY - r.top;
  var k2 = Math.max(0.08, Math.min(5, view.k * (evt.deltaY < 0 ? 1.12 : 1 / 1.12))), ratio = k2 / view.k;
  view.tx = mx - (mx - view.tx) * ratio; view.ty = my - (my - view.ty) * ratio; view.k = k2; applyView();
}, {passive:false});
/* ---- detail ---- */
function markSelected(){
  var els = svg.querySelectorAll('.node');
  for(var i = 0; i < els.length; i++) els[i].classList.toggle('selected', els[i].getAttribute('data-node-id') === selectedId);
}
function showPlaceholder(){
  detailTitle.textContent = 'Details';
  while(detailBody.firstChild) detailBody.removeChild(detailBody.firstChild);
  detailBody.appendChild(h('p', 'muted', 'Click a node to inspect it.'));
}
function scriptBlocks(scripts, parent){
  (scripts || []).forEach(function(s){
    var wrap = h('div', 'script-block');
    wrap.appendChild(h('span', 'sid', s.id));
    if(s.output) wrap.appendChild(h('pre', null, s.output));
    (s.elements || []).forEach(function(e){ wrap.appendChild(h('pre', null, e.key + ' = ' + e.value)); });
    parent.appendChild(wrap);
  });
}
function select(id){
  selectedId = id; markSelected();
  var d = model.details[id]; if(!d) return;
  detailTitle.textContent = d.title;
  while(detailBody.firstChild) detailBody.removeChild(detailBody.firstChild);
  var dl = h('dl', 'fields');
  (d.fields || []).forEach(function(pair){
    dl.appendChild(h('dt', null, pair[0]));
    dl.appendChild(h('dd', null, pair[1]));
  });
  detailBody.appendChild(dl);
  if(d.ports && d.ports.length){
    detailBody.appendChild(h('h3', null, 'Ports (' + d.ports.length + ' listed)'));
    var table = h('table', 'ports'), head = h('tr');
    ['Port','State','Service','Banner'].forEach(function(t){ head.appendChild(h('th', null, t)); });
    table.appendChild(head);
    d.ports.forEach(function(p){
      var tr = h('tr');
      tr.appendChild(h('td', null, p.label));
      tr.appendChild(h('td', 'state-' + p.state.replace('|',''), p.state));
      tr.appendChild(h('td', null, p.service));
      tr.appendChild(h('td', null, p.banner));
      table.appendChild(tr);
      if(p.scripts && p.scripts.length){
        var tr2 = h('tr'), td = h('td'); td.colSpan = 4;
        scriptBlocks(p.scripts, td); tr2.appendChild(td); table.appendChild(tr2);
      }
    });
    detailBody.appendChild(table);
  }
  if(d.scripts && d.scripts.length){
    detailBody.appendChild(h('h3', null, 'Script output'));
    scriptBlocks(d.scripts, detailBody);
  }
  if(d.links && d.links.length){
    detailBody.appendChild(h('h3', null, 'Connections'));
    d.links.forEach(function(link){
      var b = h('button', 'link-row', link.label);
      b.addEventListener('click', function(){ select(link.to); });
      detailBody.appendChild(b);
    });
  }
}
/* ---- search ---- */
el('search').addEventListener('input', function(){
  var q = el('search').value.trim().toLowerCase();
  var keep = {};
  if(q){
    model.nodes.forEach(function(n){
      var hay = (n.label + ' ' + (n.sub || '') + ' ' + n.id).toLowerCase();
      if(hay.indexOf(q) !== -1){
        keep[n.id] = true;
        (parentsOf[n.id] || []).forEach(function(p){ keep[p] = true;
          (parentsOf[p] || []).forEach(function(pp){ keep[pp] = true; }); });
        (childrenOf[n.id] || []).forEach(function(c){ keep[c] = true; });
      }
    });
  }
  var els = svg.querySelectorAll('.node');
  for(var i = 0; i < els.length; i++) els[i].classList.toggle('dim', !!q && !keep[els[i].getAttribute('data-node-id')]);
  var lines = svg.querySelectorAll('line.edge');
  for(var j = 0; j < lines.length; j++){
    var f = lines[j].getAttribute('data-from'), t = lines[j].getAttribute('data-to');
    lines[j].classList.toggle('dim', !!q && !(keep[f] && keep[t]));
  }
});
el('btn-fit').addEventListener('click', fit);
layout();
render();
fit();
})();
</script>
</body>
</html>
"""

_PORT_STATE_RANK = {
    "open": 0, "open|filtered": 1, "unfiltered": 2,
    "closed|filtered": 3, "filtered": 4, "closed": 5,
}


def _sorted_ports(ports):
    return sorted(
        ports,
        key=lambda p: (
            _PORT_STATE_RANK.get(p["state"], 6),
            p["portid"] if p["portid"] is not None else 0,
        ),
    )


def _port_detail_entry(port):
    svc = port.get("service") or {}
    return {
        "label": "%s/%s" % (
            port["portid"] if port["portid"] is not None else "?",
            port["protocol"]),
        "state": port["state"],
        "service": svc.get("name", ""),
        "banner": service_banner(port),
        "scripts": port.get("scripts", []),
    }


def _host_fields(rec):
    fields = []

    def add(name, value):
        if value:
            fields.append([name, str(value)])

    add("Status", rec["status"] + (
        " (%s)" % rec["statusReason"] if rec.get("statusReason") else ""))
    ipv4s = [a["addr"] for a in rec["addresses"] if a["addrtype"] == "ipv4"]
    ipv6s = [a["addr"] for a in rec["addresses"] if a["addrtype"] == "ipv6"]
    add("IPv4", ", ".join(ipv4s))
    add("IPv6", ", ".join(ipv6s))
    add("MAC", rec.get("mac"))
    add("MAC vendor", rec.get("macVendor"))
    for i, hn in enumerate(rec["hostnames"]):
        add("Hostname" if i == 0 else "Hostname %d" % (i + 1),
            hn["name"] + (" (%s)" % hn["type"] if hn["type"] else ""))
    if rec["osMatches"]:
        best = rec["osMatches"][0]
        add("OS guess", best["name"] + (
            " — %s%% accuracy" % best["accuracy"] if best["accuracy"] else ""))
    add("Distance", (rec["distance"] + " hops") if rec.get("distance") else "")
    if rec.get("uptimeSeconds"):
        try:
            add("Uptime", "%d days" % (int(rec["uptimeSeconds"]) // 86400))
        except ValueError:
            pass
    for ep in rec["extraPorts"]:
        add("Not listed", "%d ports %s" % (ep["count"], ep["state"]))
    add("Subnets", ", ".join(rec.get("subnets", [])))
    return fields


def _service_fields(det):
    port = det["port"]
    svc = port.get("service") or {}
    fields = []

    def add(name, value):
        if value:
            fields.append([name, str(value)])

    add("Host", det["host"])
    add("State", port["state"] + (
        " (%s)" % port["stateReason"] if port.get("stateReason") else ""))
    add("Service", svc.get("name"))
    add("Product", svc.get("product"))
    add("Version", svc.get("version"))
    add("Extra info", svc.get("extrainfo"))
    add("Banner", service_banner(port))
    add("Tunnel", svc.get("tunnel"))
    add("Hostname", svc.get("hostname"))
    add("OS type", svc.get("ostype"))
    if svc.get("method"):
        add("Detection", svc["method"] + (
            " (confidence %s/10)" % svc["conf"] if svc.get("conf") else ""))
    for i, cpe in enumerate(svc.get("cpes", [])):
        add("CPE" if i == 0 else "CPE %d" % (i + 1), cpe)
    return fields


def build_display(model, path=None):
    """Model llabyrinth -> struktur tampilan untuk ekspor web.

    path: hasil shortest_path() [(node, rel), ...] atau None. Overlay
    jalur dihitung di sini (bukan di JS) supaya bisa diuji dari Python:
    display["path"] = {"nodes": [...], "edges": [[from, to], ...],
    "summary": "a → b → c"}.
    """
    nodes = model["nodes"]
    edges = model["edges"]
    details = model.get("details")
    path_ids = [n for n, _ in path] if path else []

    d_nodes = []
    d_edges = []
    d_details = {}
    path_display = None

    if model.get("source") == "nmap" and details is not None:
        host_ids = [nid for nid in sorted(details)
                    if details[nid].get("kind") == "host"]
        subnet_keys = sorted({s for hid in host_ids
                              for s in details[hid].get("subnets", [])})
        for key in subnet_keys:
            d_nodes.append({
                "id": "subnet:" + key, "kind": "subnet",
                "label": key, "sub": "subnet",
            })
        port_display_id = {}  # service model id -> display node id
        for hid in host_ids:
            rec = details[hid]
            label = rec["hostnames"][0]["name"] if rec["hostnames"] else hid
            d_nodes.append({
                "id": hid, "kind": "host", "label": label, "sub": hid,
                "status": rec["status"],
            })
            for key in rec.get("subnets", []):
                d_edges.append({"from": "subnet:" + key, "to": hid, "rel": ""})
            shown = _sorted_ports(
                [details[sid]["port"] for sid in rec["serviceIds"]])
            overflow = 0
            for i, port in enumerate(shown):
                sid = "%s:%s/%s" % (hid, port["portid"], port["protocol"])
                if i >= WEB_PORT_CAP:
                    overflow += 1
                    continue
                port_display_id[sid] = sid
                d_nodes.append({
                    "id": sid, "kind": "port",
                    "label": "%s/%s" % (port["portid"], port["protocol"]),
                    "sub": (port["service"] or {}).get("name", ""),
                    "state": port["state"], "parent": hid,
                })
                d_edges.append({"from": hid, "to": sid, "rel": ""})
            if overflow:
                more_id = hid + "/more"
                d_nodes.append({
                    "id": more_id, "kind": "more",
                    "label": "+%d ports" % overflow, "sub": "",
                    "parent": hid,
                })
                d_edges.append({"from": hid, "to": more_id, "rel": ""})
                for sid in rec["serviceIds"]:
                    port_display_id.setdefault(sid, more_id)
            # Detail host: tabel port PENUH (tanpa cap).
            d_details[hid] = {
                "title": label,
                "fields": _host_fields(rec),
                "ports": [_port_detail_entry(p) for p in _sorted_ports(rec["ports"])],
                "scripts": rec.get("hostScripts", []),
                "links": [{"to": "subnet:" + k, "label": "Subnet " + k}
                          for k in rec.get("subnets", [])],
            }
            for sid in rec["serviceIds"]:
                sdet = details[sid]
                d_details[sid] = {
                    "title": "%s/%s" % (sdet["port"]["portid"],
                                        sdet["port"]["protocol"]),
                    "fields": _service_fields(sdet),
                    "ports": [],
                    "scripts": sdet["port"].get("scripts", []),
                    "links": [{"to": hid, "label": "Host " + hid}],
                }
        for key in subnet_keys:
            members = [hid for hid in host_ids
                       if key in details[hid].get("subnets", [])]
            d_details["subnet:" + key] = {
                "title": key,
                "fields": [["Type", "subnet"],
                           ["Hosts shown", str(len(members))]],
                "ports": [], "scripts": [],
                "links": [{"to": hid, "label": hid} for hid in members],
            }
        for hid in host_ids:
            rec = details[hid]
            shown_n = len(rec["serviceIds"])
            if shown_n > WEB_PORT_CAP:
                d_details[hid + "/more"] = {
                    "title": "+%d more ports" % (shown_n - WEB_PORT_CAP),
                    "fields": [["Note",
                                "Graph draws at most %d port nodes per host; "
                                "the full list is in the host details."
                                % WEB_PORT_CAP]],
                    "ports": [], "scripts": [],
                    "links": [{"to": hid, "label": "Host " + hid}],
                }
        if path:
            mapped = []
            for mid in path_ids:
                if mid in details and details[mid].get("kind") == "host":
                    mapped.append(mid)
                elif mid in details and details[mid].get("kind") == "service":
                    mapped.append(port_display_id.get(mid, details[mid]["host"]))
                elif mid in nodes and nodes[mid]["type"] == "group":
                    mapped.append("subnet:" + mid)
                else:
                    mapped.append(mid)
            # Buang duplikat berurutan (host bisa muncul via merge).
            dedup = []
            for m in mapped:
                if not dedup or dedup[-1] != m:
                    dedup.append(m)
            labels = {}
            for dn in d_nodes:
                labels[dn["id"]] = dn["label"]
            # Pasangan jalur model (host -> subnet) tidak selalu searah
            # dengan edge tampilan (subnet -> host): cocokkan dua arah,
            # dan hanya sertakan pasangan yang benar-benar tergambar.
            display_edge_keys = {(e["from"], e["to"]) for e in d_edges}
            path_edges_display = []
            for i in range(len(dedup) - 1):
                a, b = dedup[i], dedup[i + 1]
                if (a, b) in display_edge_keys:
                    path_edges_display.append([a, b])
                elif (b, a) in display_edge_keys:
                    path_edges_display.append([b, a])
            path_display = {
                "nodes": dedup,
                "edges": path_edges_display,
                "summary": " → ".join(labels.get(m, m) for m in dedup),
            }
        stats_line = "%d hosts · %d services · %d subnets" % (
            len(host_ids),
            sum(1 for n in nodes.values() if n["type"] == "service"),
            len(subnet_keys),
        )
    else:
        for nid in sorted(nodes):
            d_nodes.append({
                "id": nid, "kind": nodes[nid]["type"],
                "label": nid, "sub": nodes[nid]["type"],
            })
        for e in edges:
            d_edges.append({"from": e["from"], "to": e["to"], "rel": e["rel"]})
        for nid in sorted(nodes):
            links = []
            for e in edges:
                if e["from"] == nid:
                    links.append({"to": e["to"],
                                  "label": "--[%s]--> %s" % (e["rel"], e["to"])})
                elif e["to"] == nid:
                    links.append({"to": e["from"],
                                  "label": "%s --[%s]-->" % (e["from"], e["rel"])})
            d_details[nid] = {
                "title": nid,
                "fields": [["Type", nodes[nid]["type"]]],
                "ports": [], "scripts": [], "links": links,
            }
        if path:
            path_display = {
                "nodes": path_ids,
                "edges": [[path_ids[i], path_ids[i + 1]]
                          for i in range(len(path_ids) - 1)],
                "summary": " → ".join(path_ids),
            }
        stats_line = "%d nodes · %d edges" % (len(nodes), len(edges))

    meta = model.get("meta") or {}
    title = "llabyrinth web map"
    if meta.get("args"):
        title = meta["args"]
    return {
        "title": title,
        "source": model.get("source", "infra"),
        "statsLine": stats_line,
        "meta": meta,
        "nodes": d_nodes,
        "edges": d_edges,
        "details": d_details,
        "path": path_display,
    }


def _json_for_html(obj):
    """JSON aman disisipkan di <script type="application/json">: escape
    <, >, & sebagai \\uXXXX supaya string hasil scan (banner dsb.) tidak
    bisa menutup tag script atau membuka komentar HTML."""
    text = json.dumps(obj, ensure_ascii=False)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def render_web_html(display):
    """Satu file HTML mandiri: CSS+JS inline, model JSON tertanam,
    nol request eksternal. Semua string model dirender JS via
    textContent — tidak ada jalur innerHTML untuk data scan."""
    import html as _html

    # partition, BUKAN replace berantai: judul berasal dari data scan
    # (meta args) dan bisa mengandung literal "__TITLE__"/"__MODEL_JSON__";
    # replace global akan menyuntikkan JSON ke <title> atau sebaliknya.
    head, sep, tail = WEB_TEMPLATE.partition("__MODEL_JSON__")
    assert sep, "WEB_TEMPLATE kehilangan token __MODEL_JSON__"
    return (
        head.replace("__TITLE__", _html.escape(display["title"], quote=True))
        + _json_for_html(display)
        + tail
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _die(msg, code=1):
    print("llabyrinth: error: %s" % msg, file=sys.stderr)
    return code


def load_model(args):
    """Sumber model untuk semua subcommand: --from-nmap (impor scan)
    atau file infra JSON posisi pertama. Return dict seragam."""
    if getattr(args, "nmap", None):
        return import_nmap(
            args.nmap,
            include_down=getattr(args, "include_down", False),
            include_closed=getattr(args, "include_closed", False),
        )
    if getattr(args, "infra", None):
        nodes, edges = load_infra(args.infra)
        return {
            "nodes": nodes, "edges": edges, "details": None,
            "meta": None, "warnings": [], "source": "infra",
        }
    raise InfraError("butuh file infra JSON atau --from-nmap FILE.xml")


def _load_or_die(args):
    try:
        return load_model(args), None
    except InfraError as exc:
        return None, _die(exc)


def cmd_paths(args):
    model, err = _load_or_die(args)
    if err is not None:
        return err
    nodes, edges = model["nodes"], model["edges"]
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
    model, err = _load_or_die(args)
    if err is not None:
        return err
    nodes, edges = model["nodes"], model["edges"]
    adj = build_graph(nodes, edges)
    if args.source not in nodes:
        return _die("node --from %r tidak ada di infra" % args.source)
    print("peta serangan dari %s (maks %d hop):\n" % (args.source, args.max_depth))
    print("\n".join(reachable_tree(adj, nodes, args.source, args.max_depth)))
    return 0


def cmd_dot(args):
    model, err = _load_or_die(args)
    if err is not None:
        return err
    nodes, edges = model["nodes"], model["edges"]
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


def cmd_web(args):
    model, err = _load_or_die(args)
    if err is not None:
        return err
    nodes, edges = model["nodes"], model["edges"]
    for w in model.get("warnings", []):
        print("llabyrinth: catatan: %s" % w, file=sys.stderr)
    adj = build_graph(nodes, edges)
    path = None
    if args.target and not args.source:
        print("llabyrinth: peringatan: --to diabaikan tanpa --from "
              "(sorotan jalur butuh keduanya)", file=sys.stderr)
    if args.source and args.target:
        if args.source not in nodes:
            return _die("node --from %r tidak ada di model" % args.source)
        if args.target not in nodes:
            return _die("node --to %r tidak ada di model" % args.target)
        path = shortest_path(adj, args.source, args.target, args.max_depth)
        if path is None:
            print("llabyrinth: peringatan: tidak ada jalur %s -> %s "
                  "(maks %d hop); ekspor tanpa sorotan"
                  % (args.source, args.target, args.max_depth),
                  file=sys.stderr)
    display = build_display(model, path)
    html_text = render_web_html(display)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(html_text)
        except OSError as exc:
            return _die("gagal menulis %s: %s" % (args.out, exc))
        print("HTML ditulis ke %s" % args.out)
    else:
        print(html_text, end="")
    return 0


def cmd_validate(args):
    model, err = _load_or_die(args)
    if err is not None:
        return err
    nodes, edges = model["nodes"], model["edges"]
    problems = []
    problems.extend(model.get("warnings", []))
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


def _add_source_args(sp):
    """Argumen sumber model bersama: file infra JSON (posisional,
    opsional) ATAU --from-nmap untuk impor scan Nmap XML."""
    sp.add_argument("infra", nargs="?", default=None,
                    help="file infra JSON (opsional bila --from-nmap dipakai)")
    sp.add_argument("--from-nmap", dest="nmap", default=None,
                    help="impor model dari file Nmap XML (-oX)")
    sp.add_argument("--include-down", action="store_true",
                    help="(--from-nmap) sertakan host berstatus down")
    sp.add_argument("--include-closed", action="store_true",
                    help="(--from-nmap) sertakan port closed/filtered "
                         "sebagai node service")


def build_parser():
    p = argparse.ArgumentParser(
        prog="llabyrinth",
        description="Pemeta attack path: BFS jalur lateral movement dari infra JSON "
                    "atau scan Nmap (-oX), render ASCII tree, ekspor DOT dan HTML.",
    )
    p.add_argument("--version", action="version", version="llabyrinth " + VERSION)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("paths", help="cari jalur serangan start -> target (BFS)")
    _add_source_args(sp)
    sp.add_argument("--from", dest="source", required=True, help="node awal (titik masuk attacker)")
    sp.add_argument("--to", dest="target", required=True, help="node target")
    sp.add_argument("--all", action="store_true", help="tampilkan SEMUA simple path, bukan cuma tercepat")
    sp.add_argument("--max-depth", type=int, default=8, help="maks hop (default 8)")
    sp.add_argument("--json", action="store_true", help="output JSON")
    sp.set_defaults(func=cmd_paths)

    st = sub.add_parser("tree", help="gambar peta serangan ASCII dari satu titik")
    _add_source_args(st)
    st.add_argument("--from", dest="source", required=True, help="node awal")
    st.add_argument("--max-depth", type=int, default=8, help="maks kedalaman (default 8)")
    st.set_defaults(func=cmd_tree)

    sd = sub.add_parser("dot", help="ekspor graf ke DOT (Graphviz)")
    _add_source_args(sd)
    sd.add_argument("--from", dest="source", default=None, help="sorot jalur tercepat dari node ini")
    sd.add_argument("--to", dest="target", default=None, help="sorot jalur tercepat ke node ini")
    sd.add_argument("--max-depth", type=int, default=8, help="maks hop jalur sorotan (default 8)")
    sd.add_argument("-o", "--out", default=None, help="tulis ke file (default: stdout)")
    sd.set_defaults(func=cmd_dot)

    sw = sub.add_parser("web", help="ekspor graf sebagai satu file HTML interaktif (offline)")
    _add_source_args(sw)
    sw.add_argument("--from", dest="source", default=None, help="sorot jalur tercepat dari node ini")
    sw.add_argument("--to", dest="target", default=None, help="sorot jalur tercepat ke node ini")
    sw.add_argument("--max-depth", type=int, default=8, help="maks hop jalur sorotan (default 8)")
    sw.add_argument("-o", "--out", default=None, help="tulis ke file (default: stdout)")
    sw.set_defaults(func=cmd_web)

    sv = sub.add_parser("validate", help="validasi file infra JSON / hasil impor Nmap")
    _add_source_args(sv)
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
