#!/usr/bin/env python3
"""Unit test fitur 1.1.0 llabyrinth: impor Nmap + ekspor web.
Stdlib only. Jalankan: python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llabyrinth import (  # noqa: E402
    InfraError,
    build_display,
    import_nmap,
    render_web_html,
    shortest_path,
    build_graph,
    _json_for_html,
)

BIN = os.path.join(os.path.dirname(__file__), "..", "llabyrinth.py")
SAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "scan-sample.xml")
CORP = os.path.join(os.path.dirname(__file__), "..", "examples", "corp.json")


def read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write_tmp(text, suffix=".xml"):
    fh = tempfile.NamedTemporaryFile(
        "w", suffix=suffix, delete=False, encoding="utf-8")
    fh.write(text)
    fh.close()
    return fh.name


def run_cli(*argv):
    return subprocess.run(
        [sys.executable, BIN] + list(argv),
        capture_output=True, text=True, timeout=60,
    )


def extract_model(html_text):
    marker = '<script type="application/json" id="model">'
    start = html_text.index(marker) + len(marker)
    end = html_text.index("</script>", start)
    return json.loads(html_text[start:end])


EVIL_XML = (
    '<nmaprun scanner="nmap" version="7.94"><host>'
    '<status state="up" reason="echo-reply"/>'
    '<address addr="10.6.6.6" addrtype="ipv4"/>'
    '<hostnames><hostname name="&lt;script&gt;alert(1)&lt;/script&gt;" type="PTR"/></hostnames>'
    '<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>'
    '<service name="http" product="&quot;&gt;&lt;img src=x onerror=alert(2)&gt;" version="1.0"/>'
    '<script id="http-title" output="&lt;/title&gt;&lt;svg onload=alert(3)&gt;"/>'
    '</port></ports></host></nmaprun>'
)


class TestImportNmap(unittest.TestCase):
    def test_sample_counts(self):
        m = import_nmap(SAMPLE)
        hosts = [n for n in m["nodes"].values() if n["type"] == "host"]
        groups = [n for n in m["nodes"].values() if n["type"] == "group"]
        services = [n for n in m["nodes"].values() if n["type"] == "service"]
        self.assertEqual(len(hosts), 7)
        self.assertEqual(len(groups), 3)
        self.assertEqual(len(services), 17)
        self.assertEqual(len(m["edges"]), 14 + 17)
        self.assertEqual(m["meta"]["version"], "7.94")

    def test_down_host_skipped_by_default_with_warning(self):
        m = import_nmap(SAMPLE)
        self.assertNotIn("192.168.1.30", m["nodes"])
        self.assertTrue(any("down" in w for w in m["warnings"]))

    def test_include_down(self):
        m = import_nmap(SAMPLE, include_down=True)
        self.assertIn("192.168.1.30", m["nodes"])
        self.assertEqual(m["warnings"], [])
        # Host down tidak punya service.
        self.assertFalse(any(e["from"] == "192.168.1.30" and
                             e["rel"] == "exposes" for e in m["edges"]))

    def test_filtered_and_closed_excluded_by_default(self):
        m = import_nmap(SAMPLE)
        self.assertNotIn("192.168.1.1:8080/tcp", m["nodes"])   # filtered
        self.assertNotIn("192.168.1.20:22/tcp", m["nodes"])    # closed

    def test_include_closed(self):
        m = import_nmap(SAMPLE, include_closed=True)
        self.assertIn("192.168.1.1:8080/tcp", m["nodes"])
        self.assertIn("192.168.1.20:22/tcp", m["nodes"])

    def test_ipv6_host_and_subnet(self):
        m = import_nmap(SAMPLE)
        self.assertIn("2001:db8:85a3::8a2e:370:7334", m["nodes"])
        self.assertIn("2001:db8:85a3:0::/64", m["nodes"])

    def test_details_carry_scan_data(self):
        m = import_nmap(SAMPLE)
        fs = m["details"]["192.168.1.10"]
        self.assertEqual(fs["macVendor"], "Synology Incorporated")
        self.assertEqual(fs["hostnames"][0]["name"], "fileserver.lan")
        ws = m["details"]["192.168.1.20"]
        p80 = [p for p in ws["ports"] if p["portid"] == 80][0]
        self.assertEqual(p80["service"]["product"], "Apache httpd")
        title = [s for s in p80["scripts"] if s["id"] == "http-title"][0]
        self.assertEqual(title["output"], "Example <b>Portal</b> - sign in")
        svc = m["details"]["192.168.1.20:3306/tcp"]
        self.assertEqual(svc["port"]["service"]["name"], "mysql")

    def test_mac_merge_multihomed_host(self):
        xml = (
            '<nmaprun scanner="nmap" version="7.94">'
            '<host><status state="up" reason="arp"/>'
            '<address addr="192.168.1.50" addrtype="ipv4"/>'
            '<address addr="AA:BB:CC:00:00:01" addrtype="mac" vendor="X"/>'
            '<ports><port protocol="tcp" portid="22"><state state="open" reason="s"/>'
            '<service name="ssh"/></port></ports></host>'
            '<host><status state="up" reason="arp"/>'
            '<address addr="10.0.0.50" addrtype="ipv4"/>'
            '<address addr="aa:bb:cc:00:00:01" addrtype="mac" vendor="X"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open" reason="s"/>'
            '<service name="https"/></port></ports></host>'
            '</nmaprun>'
        )
        m = import_nmap(write_tmp(xml))
        hosts = [n for n in m["nodes"].values() if n["type"] == "host"]
        self.assertEqual(len(hosts), 1)
        det = m["details"]["192.168.1.50"]
        self.assertEqual(len(det["subnets"]), 2)
        self.assertEqual(len(det["ports"]), 2)
        self.assertEqual(len(det["addresses"]), 4)
        # Kedua subnet terhubung lewat host yang sama.
        adj = build_graph(m["nodes"], m["edges"])
        path = shortest_path(adj, "192.168.1.0/24", "10.0.0.0/24")
        self.assertIsNotNone(path)

    def test_extraports_non_numeric_count_skipped(self):
        # Regresi audit Minggu 2026-10-25: count="abc" sempat meledak
        # jadi ValueError mentah (traceback), bukan error bersih.
        xml = (
            '<nmaprun scanner="nmap" version="7.94">'
            '<host><status state="up" reason="arp"/>'
            '<address addr="10.9.9.1" addrtype="ipv4"/>'
            '<ports><extraports state="closed" count="abc"/>'
            '<extraports state="filtered" count="42"/>'
            '<port protocol="tcp" portid="80"><state state="open" reason="s"/>'
            '<service name="http"/></port></ports></host>'
            '</nmaprun>'
        )
        m = import_nmap(write_tmp(xml))
        det = m["details"]["10.9.9.1"]
        self.assertEqual(det["extraPorts"],
                         [{"state": "filtered", "count": 42}])
        self.assertIn("10.9.9.1:80/tcp", m["nodes"])

    def test_malformed_xml_is_clean_error(self):
        p = write_tmp("<nmaprun><host><status state='up'")
        with self.assertRaises(InfraError):
            import_nmap(p)

    def test_truncated_xml_is_clean_error(self):
        text = read_text(SAMPLE)
        p = write_tmp(text[: text.index("</ports>")])
        with self.assertRaises(InfraError):
            import_nmap(p)

    def test_non_nmap_xml_is_clean_error(self):
        p = write_tmp("<html><body>halo</body></html>")
        with self.assertRaises(InfraError) as ctx:
            import_nmap(p)
        self.assertIn("nmaprun", str(ctx.exception))

    def test_missing_file_is_clean_error(self):
        with self.assertRaises(InfraError):
            import_nmap("/tidak/ada/scan.xml")

    def test_deeply_nested_script_tables_do_not_crash(self):
        # Regresi audit ronde 1: <table> bersarang 5000 lapis di dalam
        # <script> sempat membuat importer RecursionError (traceback).
        depth = 5000
        xml = ('<nmaprun scanner="nmap" version="7.94"><host>'
               '<status state="up" reason="x"/>'
               '<address addr="10.1.1.3" addrtype="ipv4"/>'
               '<ports><port protocol="tcp" portid="80">'
               '<state state="open" reason="s"/><service name="http"/>'
               '<script id="deep" output="o">' + '<table key="t">' * depth +
               '<elem key="leaf">v</elem>' + '</table>' * depth +
               '</script></port></ports></host></nmaprun>')
        m = import_nmap(write_tmp(xml))  # tidak boleh raise
        self.assertIn("10.1.1.3", m["nodes"])

    def test_port_without_portid_gets_placeholder_label(self):
        xml = ('<nmaprun scanner="nmap" version="7.94"><host>'
               '<status state="up" reason="x"/>'
               '<address addr="10.1.1.4" addrtype="ipv4"/>'
               '<ports><port protocol="tcp"><state state="open" reason="s"/>'
               '<service name="http"/></port></ports></host></nmaprun>')
        m = import_nmap(write_tmp(xml))
        d = build_display(m)
        labels = [p["label"] for p in d["details"]["10.1.1.4"]["ports"]]
        self.assertEqual(labels, ["?/tcp"])
        # Tanpa portid tidak ada node service.
        self.assertFalse(any(n["type"] == "service"
                             for n in m["nodes"].values()))

    def test_xxe_external_entity_is_clean_error(self):
        xml = ('<?xml version="1.0"?>'
               '<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
               '<nmaprun scanner="nmap" version="7.94"><host>'
               '<status state="up" reason="x"/>'
               '<address addr="10.1.1.1" addrtype="ipv4"/>'
               '<hostnames><hostname name="&xxe;" type="PTR"/></hostnames>'
               '</host></nmaprun>')
        with self.assertRaises(InfraError):
            import_nmap(write_tmp(xml))

    def test_evil_strings_preserved_verbatim_in_details(self):
        m = import_nmap(write_tmp(EVIL_XML))
        det = m["details"]["10.6.6.6"]
        self.assertEqual(det["hostnames"][0]["name"],
                         "<script>alert(1)</script>")
        self.assertEqual(det["ports"][0]["service"]["product"],
                         '"><img src=x onerror=alert(2)>')


class TestWebExport(unittest.TestCase):
    def test_json_for_html_neutralises_script_breakout(self):
        payload = {"x": "</script><script>alert(1)</script><!--"}
        out = _json_for_html(payload)
        self.assertNotIn("</script", out)
        self.assertNotIn("<!--", out)
        self.assertEqual(json.loads(out), payload)

    def test_display_nmap_structure(self):
        m = import_nmap(SAMPLE)
        d = build_display(m)
        kinds = {}
        for n in d["nodes"]:
            kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
        self.assertEqual(kinds, {"subnet": 3, "host": 7, "port": 17})
        ws = d["details"]["192.168.1.20"]
        ports = {p["label"]: p for p in ws["ports"]}
        self.assertEqual(ports["3306/tcp"]["service"], "mysql")
        # Tabel detail memuat SEMUA port termasuk closed ssh.
        self.assertIn("22/tcp", ports)
        self.assertEqual(ports["22/tcp"]["state"], "closed")

    def test_display_path_overlay_nmap(self):
        m = import_nmap(SAMPLE)
        adj = build_graph(m["nodes"], m["edges"])
        path = shortest_path(adj, "192.168.1.1", "192.168.1.20:3306/tcp")
        d = build_display(m, path)
        # Edge jalur dinyatakan dalam arah edge tampilan (subnet -> host),
        # walau jalur model berjalan host -> subnet.
        self.assertEqual(d["path"]["edges"], [
            ["subnet:192.168.1.0/24", "192.168.1.1"],
            ["subnet:192.168.1.0/24", "192.168.1.20"],
            ["192.168.1.20", "192.168.1.20:3306/tcp"],
        ])
        self.assertIn("3306", d["path"]["summary"])

    def test_display_path_overlay_infra(self):
        from llabyrinth import load_infra
        nodes, edges = load_infra(CORP)
        model = {"nodes": nodes, "edges": edges, "details": None,
                 "meta": None, "warnings": [], "source": "infra"}
        adj = build_graph(nodes, edges)
        path = shortest_path(adj, "attacker", "dc01")
        d = build_display(model, path)
        self.assertEqual(d["path"]["nodes"][0], "attacker")
        self.assertEqual(d["path"]["nodes"][-1], "dc01")
        self.assertEqual(len(d["path"]["edges"]), len(path) - 1)

    def test_render_html_self_contained_and_escaped(self):
        m = import_nmap(write_tmp(EVIL_XML))
        html_text = render_web_html(build_display(m))
        # Hanya dua tag script sah: blok JSON model + renderer.
        self.assertEqual(html_text.count("<script"), 2)
        self.assertNotIn("<img src=x", html_text)
        self.assertNotIn("http://", html_text.replace(
            "http://www.w3.org/2000/svg", ""))
        self.assertNotIn("https://", html_text)
        model = extract_model(html_text)
        det = model["details"]["10.6.6.6"]
        self.assertEqual(det["title"], "<script>alert(1)</script>")

    def test_render_title_token_collision(self):
        # Regresi audit ronde 2: args scan mengandung literal token
        # template -> <title> tidak boleh ketumpahan dump JSON.
        xml = ('<nmaprun scanner="nmap" args="nmap __MODEL_JSON__ __TITLE__" '
               'version="7.94"><host><status state="up" reason="x"/>'
               '<address addr="10.1.1.6" addrtype="ipv4"/></host></nmaprun>')
        m = import_nmap(write_tmp(xml))
        html_text = render_web_html(build_display(m))
        head = html_text.split("</title>")[0]
        self.assertNotIn('"nodes"', head)
        self.assertIn("nmap __MODEL_JSON__ __TITLE__", head)
        model = extract_model(html_text)
        self.assertEqual(model["title"], "nmap __MODEL_JSON__ __TITLE__")

    def test_render_html_contains_model_data(self):
        m = import_nmap(SAMPLE)
        html_text = render_web_html(build_display(m))
        model = extract_model(html_text)
        self.assertEqual(model["statsLine"],
                         "7 hosts · 17 services · 3 subnets")
        self.assertIn("192.168.1.20:3306/tcp", model["details"])

    def test_port_cap_collapses_display_but_not_details(self):
        ports = "".join(
            '<port protocol="tcp" portid="%d"><state state="open" reason="s"/>'
            '<service name="svc%d"/></port>' % (1000 + i, i)
            for i in range(40))
        xml = ('<nmaprun scanner="nmap" version="7.94"><host>'
               '<status state="up" reason="x"/>'
               '<address addr="172.16.0.9" addrtype="ipv4"/>'
               '<ports>%s</ports></host></nmaprun>' % ports)
        m = import_nmap(write_tmp(xml))
        d = build_display(m)
        port_nodes = [n for n in d["nodes"] if n["kind"] == "port"]
        more_nodes = [n for n in d["nodes"] if n["kind"] == "more"]
        self.assertEqual(len(port_nodes), 30)
        self.assertEqual(len(more_nodes), 1)
        self.assertEqual(len(d["details"]["172.16.0.9"]["ports"]), 40)


class TestCliNmapWeb(unittest.TestCase):
    def test_paths_from_nmap(self):
        r = run_cli("paths", "--from-nmap", SAMPLE,
                    "--from", "192.168.1.1", "--to", "192.168.1.20:3306/tcp")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("3 hop", r.stdout)

    def test_paths_no_source_is_error(self):
        r = run_cli("paths", "--from", "a", "--to", "b")
        self.assertEqual(r.returncode, 1)
        self.assertIn("error", r.stderr)

    def test_web_writes_file(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "peta.html")
            r = run_cli("web", "--from-nmap", SAMPLE,
                        "--from", "192.168.1.1",
                        "--to", "192.168.1.20:3306/tcp", "-o", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            text = read_text(out)
            model = extract_model(text)
            self.assertIsNotNone(model["path"])

    def test_web_unknown_node_is_error(self):
        r = run_cli("web", "--from-nmap", SAMPLE,
                    "--from", "192.168.1.1", "--to", "tidak-ada")
        self.assertEqual(r.returncode, 1)

    def test_validate_from_nmap(self):
        r = run_cli("validate", "--from-nmap", SAMPLE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("valid", r.stdout)

    def test_web_from_infra_json(self):
        with tempfile.TemporaryDirectory() as td:
            out = os.path.join(td, "corp.html")
            r = run_cli("web", CORP, "--from", "attacker", "--to", "dc01",
                        "-o", out)
            self.assertEqual(r.returncode, 0, r.stderr)
            model = extract_model(read_text(out))
            self.assertEqual(model["path"]["nodes"][0], "attacker")
            self.assertEqual(model["path"]["nodes"][-1], "dc01")


if __name__ == "__main__":
    unittest.main()
