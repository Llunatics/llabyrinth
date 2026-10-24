#!/usr/bin/env python3
"""Unit test llabyrinth — stdlib only. Jalankan: python3 -m unittest discover -s tests"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from llabyrinth import (  # noqa: E402
    InfraError,
    _term_safe,
    all_paths,
    build_graph,
    load_infra,
    path_edges,
    reachable_tree,
    render_dot,
    render_path,
    shortest_path,
)

BIN = os.path.join(os.path.dirname(__file__), "..", "llabyrinth.py")
EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "corp.json")

NODES = {
    "attacker": {"id": "attacker", "type": "principal"},
    "alice": {"id": "alice", "type": "user"},
    "ws01": {"id": "ws01", "type": "host"},
    "dc01": {"id": "dc01", "type": "host"},
}
EDGES = [
    {"from": "attacker", "to": "alice", "rel": "phished"},
    {"from": "alice", "to": "ws01", "rel": "local-admin"},
    {"from": "ws01", "to": "dc01", "rel": "has-session"},
    {"from": "alice", "to": "dc01", "rel": "rdp"},
]


def write_infra(data):
    fh = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    json.dump(data, fh)
    fh.close()
    return fh.name


class TestLoadInfra(unittest.TestCase):
    def test_example_valid(self):
        nodes, edges = load_infra(EXAMPLE)
        self.assertEqual(len(nodes), 13)
        self.assertEqual(len(edges), 14)
        self.assertEqual(nodes["dc01"]["type"], "host")

    def test_missing_file(self):
        with self.assertRaises(InfraError):
            load_infra("/tidak/ada.json")

    def test_bad_json(self):
        p = write_infra(None)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{bukan json")
        try:
            with self.assertRaises(InfraError):
                load_infra(p)
        finally:
            os.unlink(p)

    def test_duplicate_id(self):
        p = write_infra({"nodes": [{"id": "a"}, {"id": "a"}], "edges": []})
        try:
            with self.assertRaises(InfraError) as ctx:
                load_infra(p)
            self.assertIn("duplikat", str(ctx.exception))
        finally:
            os.unlink(p)

    def test_dangling_edge(self):
        p = write_infra({"nodes": [{"id": "a"}], "edges": [{"from": "a", "to": "hantu", "rel": "rdp"}]})
        try:
            with self.assertRaises(InfraError) as ctx:
                load_infra(p)
            self.assertIn("hantu", str(ctx.exception))
        finally:
            os.unlink(p)

    def test_bad_node_type(self):
        p = write_infra({"nodes": [{"id": "a", "type": "alien"}], "edges": []})
        try:
            with self.assertRaises(InfraError):
                load_infra(p)
        finally:
            os.unlink(p)

    def test_default_type_is_user(self):
        p = write_infra({"nodes": [{"id": "a"}], "edges": []})
        try:
            nodes, _ = load_infra(p)
            self.assertEqual(nodes["a"]["type"], "user")
        finally:
            os.unlink(p)


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.adj = build_graph(NODES, EDGES)

    def test_shortest_picks_fewer_hops(self):
        path = shortest_path(self.adj, "attacker", "dc01")
        self.assertEqual([n for n, _ in path], ["attacker", "alice", "dc01"])

    def test_start_equals_goal(self):
        self.assertEqual(shortest_path(self.adj, "alice", "alice"), [("alice", None)])

    def test_no_path(self):
        self.assertIsNone(shortest_path(self.adj, "dc01", "attacker"))

    def test_max_depth_respected(self):
        # attacker->alice->ws01->dc01 butuh 3 hop; batasi 2 -> None
        self.assertIsNone(shortest_path(self.adj, "attacker", "ws01", max_depth=1))
        self.assertIsNotNone(shortest_path(self.adj, "attacker", "ws01", max_depth=2))

    def test_all_paths_no_cycles(self):
        adj = build_graph(
            {"a": {"id": "a", "type": "user"}, "b": {"id": "b", "type": "user"},
             "c": {"id": "c", "type": "user"}},
            [{"from": "a", "to": "b", "rel": "rdp"},
             {"from": "b", "to": "a", "rel": "rdp"},  # cycle a<->b
             {"from": "b", "to": "c", "rel": "smb"}],
        )
        paths = all_paths(adj, "a", "c")
        self.assertEqual(len(paths), 1)
        self.assertEqual([n for n, _ in paths[0]], ["a", "b", "c"])

    def test_all_paths_sorted_shortest_first(self):
        paths = all_paths(self.adj, "attacker", "dc01")
        self.assertEqual(len(paths), 2)
        self.assertLessEqual(len(paths[0]), len(paths[1]))

    def test_path_edges(self):
        path = [("a", None), ("b", "rdp"), ("c", "smb")]
        self.assertEqual(path_edges(path), [("a", "b"), ("b", "c")])


class TestTree(unittest.TestCase):
    def test_tree_marks_cycle(self):
        adj = build_graph(
            {"a": {"id": "a", "type": "user"}, "b": {"id": "b", "type": "user"}},
            [{"from": "a", "to": "b", "rel": "rdp"}, {"from": "b", "to": "a", "rel": "rdp"}],
        )
        lines = reachable_tree(adj, {"a": {"id": "a", "type": "user"},
                                     "b": {"id": "b", "type": "user"}}, "a")
        self.assertTrue(any("cycle" in ln for ln in lines))

    def test_tree_contains_nodes_and_rels(self):
        adj = build_graph(NODES, EDGES)
        text = "\n".join(reachable_tree(adj, NODES, "attacker"))
        self.assertIn("alice", text)
        self.assertIn("phished", text)
        self.assertIn("dc01", text)


class TestDot(unittest.TestCase):
    def test_dot_structure_and_highlight(self):
        dot = render_dot(NODES, EDGES, {("attacker", "alice")})
        self.assertIn("digraph attack_paths", dot)
        self.assertIn('"dc01" [shape=box', dot)
        self.assertIn('"attacker" [shape=plaintext', dot)
        self.assertIn('color=red', dot)

    def test_dot_valid_braces(self):
        dot = render_dot(NODES, EDGES)
        self.assertEqual(dot.count("{"), dot.count("}"))


class TestCLI(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, BIN, *args],
            capture_output=True, text=True, timeout=30,
        )

    def test_paths_ok(self):
        r = self.run_cli("paths", EXAMPLE, "--from", "attacker", "--to", "dc01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dc01", r.stdout)
        self.assertIn("phished", r.stdout)

    def test_paths_json(self):
        r = self.run_cli("paths", EXAMPLE, "--from", "attacker", "--to", "dc01", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertEqual(data["nodes"][-1], "dc01")

    def test_paths_all(self):
        r = self.run_cli("paths", EXAMPLE, "--from", "attacker", "--to", "dc01", "--all")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("path 1", r.stdout)

    def test_no_path_exit_2(self):
        r = self.run_cli("paths", EXAMPLE, "--from", "dc01", "--to", "attacker")
        self.assertEqual(r.returncode, 2)

    def test_tree_ok(self):
        r = self.run_cli("tree", EXAMPLE, "--from", "attacker")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("alice", r.stdout)
        self.assertIn("cycle", r.stdout)  # helpdesk -> alice balik

    def test_dot_stdout(self):
        r = self.run_cli("dot", EXAMPLE, "--from", "attacker", "--to", "dc01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("digraph", r.stdout)
        self.assertIn("color=red", r.stdout)

    def test_validate_ok(self):
        r = self.run_cli("validate", EXAMPLE)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("valid", r.stdout)

    def test_validate_bad_file(self):
        r = self.run_cli("validate", "/tidak/ada.json")
        self.assertEqual(r.returncode, 1)
        self.assertIn("error", r.stderr)

    def test_unknown_node(self):
        r = self.run_cli("paths", EXAMPLE, "--from", "hantu", "--to", "dc01")
        self.assertEqual(r.returncode, 1)

    def test_dot_to_without_from_warns(self):
        r = self.run_cli("dot", EXAMPLE, "--to", "dc01")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("peringatan", r.stderr)
        self.assertIn("digraph", r.stdout)


class TestAuditFixes(unittest.TestCase):
    """Regresi temuan audit 2026-10-21."""

    def test_dot_escapes_quotes_and_backslash(self):
        nodes = {
            'a"b': {"id": 'a"b', "type": "user"},
            "c\\d": {"id": "c\\d", "type": "host"},
        }
        edges = [{"from": 'a"b', "to": "c\\d", "rel": 'x"y\nz'}]
        dot = render_dot(nodes, edges)
        # id ter-escape: tidak ada lagi token mentah yang merusak sintaks
        self.assertIn('"a\\"b"', dot)
        self.assertIn('"c\\\\d"', dot)
        self.assertIn('label="x\\"y\\nz"', dot)
        self.assertNotIn('"a"b"', dot.replace('\\"', ""))
        self.assertEqual(dot.count("{"), dot.count("}"))

    def test_tree_no_duplicate_at_depth_limit(self):
        # X dicapai tepat di batas max_depth lewat dua parent:
        # sebelum fix, X digambar dua kali sebagai node baru.
        nodes = {n: {"id": n, "type": "user"} for n in ["r", "A", "B", "X"]}
        edges = [
            {"from": "r", "to": "A", "rel": "e"},
            {"from": "r", "to": "B", "rel": "e"},
            {"from": "A", "to": "X", "rel": "e"},
            {"from": "B", "to": "X", "rel": "e"},
        ]
        adj = build_graph(nodes, edges)
        lines = reachable_tree(adj, nodes, "r", max_depth=2)
        x_lines = [ln for ln in lines if "X [user]" in ln]
        self.assertEqual(len(x_lines), 2)
        self.assertEqual(sum("sudah digambar" in ln for ln in x_lines), 1)

    def test_term_safe_strips_control_chars(self):
        # Karakter kontrol (ESC, newline, NUL, DEL, BEL) dari id tak
        # tepercaya -> netral; sisa teks '[31m' tanpa ESC itu inert.
        self.assertEqual(_term_safe("h\x1b[31mRED\x1b[0m"), "h[31mRED[0m")
        self.assertEqual(_term_safe("a\nFAKE: owned"), "a FAKE: owned")
        self.assertEqual(_term_safe("x\x00y\x7fz"), "xyz")
        self.assertEqual(_term_safe("biasa-123"), "biasa-123")

    def test_tree_output_has_no_raw_control_chars(self):
        # id berisi ESC + newline: tree satu baris per node, tanpa escape mentah
        evil = "h\x1b[31mRED\x1b[0m\nFAKE: owned"
        nodes = {"r": {"id": "r", "type": "host"},
                 evil: {"id": evil, "type": "host"}}
        adj = build_graph(nodes, [{"from": "r", "to": evil, "rel": "scans"}])
        for ln in reachable_tree(adj, nodes, "r"):
            self.assertNotIn("\x1b", ln)
            self.assertNotIn("\n", ln)
        self.assertTrue(any("h[31mRED[0m FAKE: owned [host]" in ln
                            for ln in reachable_tree(adj, nodes, "r")))

    def test_render_path_neutralises_control_chars(self):
        evil = "n\x1b[2K\nINJEKSI"
        text = render_path([("r", ""), (evil, "rel\x07x")])
        self.assertNotIn("\x1b", text)
        self.assertEqual(text.count("\n"), 1)  # hanya pemisah baris path
        self.assertIn("n[2K INJEKSI", text)

    def test_function_default_max_depth_is_8(self):
        # rantai 7 hop: butuh max_depth >= 7 (default lama 6 gagal)
        ids = ["n%d" % i for i in range(8)]
        nodes = {nid: {"id": nid, "type": "user"} for nid in ids}
        edges = [{"from": ids[i], "to": ids[i + 1], "rel": "e"} for i in range(7)]
        adj = build_graph(nodes, edges)
        path = shortest_path(adj, ids[0], ids[7])
        self.assertIsNotNone(path)
        self.assertEqual(len(path) - 1, 7)


if __name__ == "__main__":
    unittest.main()
