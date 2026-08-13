import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import cf_transfer


class TestR2KeyMapping(unittest.TestCase):
    def setUp(self):
        self.folder_map = [
            ("acp.copernicus.org", "articles", True),
            ("acp_full", "web", True),
            ("acp", "legacy", True),
        ]

    @staticmethod
    def _simulate_url_path_to_r2_key(folder_map, pathname):
        root_prefix = next(r2 for local, r2, _ in folder_map if local.endswith(".copernicus.org"))
        mapping = {"": root_prefix}
        for local, r2, _ in folder_map:
            if ".copernicus.org" not in local:
                mapping[r2] = r2

        bare = pathname[1:] if pathname.startswith("/") else pathname
        for url_prefix in mapping:
            if url_prefix == "":
                continue
            if bare == url_prefix or bare.startswith(url_prefix + "/"):
                key = bare
                break
        else:
            key = f"{mapping['']}/{bare}" if mapping.get("") else bare

        if key.endswith("/") or key == "":
            key = key + "index.html"
        elif "." not in key:
            key = key + "/index.html"
        return key

    def test_url_path_to_r2_key_cases(self):
        expected = {
            "/": "articles/index.html",
            "/index.html": "articles/index.html",
            "/foo/": "articles/foo/index.html",
            "/foo/index.html": "articles/foo/index.html",
            "/web/": "web/index.html",
            "/web/foo.html": "web/foo.html",
            "/legacy/foo.pdf": "legacy/foo.pdf",
        }
        for path, key in expected.items():
            self.assertEqual(self._simulate_url_path_to_r2_key(self.folder_map, path), key)


class TestSSICacheKey(unittest.TestCase):
    def test_generated_worker_uses_prefix_scoped_ssi_cache_keys(self):
        js = cf_transfer.generate_index_js(
            shortcut="acp",
            numeric_groups={},
            letter_groups={},
            irregular=[],
            symlink_map={},
            origin_map={"articles": "https://acp.copernicus.org"},
            folder_map=[("acp.copernicus.org", "articles", True), ("acp_full", "web", True)],
            unmigrated_rewrites=[],
        )
        self.assertIn("const cacheKey = r2prefix + ':' + virtualPath;", js)
        self.assertIn("FRAGMENT_CACHE.get(cacheKey)", js)
        self.assertIn("FRAGMENT_CACHE.set(cacheKey", js)


class TestRedirectGrouping(unittest.TestCase):
    def test_numeric_grouping_includes_status(self):
        rules = [
            {"to": "https://example.org/articles/$1", "status": 301, "r2_prefix": "web"},
            {"to": "https://example.org/articles/$1", "status": 302, "r2_prefix": "web"},
        ]
        grouped = cf_transfer.group_mirror_rules(rules)
        statuses = {k[3] for k in grouped.keys()}
        self.assertEqual(statuses, {301, 302})
        self.assertEqual(len(grouped), 2)

    def test_letter_grouping_includes_letter_and_status(self):
        rules = [
            {"to": "https://example.org/articles/$1", "status": 301, "r2_prefix": "web", "prefix": "C"},
            {"to": "https://example.org/articles/$1", "status": 302, "r2_prefix": "web", "prefix": "C"},
        ]
        grouped = cf_transfer.group_letter_rules_by_prefix(rules)
        keys = list(grouped.keys())
        self.assertTrue(all(k[2] == "C" for k in keys))
        self.assertEqual({k[4] for k in keys}, {301, 302})

    def test_irregular_redirect_passthrough(self):
        js = cf_transfer.generate_irregular_redirect_js([
            {"type": "Redirect", "from": "/old", "to": "https://example.org/new", "status": 302, "r2_prefix": "web"}
        ], root_r2_prefix="articles")
        self.assertIn('"from":"/old"', js)
        self.assertIn('"status":302', js)


class TestSymlinkMap(unittest.TestCase):
    def test_symlink_map_same_prefix_cross_prefix_and_broken(self):
        with tempfile.TemporaryDirectory() as td:
            webroot = Path(td)
            root_dir = webroot / "acp.copernicus.org"
            web_dir = webroot / "acp_full"
            root_dir.mkdir(parents=True)
            web_dir.mkdir(parents=True)

            (root_dir / "target.txt").write_text("x")
            (web_dir / "web-target.txt").write_text("y")

            (root_dir / "same.txt").symlink_to(root_dir / "target.txt")
            (root_dir / "cross.txt").symlink_to(web_dir / "web-target.txt")
            (root_dir / "broken.txt").symlink_to(root_dir / "missing.txt")

            with mock.patch.object(cf_transfer, "WEBROOT", webroot):
                symlinks = [
                    cf_transfer.categorise_symlink(root_dir / "same.txt", str(root_dir / "target.txt")),
                    cf_transfer.categorise_symlink(root_dir / "cross.txt", str(web_dir / "web-target.txt")),
                    cf_transfer.categorise_symlink(root_dir / "broken.txt", str(root_dir / "missing.txt")),
                ]

            folder_map = [
                ("acp.copernicus.org", "articles", True),
                ("acp_full", "web", True),
            ]

            with mock.patch.object(cf_transfer, "WEBROOT", webroot):
                mapping, cross, _ = cf_transfer.build_symlink_map(symlinks, folder_map)

            self.assertEqual(mapping["/articles/same.txt"], "/articles/target.txt")
            self.assertEqual(len(cross), 1)
            self.assertEqual(cross[0]["from"], "/cross.txt")
            self.assertIsNone(cross[0]["scope"])
            self.assertNotIn("/articles/broken.txt", mapping)


class TestDeployFailureHandling(unittest.TestCase):
    def test_symlink_upload_failure_aborts_without_deploy_done(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "index.js").write_text("export default {}")
            (out / "symlinks.json").write_text("{}")

            cp = cf_transfer.subprocess.CompletedProcess(args=["wrangler"], returncode=0, stdout="", stderr="")

            with mock.patch.object(cf_transfer, "get_cf_env", return_value=("a" * 32, "token" * 8, None)), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", side_effect=[True, False]), \
                 mock.patch.object(cf_transfer, "parse_workers_dev_url", return_value=None), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=[cp, cp]), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_deploy(cf_transfer.JournalAnalysis(shortcut="acp"))

            self.assertFalse(ok)
            self.assertFalse((out / ".deploy_done").exists())


class TestVerifyHeaders(unittest.TestCase):
    def test_verify_notes_for_r2_hit_origin_fallback_and_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            analysis = cf_transfer.JournalAnalysis(shortcut="acp")

            head_calls = [
                (200, None, {}), (200, None, {"X-R2-Hit": "1"}),
                (200, None, {}), (200, None, {"X-Origin-Fallback": "1"}),
                (301, "https://origin.example/new", {}), (200, None, {}),
            ]

            with mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "get_cf_env", return_value=("a" * 32, "token" * 8, "zone")), \
                 mock.patch.object(cf_transfer, "synthesise_test_paths", return_value=["/r2", "/fb", "/bad"]), \
                 mock.patch.object(cf_transfer, "http_head", side_effect=head_calls), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_verify(analysis)

            self.assertFalse(ok)
            report = json.loads((out / "verify_report.json").read_text())
            self.assertIn("R2 hit", report[0]["note"])
            self.assertIn("origin fallback", report[1]["note"])
            self.assertIn("expected 301", report[2]["note"])


class TestSynthesisePaths(unittest.TestCase):
    def test_includes_root_index_and_folder_sample_paths(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            root = base / "acp.copernicus.org"
            web = base / "acp_full"
            legacy = base / "acp"
            root.mkdir(parents=True)
            web.mkdir(parents=True)
            legacy.mkdir(parents=True)

            (root / "rootfile.html").write_text("root")
            (web / "webfile.html").write_text("web")
            (legacy / "legacyfile.html").write_text("legacy")

            analysis = cf_transfer.JournalAnalysis(
                shortcut="acp",
                folders=[
                    cf_transfer.FolderInfo(name="acp.copernicus.org", path=root, exists=True, mandatory=True),
                    cf_transfer.FolderInfo(name="acp_full", path=web, exists=True, mandatory=True),
                    cf_transfer.FolderInfo(name="acp", path=legacy, exists=True, mandatory=True),
                ],
                vhosts=[],
            )

            paths = cf_transfer.synthesise_test_paths(analysis)

            self.assertIn("/", paths)
            self.assertIn("/index.html", paths)
            self.assertIn("/rootfile.html", paths)
            self.assertIn("/web/webfile.html", paths)
            self.assertIn("/legacy/legacyfile.html", paths)


if __name__ == "__main__":
    unittest.main()
