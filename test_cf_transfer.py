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
        self.host_to_r2_prefix = {
            "acp.copernicus.org": "articles",
            "atmospheric-chemistry-and-physics.net": "web",
            "atmos-chem-phys.net": "legacy",
        }

    @staticmethod
    def _simulate_url_path_to_r2_key(folder_map, pathname, hostname=None, host_to_r2_prefix=None):
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
            r2_prefix = (host_to_r2_prefix or {}).get(hostname) or mapping.get("") or ""
            key = f"{r2_prefix}/{bare}" if r2_prefix else bare

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
        self.assertEqual(
            self._simulate_url_path_to_r2_key(
                self.folder_map, "/", "atmos-chem-phys.net", self.host_to_r2_prefix
            ),
            "legacy/index.html",
        )
        self.assertEqual(
            self._simulate_url_path_to_r2_key(
                self.folder_map, "/foo/", "atmospheric-chemistry-and-physics.net", self.host_to_r2_prefix
            ),
            "web/foo/index.html",
        )


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
        self.assertIn("const HOST_TO_R2_PREFIX =", js)
        self.assertIn("urlPathToR2Key(pathname, url.hostname)", js)
        self.assertIn("HOST_TO_R2_PREFIX[hostname] ?? keyToR2Prefix(key)", js)


class TestZoneIdCollection(unittest.TestCase):
    def test_legacy_cf_zone_id_falls_back_to_articles_only(self):
        calls = []

        def fake_prompt(name, description, secret=False, required=True):
            calls.append((name, description))
            return {
                "CF_ZONE_ID_ARTICLES": "",
                "CF_ZONE_ID_WEB": "",
                "CF_ZONE_ID_LEGACY": "",
                "CF_ZONE_ID": "legacy-zone",
            }.get(name, "")

        folder_map = [
            ("acp.copernicus.org", "articles", True),
            ("acp_full", "web", True),
            ("acp", "legacy", True),
        ]
        prefix_origin = {
            "articles": "https://acp.copernicus.org",
            "web": "https://atmospheric-chemistry-and-physics.net",
            "legacy": "https://atmos-chem-phys.net",
        }

        with mock.patch.object(cf_transfer, "_prompt_credential", side_effect=fake_prompt):
            zone_ids = cf_transfer.get_cf_zone_ids(folder_map, prefix_origin)

        self.assertEqual(zone_ids, {"articles": "legacy-zone"})
        self.assertTrue(any("atmos-chem-phys.net" in desc for _, desc in calls))


class TestDeployScriptGeneration(unittest.TestCase):
    def test_deploy_script_supports_multiple_zone_env_vars(self):
        script = cf_transfer.generate_deploy_sh(
            "acp",
            "acp.copernicus.org",
            "bucket-acp",
            {
                "articles": "https://acp.copernicus.org",
                "web": "https://atmospheric-chemistry-and-physics.net",
                "legacy": "https://atmos-chem-phys.net",
            },
        )
        self.assertIn('CF_ZONE_ID_ARTICLES:?not set', script)
        self.assertIn('CF_ZONE_ID_WEB:-', script)
        self.assertIn('CF_ZONE_ID_LEGACY:-', script)
        self.assertIn('Setting route ${DOMAIN}/*', script)
        self.assertIn('TOTAL_STEPS=$((3 + ROUTE_COUNT))', script)


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

            with mock.patch.object(cf_transfer, "get_cf_account", return_value=("a" * 32, "token" * 8)), \
                 mock.patch.object(cf_transfer, "get_cf_zone_ids", return_value={}), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={"articles": "https://acp.copernicus.org"}), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", side_effect=[True, False]), \
                 mock.patch.object(cf_transfer, "parse_workers_dev_url", return_value=None), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=[cp, cp]), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_deploy(cf_transfer.JournalAnalysis(shortcut="acp"))

            self.assertFalse(ok)
            self.assertFalse((out / ".deploy_done").exists())

    def test_multiple_routes_use_per_prefix_zone_ids(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "index.js").write_text("export default {}")
            (out / "symlinks.json").write_text("{}")

            cp = cf_transfer.subprocess.CompletedProcess(args=["wrangler"], returncode=0, stdout="", stderr="")
            cf_api_calls = []

            def fake_cf_api(method, path, token, **kwargs):
                cf_api_calls.append((method, path, kwargs.get("json")))
                if method == "GET":
                    return {"success": True, "result": []}
                return {"success": True, "result": {}}

            with mock.patch.object(cf_transfer, "get_cf_account", return_value=("a" * 32, "token" * 8)), \
                 mock.patch.object(cf_transfer, "get_cf_zone_ids", return_value={"articles": "zone-a", "web": "zone-w"}), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={
                     "articles": "https://acp.copernicus.org",
                     "web": "https://atmospheric-chemistry-and-physics.net",
                 }), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", return_value=True), \
                 mock.patch.object(cf_transfer, "parse_workers_dev_url", return_value="https://acp-worker.example.workers.dev"), \
                 mock.patch.object(cf_transfer, "cf_api", side_effect=fake_cf_api), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=[cp, cp]), \
                 mock.patch("builtins.input", return_value=""), \
                 mock.patch("requests.get") as mock_get:
                mock_get.return_value.status_code = 200
                ok = cf_transfer.run_deploy(cf_transfer.JournalAnalysis(shortcut="acp"))

            self.assertTrue(ok)
            post_payloads = [payload for method, path, payload in cf_api_calls if method == "POST"]
            self.assertEqual(
                post_payloads,
                [
                    {"pattern": "acp.copernicus.org/*", "script": "acp-worker"},
                    {"pattern": "atmospheric-chemistry-and-physics.net/*", "script": "acp-worker"},
                ],
            )


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
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={"articles": "https://acp.copernicus.org"}), \
                 mock.patch.object(cf_transfer, "synthesise_test_paths", return_value=["/r2", "/fb", "/bad"]), \
                 mock.patch.object(cf_transfer, "http_head", side_effect=head_calls), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_verify(analysis)

            self.assertFalse(ok)
            report = json.loads((out / "verify_report.json").read_text())
            self.assertIn("R2 hit", report[0]["note"])
            self.assertIn("origin fallback", report[1]["note"])
            self.assertIn("expected 301", report[2]["note"])

    def test_verify_adds_domain_notes_for_additional_origins(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            analysis = cf_transfer.JournalAnalysis(shortcut="acp")

            head_calls = [
                (200, None, {}), (200, None, {"X-R2-Hit": "1"}),
                (200, None, {}), (200, None, {}),
                (200, None, {}), (200, None, {}),
            ]

            with mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "get_cf_env", return_value=("a" * 32, "token" * 8, "zone")), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={
                     "articles": "https://acp.copernicus.org",
                     "legacy": "https://atmos-chem-phys.net",
                 }), \
                 mock.patch.object(cf_transfer, "synthesise_test_paths", return_value=["/primary"]), \
                 mock.patch.object(cf_transfer, "http_head", side_effect=head_calls), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_verify(analysis)

            self.assertTrue(ok)
            report = json.loads((out / "verify_report.json").read_text())
            self.assertTrue(any("domain=atmos-chem-phys.net" in row["note"] for row in report))


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
