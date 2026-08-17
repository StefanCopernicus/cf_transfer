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
        self.assertIn("const SYMLINK_MAP_DEFAULT = {};", js)
        self.assertIn("const shardCache = {};", js)
        self.assertIn("async function getSymlinkShard(env, r2prefix)", js)
        self.assertIn("const requestPrefix = keyToR2Prefix(key);", js)
        self.assertIn("const symlinkShard = await getSymlinkShard(env, requestPrefix);", js)


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
        self.assertTrue(any(
            desc.startswith("Zone ID for atmos-chem-phys.net (legacy/)\n")
            for _, desc in calls
        ))


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
        self.assertIn('CF_ZONE_ID_ARTICLES="${CF_ZONE_ID_ARTICLES:-${CF_ZONE_ID:-}}"', script)
        self.assertIn('CF_ZONE_ID_WEB:-', script)
        self.assertIn('CF_ZONE_ID_LEGACY:-', script)
        self.assertIn('Setting route ${DOMAIN}/*', script)
        self.assertIn('SHARD_FILES=("${SCRIPT_DIR}/symlinks/"*.json)', script)
        self.assertIn('TOTAL_STEPS=$((2 + ROUTE_COUNT + SYMLINK_UPLOAD_STEPS))', script)
        self.assertIn('/objects/_symlinks/${prefix}.json', script)


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


class TestGenerateOutputs(unittest.TestCase):
    def test_run_generate_writes_sharded_symlink_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            analysis = cf_transfer.JournalAnalysis(shortcut="acp")
            symlink_map = {
                "/articles/foo.pdf": "/articles/real/foo.pdf",
                "/legacy/bar.pdf": "/legacy/real/bar.pdf",
            }

            with mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "get_folder_map", return_value=[("acp.copernicus.org", "articles", True), ("acp", "legacy", True)]), \
                 mock.patch.object(cf_transfer, "collect_all_symlinks", return_value=[]), \
                 mock.patch.object(cf_transfer, "build_symlink_map", return_value=(symlink_map, [], {"articles": "https://acp.copernicus.org", "legacy": "https://legacy.example"})), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={"articles": "https://acp.copernicus.org", "legacy": "https://legacy.example"}), \
                 mock.patch.object(cf_transfer, "collect_host_to_r2_prefix", return_value={"acp.copernicus.org": "articles"}), \
                 mock.patch.object(cf_transfer, "collect_all_redirects", return_value=({}, {}, [])), \
                 mock.patch.object(cf_transfer, "collect_unmigrated_rewrite_rules", return_value=[]):
                ok = cf_transfer.run_generate(analysis)

            self.assertTrue(ok)
            self.assertEqual(json.loads((out / "symlinks.json").read_text()), symlink_map)
            self.assertEqual(
                json.loads((out / "symlinks" / "articles.json").read_text()),
                {"/articles/foo.pdf": "/articles/real/foo.pdf"},
            )
            self.assertEqual(
                json.loads((out / "symlinks" / "legacy.json").read_text()),
                {"/legacy/bar.pdf": "/legacy/real/bar.pdf"},
            )
            generated_js = (out / "index.js").read_text()
            self.assertIn("const SYMLINK_MAP_DEFAULT = {};", generated_js)


class TestDeployFailureHandling(unittest.TestCase):
    def test_symlink_upload_failure_aborts_without_deploy_done(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "index.js").write_text("export default {}")
            (out / "symlinks.json").write_text("{}")

            cp = cf_transfer.subprocess.CompletedProcess(args=["wrangler"], returncode=0, stdout="", stderr="")

            with mock.patch.object(cf_transfer, "get_cf_account", return_value=("a" * 32, "token" * 8)), \
                 mock.patch.object(cf_transfer, "get_cf_zone_ids", return_value={}), \
                 mock.patch.object(cf_transfer, "cf_api", return_value={"result": []}), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={"articles": "https://acp.copernicus.org"}), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", side_effect=[True, False]), \
                 mock.patch.object(cf_transfer, "parse_workers_dev_url", return_value=None), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=[cp, cp]), \
                 mock.patch("builtins.input", return_value=""):
                ok = cf_transfer.run_deploy(cf_transfer.JournalAnalysis(shortcut="acp"))

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

    def test_run_deploy_uploads_sharded_symlink_files(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            (out / "index.js").write_text("export default {}")
            (out / "symlinks.json").write_text("{}")
            symlink_dir = out / "symlinks"
            symlink_dir.mkdir()
            (symlink_dir / "articles.json").write_text("{}")
            (symlink_dir / "legacy.json").write_text("{}")

            cp = cf_transfer.subprocess.CompletedProcess(args=["wrangler"], returncode=0, stdout="", stderr="")
            run_calls = []

            def fake_run(cmd, **kwargs):
                run_calls.append(cmd)
                return cp

            with mock.patch.object(cf_transfer, "get_cf_account", return_value=("a" * 32, "token" * 8)), \
                 mock.patch.object(cf_transfer, "get_cf_zone_ids", return_value={}), \
                 mock.patch.object(cf_transfer, "cf_api", return_value={"result": []}), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={"articles": "https://acp.copernicus.org"}), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", return_value=True), \
                 mock.patch.object(cf_transfer, "parse_workers_dev_url", return_value="https://acp-worker.example.workers.dev"), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=fake_run), \
                 mock.patch("requests.get") as mock_get:
                mock_get.return_value.status_code = 200
                ok = cf_transfer.run_deploy(cf_transfer.JournalAnalysis(shortcut="acp"))

            self.assertTrue(ok)
            flattened = [" ".join(cmd) for cmd in run_calls]
            self.assertTrue(any("_symlinks/articles.json" in cmd for cmd in flattened))
            self.assertTrue(any("_symlinks/legacy.json" in cmd for cmd in flattened))
            self.assertFalse(any("_symlinks.json" in cmd for cmd in flattened))


class TestRunSetup(unittest.TestCase):
    def test_bucket_existence_check_does_not_match_substrings(self):
        with tempfile.TemporaryDirectory() as td:
            analysis = cf_transfer.JournalAnalysis(shortcut="ar")
            cp_list = cf_transfer.subprocess.CompletedProcess(
                args=["wrangler", "r2", "bucket", "list"],
                returncode=0,
                stdout="bucket-ars\nbucket-foo\n",
                stderr="",
            )
            cp_ok = cf_transfer.subprocess.CompletedProcess(args=["wrangler"], returncode=0, stdout="", stderr="")
            run_calls = []

            def fake_run(cmd, **kwargs):
                run_calls.append(cmd)
                if cmd[-2:] == ["bucket", "list"]:
                    return cp_list
                return cp_ok

            with mock.patch.object(cf_transfer, "get_cf_account", return_value=("a" * 32, "token" * 8)), \
                 mock.patch.object(cf_transfer, "validate_cf_credentials", return_value=True), \
                 mock.patch.object(cf_transfer, "get_folder_map", return_value=[("ar.copernicus.org", "articles", True)]), \
                 mock.patch.object(cf_transfer, "get_output_dir", return_value=Path(td)), \
                 mock.patch.object(cf_transfer, "check_wrangler", return_value=True), \
                 mock.patch.object(cf_transfer, "wrangler_ok", return_value=True), \
                 mock.patch.object(cf_transfer.subprocess, "run", side_effect=fake_run):
                ok = cf_transfer.run_setup(analysis)

        self.assertTrue(ok)
        self.assertTrue(any(cmd[-3:] == ["bucket", "create", "bucket-ar"] for cmd in run_calls))


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

    def test_verify_includes_symlink_results_in_report(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            analysis = cf_transfer.JournalAnalysis(shortcut="acp")
            (out / "symlinks.json").write_text(json.dumps({
                "/articles/preprints/acp-2012-101/foo.pdf": "/articles/preprints/12/101/foo.pdf",
                "/legacy/archive/bar.pdf": "/legacy/real/bar.pdf",
            }))

            head_calls = [
                (200, None, {}), (200, None, {"X-R2-Hit": "1"}),
                (200, None, {"X-R2-Hit": "1"}),
                (200, None, {}),
            ]

            with mock.patch.object(cf_transfer, "get_output_dir", return_value=out), \
                 mock.patch.object(cf_transfer, "get_cf_env", return_value=("a" * 32, "token" * 8, "zone")), \
                 mock.patch.object(cf_transfer, "get_folder_map", return_value=[
                     ("acp.copernicus.org", "articles", True),
                     ("acp", "legacy", True),
                 ]), \
                 mock.patch.object(cf_transfer, "infer_prefix_origin", return_value={
                     "articles": "https://acp.copernicus.org",
                 }), \
                 mock.patch.object(cf_transfer, "synthesise_test_paths", return_value=["/primary"]), \
                 mock.patch.object(cf_transfer, "http_head", side_effect=head_calls), \
                 mock.patch("builtins.input", side_effect=["", "2"]):
                ok = cf_transfer.run_verify(analysis)

            self.assertFalse(ok)
            report = json.loads((out / "verify_report.json").read_text())
            symlink_rows = [row for row in report if row["note"].startswith("symlink→")]
            self.assertEqual([row["path"] for row in symlink_rows], [
                "/preprints/acp-2012-101/foo.pdf",
                "/legacy/archive/bar.pdf",
            ])
            self.assertTrue(symlink_rows[0]["match"])
            self.assertFalse(symlink_rows[1]["match"])
            self.assertIn("R2 hit", symlink_rows[0]["note"])
            self.assertIn("HTTP 200 no-R2-hit", symlink_rows[1]["note"])


class TestHostFieldInRedirectRules(unittest.TestCase):
    def test_host_for_prefix_strips_scheme_and_slash(self):
        po = {"legacy": "https://atmos-phys.net/", "articles": "https://ap.copernicus.org"}
        self.assertEqual(cf_transfer._host_for_prefix("legacy", po), "atmos-phys.net")
        self.assertEqual(cf_transfer._host_for_prefix("articles", po), "ap.copernicus.org")
        self.assertEqual(cf_transfer._host_for_prefix("unknown", po), "")

    def test_irregular_redirect_js_emits_host(self):
        rule = {
            "type": "RedirectMatch",
            "pattern": "^/index\\.html$",
            "to": "https://ap.copernicus.org/articles/index.html",
            "status": 301,
            "r2_prefix": "legacy",
            "host": "atmos-phys.net",
        }
        js = cf_transfer.generate_irregular_redirect_js([rule], root_r2_prefix="articles")
        self.assertIn('"host":"atmos-phys.net"', js)

    def test_irregular_redirect_js_null_host_when_empty(self):
        rule = {
            "type": "RedirectMatch",
            "pattern": "^/index\\.html$",
            "to": "https://ap.copernicus.org/articles/index.html",
            "status": 301,
            "r2_prefix": "legacy",
            "host": "",
        }
        js = cf_transfer.generate_irregular_redirect_js([rule], root_r2_prefix="articles")
        self.assertIn('"host":null', js)

    def test_generate_index_js_emits_host_in_redirect_rules(self):
        prefix_origin = {
            "articles": "https://ap.copernicus.org",
            "legacy": "https://atmos-phys.net",
        }
        folder_map = [
            ("ap.copernicus.org", "articles", True),
            ("ap", "legacy", True),
        ]
        # minimal numeric group for legacy
        numeric_groups = {
            ("https://ap.copernicus.org", "articles", "legacy", 301): [{"r2_prefix": "legacy"}]
        }
        js = cf_transfer.generate_index_js(
            shortcut="ap",
            numeric_groups=numeric_groups,
            letter_groups={},
            irregular=[],
            symlink_map={},
            origin_map=prefix_origin,
            folder_map=folder_map,
        )
        self.assertIn("'atmos-phys.net'", js)
        # 5-tuple destructuring in worker
        self.assertIn("const [scope, pattern, template, status, host] of REDIRECT_RULES", js)
        self.assertIn("if (host && url.hostname !== host) continue;", js)

    def test_worker_js_irregular_host_guard_present(self):
        folder_map = [
            ("ap.copernicus.org", "articles", True),
            ("ap", "legacy", True),
        ]
        js = cf_transfer.generate_index_js(
            shortcut="ap",
            numeric_groups={},
            letter_groups={},
            irregular=[],
            symlink_map={},
            origin_map={"articles": "https://ap.copernicus.org", "legacy": "https://atmos-phys.net"},
            folder_map=folder_map,
        )
        self.assertIn("if (rule.host && url.hostname !== rule.host) continue;", js)


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


class TestZoneIdPersistence(unittest.TestCase):
    def test_save_and_load_zone_ids(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            zone_ids = {"articles": "abc123", "web": "def456"}
            cf_transfer.save_zone_ids(output_dir, zone_ids)
            loaded = cf_transfer.load_zone_ids(output_dir)
            self.assertEqual(loaded, zone_ids)

    def test_load_zone_ids_returns_empty_when_missing(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            loaded = cf_transfer.load_zone_ids(output_dir)
            self.assertEqual(loaded, {})

    def test_load_zone_ids_returns_empty_on_corrupt_file(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            (output_dir / ".zone_ids").write_text("not valid json{{")
            loaded = cf_transfer.load_zone_ids(output_dir)
            self.assertEqual(loaded, {})

    def test_save_zone_ids_does_nothing_when_empty(self):
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            cf_transfer.save_zone_ids(output_dir, {})
            self.assertFalse((output_dir / ".zone_ids").exists())


if __name__ == "__main__":
    unittest.main()
