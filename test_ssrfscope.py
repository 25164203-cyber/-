import argparse
import contextlib
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ssrfscope  # noqa: E402


class SnapshotTests(unittest.TestCase):
    def snapshot(self, **kwargs):
        values = dict(
            status=200,
            headers={"Content-Type": "text/plain", "Authorization": "Bearer secret", "X-Test": "ok"},
            body="normal response",
            body_length=15,
            body_sha256="hash",
            elapsed_ms=10.0,
            content_type="text/plain",
            title=None,
            signatures=[],
        )
        values.update(kwargs)
        return ssrfscope.ResponseSnapshot(**values)

    def test_sensitive_headers_redacted_by_default_and_can_be_disabled(self):
        snap = self.snapshot()
        public = snap.public()
        self.assertEqual(public["headers"]["Authorization"], "[REDACTED]")
        self.assertEqual(public["headers"]["X-Test"], "ok")
        self.assertEqual(snap.public(redact=False)["headers"]["Authorization"], "Bearer secret")

    def test_max_headers_bounds_output(self):
        snap = self.snapshot(headers={f"X-{i}": str(i) for i in range(4)})
        public = snap.public(max_headers=2)
        self.assertEqual(len(public["headers"]), 2)

    def test_representative_baseline_preserves_response_snapshot(self):
        first = self.snapshot(body="a", body_length=1, elapsed_ms=10)
        second = self.snapshot(body="bb", body_length=2, elapsed_ms=30)
        representative = ssrfscope.representative_snapshot([first, second])
        self.assertIsInstance(representative, ssrfscope.ResponseSnapshot)
        self.assertEqual(representative.body_length, 2)
        self.assertEqual(representative.elapsed_ms, 20)

    def test_scoring_and_confidence_are_heuristic(self):
        baseline = self.snapshot()
        candidate = self.snapshot(
            status=500,
            body="redis_version: 7",
            body_length=100,
            signatures=["redis"],
            error=None,
        )
        score, reasons = ssrfscope.response_diff_score(baseline, candidate)
        confidence = ssrfscope.confidence_from_evidence(score, reasons, candidate)
        self.assertGreaterEqual(score, 3)
        self.assertIn("status changed (200 -> 500)", reasons)
        self.assertGreater(confidence, 0.2)
        self.assertLessEqual(confidence, 0.95)


class RetryAndJSONTests(unittest.TestCase):
    def test_http_response_is_not_retried(self):
        client = ssrfscope.HTTPClient(1, 100, True, False, "test", retries=2)
        response = Mock()
        response.status = 503
        response.getcode.return_value = 503
        response.headers.items.return_value = [("Content-Type", "text/plain")]
        response.read.return_value = b"busy"
        response.close.return_value = None
        client.opener.open = Mock(return_value=response)
        snapshot = client.fetch("http://127.0.0.1:1/", "GET", {}, None)
        self.assertEqual(snapshot.status, 503)
        self.assertEqual(client.opener.open.call_count, 1)

    def test_response_snapshot_public_shape_remains_json_serializable(self):
        snap = ssrfscope.ResponseSnapshot(
            status=200,
            headers={},
            body="ok",
            body_length=2,
            body_sha256="x",
            elapsed_ms=1.2,
            content_type="text/plain",
            title=None,
            signatures=[],
        )
        encoded = json.dumps(snap.public())
        decoded = json.loads(encoded)
        self.assertEqual(decoded["status"], 200)
        self.assertIn("body_preview", decoded)
        self.assertIn("headers", decoded)

    def test_run_probe_uses_configurable_baseline_count(self):
        args = argparse.Namespace(
            baseline_count=3,
            redact=True,
            max_headers=100,
            url="http://127.0.0.1/test?url=x",
            method="GET",
            body_json=None,
            body_form=None,
        )
        target = ssrfscope.Target("parameter", "url")
        sample = ssrfscope.ResponseSnapshot(200, {}, "ok", 2, "x", 1, "text/plain", None, [])
        client = Mock()
        client.fetch.return_value = sample
        executor = __import__("concurrent.futures").futures.ThreadPoolExecutor(max_workers=1)
        try:
            result = ssrfscope.run_probe(args, client, target, [("http://127.0.0.1/", None)], {}, executor)
        finally:
            executor.shutdown(wait=True)
        self.assertEqual(client.fetch.call_count, 4)  # 3 baselines + 1 candidate
        self.assertEqual(len(result["baseline_samples"]), 3)
        self.assertIn("confidence", result["attempts"][0])


class DiscoveryAndInterfaceTests(unittest.TestCase):
    def test_discover_is_local_only_and_finds_query_json_and_form_inputs(self):
        args = ssrfscope.create_parser().parse_args([
            "discover", "http://127.0.0.1/fetch?url=x", "--body-json", '{"options":{"redirect":{"url":"x"}}}',
            "--body-form", "mode=test&destination=x", "--all-request-headers", "--json", "--no-color",
        ])
        with patch.object(ssrfscope, "build_opener", side_effect=AssertionError("network must not be used")):
            result = ssrfscope.discover_inputs(args)
        names = {(item["kind"], item["name"]) for item in result["targets"]}
        self.assertIn(("parameter", "url"), names)
        self.assertIn(("json-body", "options.redirect.url"), names)
        self.assertIn(("form-body", "mode"), names)
        self.assertEqual(result["network_requests"], 0)
        self.assertIn("authorization", result["excluded_request_headers"])

    def test_no_color_and_no_color_environment_strip_ansi(self):
        self.assertFalse(ssrfscope.colors_enabled(no_color=True, stream=io.StringIO()))
        with patch.dict(os.environ, {"NO_COLOR": "1"}, clear=False):
            self.assertFalse(ssrfscope.colors_enabled(stream=io.StringIO()))

    def test_banner_prints_without_exception(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ssrfscope.show_banner(no_color=True)
        text = output.getvalue()
        self.assertIn("SSRFSCOPE", text)
        self.assertIn("AUTHORIZATION REQUIRED", text)
        self.assertNotIn("\033[", text)


class HTMLReportTests(unittest.TestCase):
    def document(self, attempts=None):
        attempts = attempts if attempts is not None else [{
            "target": {"kind": "parameter", "name": "url<script>"},
            "payload": "http://example.test/ignored",
            "payload_template": "http://example.test/?q=<script>alert(1)</script>",
            "response": {
                "status": 500,
                "headers": {
                    "Content-Type": "text/plain",
                    "Authorization": "Bearer secret",
                    "Cookie": "sid=secret",
                },
                "body_length": 42,
                "body_sha256": "hash",
                "content_type": "text/plain",
                "title": "<title>",
                "truncated": False,
                "elapsed_ms": 12.3,
                "body_preview": "secret preview",
            },
            "baseline": {"status": 200, "body_length": 4, "body_sha256": "base"},
            "score": 3,
            "severity": "possible-ssrf",
            "confidence": 0.7,
            "reasons": ["reason <b>unsafe</b>"],
        }]
        return {
            "url": "http://authorized.test/fetch?url=x",
            "generated_at": "now",
            "version": "test",
            "summary": {"targets": 1, "attempts": len(attempts), "possible_ssrf": 1 if attempts else 0, "interesting": 0, "inconclusive": 0},
            "results": [{"attempts": attempts}],
        }

    def test_detailed_findings_have_sections_and_anchors(self):
        report = ssrfscope.build_html_report(self.document())
        self.assertIn("id='finding-1'", report)
        self.assertIn("href='#finding-1'", report)
        for label in ("Target injection point", "Payload template", "Severity", "Confidence", "Score", "Reasons", "Response summary", "Baseline summary", "Methodology and limitations", "إرشادات المعالجة العامة"):
            self.assertIn(label, report)

    def test_payload_and_reasons_are_escaped(self):
        report = ssrfscope.build_html_report(self.document())
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertIn("reason &lt;b&gt;unsafe&lt;/b&gt;", report)
        self.assertNotIn("<script>alert(1)</script>", report)

    def test_sensitive_headers_and_preview_not_leaked_by_default(self):
        report = ssrfscope.build_html_report(self.document())
        self.assertNotIn("Bearer secret", report)
        self.assertNotIn("sid=secret", report)
        self.assertNotIn("secret preview", report)

    def test_no_findings_is_explicit(self):
        report = ssrfscope.build_html_report(self.document([]))
        self.assertIn("لا توجد اكتشافات Interesting أو Possible SSRF", report)
        self.assertIn("لا توجد محاولات مسجلة", report)


class DeepAuditSafetyTests(unittest.TestCase):
    def test_parser_uses_conservative_deep_audit_defaults(self):
        args = ssrfscope.create_parser().parse_args(["deep-audit", "http://authorized.example/fetch?url=x"])
        self.assertEqual(args.baseline_count, 3)
        self.assertEqual(args.retries, 1)
        self.assertEqual(args.workers, 2)
        self.assertGreaterEqual(args.delay, 0.05)
        self.assertTrue(args.redact)

    def test_dry_run_plan_has_no_network_and_allows_missing_payload(self):
        args = ssrfscope.create_parser().parse_args([
            "deep-audit", "http://authorized.example/fetch?url=x", "--dry-run", "--json",
        ])
        with patch.object(ssrfscope, "build_opener", side_effect=AssertionError("network must not be used")):
            plan = ssrfscope.build_deep_audit_plan(args)
        self.assertEqual(plan["network_requests"], 0)
        self.assertEqual(plan["payloads"], [])
        self.assertFalse(plan["payloads_explicit"])
        self.assertEqual(plan["settings"]["baseline_count"], 3)

    def test_non_dry_run_requires_explicit_payload(self):
        args = ssrfscope.create_parser().parse_args(["deep-audit", "http://authorized.example/fetch?url=x"])
        with self.assertRaisesRegex(ValueError, "explicit"):
            ssrfscope.build_deep_audit_plan(args)

    def test_scope_allowlist_rejects_out_of_scope_hostname_without_dns(self):
        args = ssrfscope.create_parser().parse_args([
            "deep-audit", "http://outside.example/fetch?url=x", "--scope-host", "authorized.example",
            "--payload", "http://payload.example/",
        ])
        with patch.object(ssrfscope.socket, "getaddrinfo", side_effect=AssertionError("DNS must not be used")):
            with self.assertRaisesRegex(ValueError, "outside"):
                ssrfscope.build_deep_audit_plan(args)

    def test_deep_audit_plan_supports_explicit_payload_and_scope(self):
        args = ssrfscope.create_parser().parse_args([
            "deep-audit", "http://authorized.example/fetch?url=x", "--scope-host", "authorized.example",
            "--payload", "http://payload.example/", "--param", "url",
        ])
        plan = ssrfscope.build_deep_audit_plan(args)
        self.assertTrue(plan["payloads_explicit"])
        self.assertEqual(plan["target_scope"]["target_hostname"], "authorized.example")
        self.assertEqual(plan["targets"], [{"kind": "parameter", "name": "url"}])


if __name__ == "__main__":
    unittest.main()


# Keep a local reference to avoid lint tools treating the imported module as unused.
_UNUSED = ssrfscope
