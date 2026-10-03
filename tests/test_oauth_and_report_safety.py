import unittest
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

import app as web_app
import zoho_audit_agent as agent


class AccountsRegionTests(unittest.TestCase):
    def test_supported_accounts_hosts_are_normalized(self):
        self.assertEqual(agent._zoho_accounts_url("https://accounts.zoho.in/"), "https://accounts.zoho.in")

    def test_rejects_non_zoho_or_non_https_hosts(self):
        for url in (
            "http://accounts.zoho.in",
            "https://attacker.example",
            "https://accounts.zoho.in.attacker.example",
            "https://user:pass@accounts.zoho.in",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                agent._zoho_accounts_url(url)


class OAuthFlowTests(unittest.TestCase):
    @patch("requests.post")
    def test_grant_exchange_sends_form_data_and_requires_refresh_token(self, post):
        response = Mock()
        response.json.return_value = {"access_token": "short-lived", "refresh_token": "reusable"}
        post.return_value = response

        result = agent.exchange_zoho_grant_code("client", "secret", "one-time-code")

        self.assertEqual(result["refresh_token"], "reusable")
        self.assertIn("data", post.call_args.kwargs)
        self.assertNotIn("params", post.call_args.kwargs)
        self.assertEqual(post.call_args.kwargs["data"]["grant_type"], "authorization_code")

    @patch("requests.post")
    def test_access_token_response_is_not_accepted_as_refresh_token(self, post):
        response = Mock()
        response.json.return_value = {"access_token": "short-lived"}
        post.return_value = response

        with self.assertRaisesRegex(ValueError, "did not return both"):
            agent.exchange_zoho_grant_code("client", "secret", "one-time-code")

    @patch("requests.post")
    def test_refresh_auth_uses_refresh_grant_only(self, post):
        response = Mock()
        response.json.return_value = {"access_token": "short-lived", "api_domain": "https://www.zohoapis.in", "scope": "ZohoCRM.modules.READ"}
        post.return_value = response

        access, refresh, _, _ = agent.unified_zoho_auth("client", "secret", "reusable")

        self.assertEqual((access, refresh), ("short-lived", "reusable"))
        self.assertEqual(post.call_args.kwargs["data"]["grant_type"], "refresh_token")

    @patch.object(agent, "unified_zoho_auth", side_effect=ValueError("invalid refresh token"))
    def test_live_collection_failure_does_not_return_demo_data(self, _auth):
        credentials = {"client_id": "client", "client_secret": "secret", "refresh_token": "expired"}
        with self.assertRaises(agent.ZohoTelemetryError):
            agent.collect_environment_telemetry(credentials, ["Zoho CRM"], force_sample=False)


class ReportScopeTests(unittest.TestCase):
    @patch("requests.get")
    def test_closed_deals_do_not_inflate_active_pipeline(self, get):
        def response(url, **_kwargs):
            payload = Mock(status_code=403)
            payload.json.return_value = {}
            if "/Deals?" in url:
                payload.status_code = 200
                payload.json.return_value = {"data": [
                    {"id": "closed", "Stage": "Closed Won", "Amount": 100,
                     "Closing_Date": "2020-01-01", "Modified_Time": "2020-01-01T00:00:00+00:00"},
                    {"id": "open", "Stage": "Qualification", "Amount": 200,
                     "Closing_Date": "2020-01-01", "Modified_Time": "2020-01-01T00:00:00+00:00"},
                ]}
            return payload
        get.side_effect = response

        metrics = agent.collect_crm_telemetry("test-token", "https://www.zohoapis.in", [])["operational_metrics"]

        self.assertEqual(metrics["deals_sampled"], 2)
        self.assertEqual(metrics["open_deals_sampled"], 1)
        self.assertEqual(metrics["closed_deals_excluded_from_pipeline"], 1)
        self.assertEqual(metrics["total_pipeline_value_sampled"], 200)
        self.assertEqual(metrics["stagnant_pipeline_value_over_60d"], 200)
        self.assertEqual(metrics["stale_deals_over_60d"], 1)
        self.assertEqual(metrics["slipped_deals_count"], 1)

    def test_unavailable_app_is_not_reported_or_scored(self):
        telemetry = {"client_metadata": {"company_name": "Example", "probed_suites": ["Zoho CRM"]},
                     "zoho_crm": {"status": "unauthorized"}}
        report = {"app_audits": [{"app_name": "Zoho CRM", "health_score": 80, "findings": []}],
                  "cross_app_integration_gaps": [{"source": "Zoho CRM", "target": "Zoho Books"}]}

        result = agent.validate_and_normalize_audit_schema(report, telemetry, "Tester")

        self.assertEqual(result["client"]["audited_apps"], [])
        self.assertEqual(result["app_audits"], [])
        self.assertEqual(result["overall_health_score"], 0)
        self.assertEqual(result["cross_app_integration_gaps"], [])

    def test_unset_status_is_not_reported_as_missing_outreach(self):
        telemetry = {
            "client_metadata": {"company_name": "Example", "audit_mode": "Live Zoho API Telemetry"},
            "zoho_crm": {"status": "connected", "operational_metrics": {
                "leads_status_null_count": 4, "leads_sampled": 13,
            }},
        }
        report = {
            "executive_summary": "Uncontacted inbound leads need attention.",
            "app_audits": [{"app_name": "Zoho CRM", "health_score": 50, "findings": [{
                "severity": "CRITICAL", "issue": "Uncontacted inbound leads",
                "root_cause": "No outreach happened", "recommended_fix": "Add a response alert",
            }]}],
            "revenue_and_sales_scaling": {"origination_and_inflow_assessment": {
                "speed_to_lead_latency": "18 hours", "origination_risks": "Missed outreach",
            }},
        }

        result = agent.validate_and_normalize_audit_schema(report, telemetry, "Tester")

        finding = result["app_audits"][0]["findings"][0]
        self.assertEqual(finding["issue"], "Unset Lead Status in sampled records")
        self.assertIn("contact activity was not measured", finding["root_cause"])
        self.assertNotIn("Uncontacted", result["executive_summary"])
        self.assertEqual(result["revenue_and_sales_scaling"]["origination_and_inflow_assessment"]["speed_to_lead_latency"], "Not assessed")

    def test_uninspected_automation_is_not_named_as_root_cause(self):
        telemetry = {"client_metadata": {"company_name": "Example", "audit_mode": "Live Zoho API Telemetry"},
                     "zoho_crm": {"status": "partial_access", "workflow_automation": {"note": "HTTP 403"},
                                  "operational_metrics": {"deals_sampled": 13, "open_deals_sampled": 11,
                                                          "stale_deals_over_60d": 11, "slipped_deals_count": 11}}}
        report = {"app_audits": [{"app_name": "Zoho CRM", "health_score": 50,
                                  "findings": [{"severity": "CRITICAL", "issue": "Stagnant pipeline value",
                                                "root_cause": "Missing deal aging alerts", "recommended_fix": "Review alerts"}]}]}

        result = agent.validate_and_normalize_audit_schema(report, telemetry, "Tester")

        cause = result["app_audits"][0]["findings"][0]["root_cause"]
        self.assertIn("11 of 11 sampled open deals", cause)
        self.assertIn("automation was not assessed", cause)
        self.assertNotIn("Missing deal aging alerts", cause)

    def test_failed_rule_endpoint_is_an_inspection_limit(self):
        telemetry = {
            "client_metadata": {"company_name": "Example", "audit_mode": "Live Zoho API Telemetry"},
            "zoho_crm": {"status": "partial_access", "lead_assignment_rules": [
                {"note": "Lead assignment rules returned HTTP 400"}
            ]},
        }
        report = {"app_audits": [{"app_name": "Zoho CRM", "health_score": 50,
                                  "findings": [{"severity": "CRITICAL", "issue": "Assignment rule endpoint unavailable",
                                                "root_cause": "HTTP 400", "recommended_fix": "Add scopes"}]}]}

        result = agent.validate_and_normalize_audit_schema(report, telemetry, "Tester")

        self.assertEqual(result["app_audits"][0]["findings"], [])
        self.assertIn("lead assignment rules", result["evidence_provenance"]["inspection_limits"])


class DeliverySafetyTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(web_app.app)

    def test_invalid_format_is_rejected_before_analysis(self):
        with patch.object(agent, "collect_environment_telemetry") as collect:
            response = self.client.post("/api/audit?format=txt", data={"use_demo": "true"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.headers["cache-control"], "no-store")
        collect.assert_not_called()

    def test_public_deployment_disables_sample_audits(self):
        with patch.dict(os.environ, {"VERCEL": "1"}, clear=False), patch.object(agent, "collect_environment_telemetry") as collect:
            os.environ.pop("ENABLE_DEMO_AUDIT", None)
            response = self.client.post("/api/audit", data={"use_demo": "true"})
        self.assertEqual(response.status_code, 403)
        collect.assert_not_called()

    def test_pdf_callback_uses_platform_url_without_redirects(self):
        pdf_response = Mock(status_code=200, content=b"%PDF-1.4\nexample")
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "VERCEL": "1", "VERCEL_URL": "untrusted-preview.vercel.app",
            "PDF_RENDER_ORIGIN": "trusted.vercel.app", "PDF_RENDER_TOKEN": "test-token"
        }), patch("requests.post", return_value=pdf_response) as post:
            output = Path(folder) / "audit.pdf"
            self.assertTrue(web_app._render_audit_pdf({}, output))
            self.assertEqual(output.read_bytes(), pdf_response.content)
        self.assertEqual(post.call_args.args[0], "https://trusted.vercel.app/api/pdf.php")
        self.assertFalse(post.call_args.kwargs["allow_redirects"])

    def test_failed_module_probe_does_not_count_as_module(self):
        summary = web_app._extract_telemetry_summary({"zoho_crm": {
            "modules_inventory": [{"note": "Modules endpoint returned HTTP 404"}]
        }}, "Example", ["Zoho CRM"])
        self.assertIsNone(summary["modules_detected"])

    def test_word_download_does_not_invoke_pdf_renderer(self):
        telemetry = {"client_metadata": {"audit_mode": "Sample Diagnostic Baseline"},
                     "zoho_crm": {"status": "connected"}}
        report = {"app_audits": [{"app_name": "Zoho CRM", "findings": []}]}
        def write_word(_report, path):
            Path(path).write_bytes(b"word-test")

        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}), \
             patch.object(agent, "collect_environment_telemetry", return_value=telemetry), \
             patch.object(agent, "analyze_telemetry_with_groq", return_value=report), \
             patch.object(agent, "build_docx", side_effect=write_word), \
             patch.object(web_app, "_render_audit_pdf") as render:
            response = self.client.post("/api/audit?format=docx", data={"use_demo": "true", "company_name": "Example"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"word-test")
        self.assertEqual(response.headers["cache-control"], "no-store")
        render.assert_not_called()

    def test_pdf_failure_returns_error_instead_of_word(self):
        telemetry = {"client_metadata": {"audit_mode": "Sample Diagnostic Baseline"},
                     "zoho_crm": {"status": "connected"}}
        report = {"app_audits": [{"app_name": "Zoho CRM", "findings": []}]}
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}), \
             patch.object(agent, "collect_environment_telemetry", return_value=telemetry), \
             patch.object(agent, "analyze_telemetry_with_groq", return_value=report), \
             patch.object(agent, "build_docx") as build_word, \
             patch.object(web_app, "_render_audit_pdf", return_value=False):
            response = self.client.post("/api/audit?format=pdf", data={"use_demo": "true", "company_name": "Example"})
        self.assertEqual(response.status_code, 502)
        self.assertIn("PDF rendering is unavailable", response.json()["detail"])
        build_word.assert_not_called()


if __name__ == "__main__":
    unittest.main()
