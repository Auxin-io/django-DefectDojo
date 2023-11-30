import logging
import json

from dojo.models import Finding
logger = logging.getLogger(__name__)


class GCPLogAnalyzerParser(object):
    """Parser for GCP log analysis json files."""

    def get_scan_types(self):
        return ["GCP Log Analyzer"]

    def get_label_for_scan_types(self, scan_type):
        return "GCP Log Analyzer"

    def get_description_for_scan_types(self, scan_type):
        return "GCP Log Analyzer - JSON report format"

    def get_findings(self, filename, test):
        report = json.load(filename)

        results = []
        for item in report["hits"]["hits"]:
            full_name = item.get("_source", {}).get("user", {}).get("email", {})
            domain = item.get("_source", {}).get("googlecloud", {}).get("audit", {}).get("authentication_info", {}).get("principal_email")
            audit_request= item.get("_source", {}).get("googlecloud", {}).get("audit", {}).get("request", {}).get("proto_name", {})
            service = item.get("_source", {}).get("googlecloud", {}).get("audit", {}).get("service_name", {})
            resource = item.get("_source", {}).get("googlecloud", {}).get("audit", {}).get("resource_name", {})
            action = item.get("_source", {}).get("googlecloud", {}).get("audit", {}).get("method_name", {})  
            project_id = item.get("_source", {}).get("cloud", {}).get("project", {}).get("id", {})

            description = ""
            if project_id:
                description += "**Project Id:** " + project_id

            if full_name:
                description += "\n" + "**User:** " + full_name

            if service:
                description += "\n" + "**Service:** " + service

            if resource:
                description += "\n" + "**Resource:** " + resource

            if action:
                description += "\n" + "**Action:** " + action

            if audit_request:
                description += "\n" + "**Request:** " + audit_request


            finding = Finding(
                title = report["alert_title"],
                test = test,
                description = description,
                severity = report["alert_severity"].title(),
                file_path = resource,
                dynamic_finding=False,
                nb_occurences=1,
            )
            finding.unsaved_tags = [project_id]

            results.append(finding)

        return results
