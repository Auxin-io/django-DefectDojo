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
            try:
                full_name = item["_source"]["user"]["email"]
                domain = item["_source"]["googlecloud"]["audit"]["authentication_info"]["principal_email"]
            except:
                full_name = None
                domain = None

            try:
                audit_request= item["_source"]["googlecloud"]["audit"]["request"]["proto_name"]
                service = item["_source"]["googlecloud"]["audit"]["service_name"]
                resource = item["_source"]["googlecloud"]["audit"]["resource_name"]
                action = item["_source"]["googlecloud"]["audit"]["method_name"]
            except:
                audit_request = None
                service = None
                resource = None
                action = None

            try:
                project_id = item["_source"]["cloud"]["project"]["id"]
            except:
                raise Exception('project id is missing from the report. ' + \
                                'search_path: ["_source"]["cloud"]["project"]["id"]')

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
