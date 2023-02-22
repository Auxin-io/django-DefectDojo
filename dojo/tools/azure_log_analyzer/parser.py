
import logging
import json

from dojo.models import Finding
logger = logging.getLogger(__name__)


class AzureLogAnalyzerParser(object):
    """Parser for log analysis json files."""
    
    def get_scan_types(self):
        return ["Azure Log Analyzer"]

    def get_label_for_scan_types(self, scan_type):
        return "Azure Log Analyzer"

    def get_description_for_scan_types(self, scan_type):
        return "Azure Log Analyzer - JSON report format"

    def get_findings(self, filename, test):
        report = json.load(filename)

        results = []
        for item in report["hits"]["hits"]:
            try:
                full_name = item["_source"]["user"]["full_name"]
                domain = item["_source"]["user"]["domain"]
                name = item["_source"]["user"]["name"]
                subscription_id = item["_source"]["azure"]["subscription_id"]
            except:
                full_name = None
                domain = None
                name = None
                subscription_id = None

            try:
                user_role = item["_source"]["azure"]["activitylogs"]["identity"]["authorization"]["evidence"]["role"]
                principal_type = item["_source"]["azure"]["activitylogs"]["identity"]["authorization"]["evidence"]["principal_type"]
                principal_id = item["_source"]["azure"]["activitylogs"]["identity"]["authorization"]["evidence"]["principal_id"]
                scope = item["_source"]["azure"]["activitylogs"]["identity"]["authorization"]["scope"]
                action = item["_source"]["azure"]["activitylogs"]["identity"]["authorization"]["action"]
            except:
                user_role = None
                principal_type = None
                principal_id = None
                scope = None
                action = None

            try:
                event_hub = item["_source"]["azure-eventhub"]["eventhub"]
            except:
                raise Exception('Eventhub is missing from the report. ' + \
                                'search_path: ["_source"]["azure-eventhub"]["eventhub"]')

            try:
                resouce_path = item["_source"]["azure"]["activitylogs"]["properties"]["entity"]
                resouce_message = item["_source"]["azure"]["activitylogs"]["properties"]["message"]
            except:
                resouce_path = None
                resouce_message = None

            description = ""
            if subscription_id:
                description += "**Subscription Id:** " + subscription_id
            
            if full_name:
                description += "\n" + "**User:** " + full_name
            
            if name and domain:
                description += "\n" + "**Identity:** " + name + "@" + domain
            
            if user_role:
                description += "\n" + "**User Role:** " + user_role

            if principal_type:
                description += "\n" + "**Principal Type:** " + principal_type
            
            if principal_id:
                description += "\n" + "**Principal Id:** " + principal_id
            
            if scope:
                description += "\n" + "**Scope:** " + scope
            
            if action:
                description += "\n" + "**Action:** " + action
            
            description += "\n" + "**Source:** " + event_hub
            if event_hub:
                description += "\n" + "**Source Message:** " + resouce_message
                

            finding = Finding(
                title = report["alert_title"],
                test = test,
                description = description,
                severity = report["alert_severity"].title(),
                file_path = resouce_path,
                dynamic_finding=False,
                nb_occurences=1,
            )
            finding.unsaved_tags = [event_hub]

            results.append(finding)

        return results
