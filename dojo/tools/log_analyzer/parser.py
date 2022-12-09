
import logging
import json

from dojo.models import Finding
logger = logging.getLogger(__name__)


class LogAnalyzerParser(object):
    """Parser for log analysis json files."""
    
    def get_scan_types(self):
        return ["Log Analyzer"]

    def get_label_for_scan_types(self, scan_type):
        return "Log Analyzer"

    def get_description_for_scan_types(self, scan_type):
        return "JSON report format"

    def get_findings(self, filename, test):
        data = json.load(filename)

        results = list()
        # if "generated_at" in data:
        #     find_date = dateutil.parser.parse(data["generated_at"])

        for item in data["hits"]["hits"]:
            try:
                name = item["_source"]["user"]["name"]
                id = item["_source"]["user"]["id"]
            except:
                name= "Null"
                id = "Null"
            try:
               type= item["_source"]["aws"]["cloudtrail"]["user_identity"]["session_context"]["session_issuer"]["type"]
               account_id =item["_source"]["aws"]["cloudtrail"]["user_identity"]["session_context"]["session_issuer"]["account_id"]

            except:
                type="Null"
                account_id = "Null"
            findingdetail = "\n".join(
                [
                    "**name** `" + name + "`" ,
                    "**id** `" + id + "`",
                    "**Role:** `" + type + "`",
                    "**Account ID:** `" + account_id + "`",
                    "**Filename:** `" + item["_source"]["log"]["file"]["path"] + "`",
                    
                ]
            )

            finding = Finding(
                title=data["alert_title"],
                test=test,
                tags = account_id,
                description=findingdetail,
                references = str(item["_source"]["event"]["original"]),
                # severity=item["issue_severity"].title(),
                severity=data["alert_severity"],
                file_path=item["_source"]["log"]["file"]["path"],
                # line=item["line_number"],
                # date=find_date,
                static_finding=True,
                dynamic_finding=False,
                # vuln_id_from_tool=":".join([item["test_name"], item["test_id"]]),
                nb_occurences=1,
            )
            # manage confidence
            # confidence = self.convert_confidence(item.get("issue_confidence"))
            # if confidence:
            #     finding.scanner_confidence = confidence
            # if "more_info" in item:
            #     finding.references = item["more_info"]

            results.append(finding)

        return results

    # def convert_confidence(self, value):
    #     if "high" == value.lower():
    #         return 2
    #     elif "medium" == value.lower():
    #         return 3
    #     elif "low" == value.lower():
    #         return 6
    #     else:
    #         return None

