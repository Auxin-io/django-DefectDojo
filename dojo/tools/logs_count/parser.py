import logging
import json
from dojo.models import Finding


logger = logging.getLogger(__name__)


class LogsCountParser(object):
    """Parser for elasticsearch data count hits value json files."""

    def get_scan_types(self):
        return ["Logs Count"]
    
    def get_label_for_scan_types(self, scan_type):
        return "Logs Count"
    
    def get_description_for_scan_types(self, scan_type):
        return "Logs Count - JSON report format"
    
    def get_findings(self, filename, test):

        report = json.load(filename)
        results = []

        # get the total value
        hit_value = report["hits"]["total"]["value"]

        # add condition to extract platform tags
        platform =  report["alert_platform"]
        
        if platform == "AWS":
            platform_tag = report["hits"]["hits"][0]["_source"]["aws"]["s3"]["bucket"]["name"]
        elif platform == "Azure":
            pass
        elif platform == "GCP":
            pass
        else:
            raise Exception(f'Invalid platform found: {platform}')

        output = {
            'hit_count': hit_value
        }
        description = json.dumps(output)

        finding = Finding(
            title = report["alert_title"],
            test = test,
            description = description,
            severity = report["alert_severity"].title(),
            dynamic_finding=False,
            nb_occurences=1,
        )
        finding.unsaved_tags = [platform_tag]
        
        results.append(finding)
        return results