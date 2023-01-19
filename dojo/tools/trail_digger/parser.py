
import logging
import json
import os
import re

from dojo.models import Finding
logger = logging.getLogger(__name__)


class TrailDiggerParser(object):
    """Parser for trail digger text files."""
    
    def get_scan_types(self):
        return ["Trail Digger Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Tool for digging trail log files of AWS CloudTrail - TXT Report"

    def get_findings(self, filename, test):

        # Parse txt file into dictionary 
        report_file = filename.readlines()[2:]
        output = {}
        resource_type = []
        previous_key = None
        for line in report_file:
            line = line.decode().strip()
            tmp = line.replace('  ', '|')
            row = re.sub(r'\|{2,}', '|', tmp).split(sep='|')

            if row.__len__() == 1:
                resource_type = []

            elif row.__len__() == 3:
                key = row[0]
                previous_key = key
                resource_type.append({
                    "resource": row[1].strip()[:-1],
                    "count": row[2].strip()
                })
                output[key] = resource_type

            elif row.__len__() == 2:
                key = previous_key
                resource_type.append({
                    "resource": row[0].strip()[:-1],
                    "count": row[1].strip()
                })
                output[key] = resource_type
            
            else:
                raise Exception('Algorithm breaks due to non-standard report pattern')


        # Import findings to defect-dojo
        results = []
        description = json.dumps(output)

        finding = Finding(
            title="AWS CloudTrail Digger Info",
            test=test,
            description=description,
            severity = "Info",
            static_finding = True,
            dynamic_finding = False,
            nb_occurences = 1,
        )

        results.append(finding)

        return results
