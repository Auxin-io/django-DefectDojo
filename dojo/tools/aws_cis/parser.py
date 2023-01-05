import csv
import io

from dojo.models import Finding

__author__ = 'Muhammad Farooq'


class AWSCISParser(object):

    def get_scan_types(self):
        return ["AWS CIS Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "CSV Report"

    def get_findings(self, filename, test):
        results = []
        if filename is None:
            return list()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        for row in reader:
            result = {
                    'title': row.get('title', ''),
                    'description': row.get('description', ''),
                    'control_id': row.get('control_id', ''),
                    'control_title': row.get('control_title', ''),
                    'control_description': row.get('control_description', ''),
                    'reason': row.get('reason', ''),
                    'resource': row.get('resource', ''),
                    'status': row.get('status', ''),
                    'severity': row.get('severity', 'Info'),
                    'account_id': row.get('account_id', ''),
                    'region': row.get('region', ''),
                    'service': row.get('service', ''),
                    
                }
            if result['severity'].strip() == '':
                result['severity']='Info'
            account_id = result['account_id']
            region = result['region']
            service = result['service']
            resource = result['resource']
            reason = result['reason']

            results.append(Finding(
            test=test,
            title = result["title"] + "\n" +result['control_title'],
            description = "**Account Id** :" + account_id + "\n\n" + \
                                  "**Region** :" + region + "\n\n" + \
                                  "**Service** :" + service + "\n\n" + \
                                  "**Resource** :" + resource + "\n\n" + \
                                  "**Details** :" + result['description']+ "\n\n" + result['control_description']+ "\n\n"\
                                  "**Reason** :" + reason + "\n\n"\
                                  "**ControlId** :"+ result['control_id'],

            # cwe = result['control_id'],
            # finding.notes.add(result['reason'])
            mitigation =result['status'],
            severity = result['severity']
            ))
           
       
        return results
