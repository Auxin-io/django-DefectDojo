import csv
import io

from dojo.models import Finding

__author__ = 'dr3dd525'


class AWSHIPAAParser(object):

    def get_scan_types(self):
        return ["AWS HIPAA Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Benchmark for AWS Cloud Compliance - CSV Report"

    def get_findings(self, filename, test):
        if filename is None:
            return list()
        
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')

        results = []
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
                result['severity'] = 'Info'

            resource = result['resource']
            reference = "**Benchmark:** " + result['title'] + "\n" + result['description']
            try:
                findings = Finding(
                    test = test,
                    title = result["control_title"],
                    description = "**Account Id:** " + result['account_id'] + "\n" + \
                                "**Region:** " + result['region'] + "\n" + \
                                "**Service:** " + result['service'] + "\n" + \
                                "**Resource:** " + resource + "\n" + \
                                "**Details:** " + result['control_description']+ "\n" + \
                                "**Reason:** " + result['reason'] + "\n" + \
                                "**Status:** " + result['status'] + "\n" + \
                                "**Control Id:** "+ result['control_id'],

                    severity = result['severity'],
                    references = reference
                )
            
            
                results.append(findings)
            except:
                continue
       
        return results
