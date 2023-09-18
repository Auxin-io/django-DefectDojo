import csv
import io

from dojo.models import Finding

__author__ = 'Muhammad Farooq'


class AzureNISTParser(object):

    def get_scan_types(self):
        return ["Azure NIST Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Benchmark for Azure Cloud Compliance - CSV Report"

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
                    'name': row.get('name', ''),
                    'subscription': row.get('subscription', ''),
                    'service': row.get('service', ''),
                }
            

            resource = result['resource']
            reference = "**Benchmark:** " + result['title'] + "\n" + result['description']
            try:
                findings = Finding(
                    test = test,
                    title = result["control_title"],
                    description = "**Name:** " + result['name'] + "\n" + \
                                "**Subscription:** " + result['subscription'] + "\n" + \
                                "**Service:** " + result['service'] + "\n" + \
                                "**Resource:** " + resource + "\n" + \
                                "**Details:** " + result['control_description']+ "\n" + \
                                "**Reason:** " + result['reason'] + "\n" + \
                                "**Status:** " + result['status'] + "\n" + \
                                "**Control Id:** " + result['control_id'],

                    severity = result['severity'].title(),
                    references = reference
                )
                
                
                results.append(findings)
            except:
                continue
       
        return results
