import csv
import io

from dojo.models import Finding

__author__ = 'Muhammad Farooq'


class GCPCFTParser(object):

    def get_scan_types(self):
        return ["GCP CFT Scan"]

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
                    'severity': row.get('severity', ''),
                    'location': row.get('location', ''),
                    'project': row.get('project', ''),
                    'project_id' : row.get('project_id',''),
                    'service': row.get('service', ''),
                    'title': row.get('title', '')
                    
                }
            if result['severity'].strip() == '':
                result['severity']='High'

            resource = result['resource']
            reference = "**Benchmark:** " +result['title'] + "\n" + result['description']
            # reference = result['title']
            try:
                findings = Finding(
                    test=test,
                    title = result["control_title"],
                    description = "**Project:** " + result['project'] + "\n" + \
                                "**Project ID:** " + result['project_id'] + "\n" + \
                                "**Service:** " + result['service'] + "\n" + \
                                "**Resource:** " + resource + "\n" + \
                                "**Details:** " + result['control_description']+ "\n" + \
                                "**Reason:** " + result['reason'] + "\n" + \
                                "**Status:** " + result['status'] + "\n" + \
                                "**Control Id:** " + result['control_id'],

                    severity = result['severity'],
                    references = reference
                    # cwe = result['control_id'],
                    # finding.notes.add(result['reason'])
                    # mitigation = result['status'],
                )
            

                results.append(findings)
            except:
                continue
        return results