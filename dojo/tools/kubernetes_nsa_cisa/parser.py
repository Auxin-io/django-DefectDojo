import csv
import io

from dojo.models import Finding

__author__ = 'Muhammad Farooq'


class KubernetesNSACISAParser(object):

    def get_scan_types(self):
        return ["Kubernetes NSA CISA Scan"]

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
                    'context_name': row.get('context_name', ''),
                    'daemonset_name': row.get('daemonset_name', ''),
                    'deployment_name': row.get('deployment_name', ''),
                    'pod_name': row.get('pod_name', ''),
                    'replicaset_name': row.get('replicaset_name', ''),                        
                    'namespace': row.get('namespace', ''),
                    'service': row.get('service', ''),
                    
                }
            if result['severity'].strip() == '':
                result['severity'] = 'High'
            resource = result['resource']
            reference = "**Benchmark:** " + result['title'] + "\n" + result['description']
            try:
                findings = Finding(
                    test=test,
                    title = result["control_title"],
                    description = "**Context Name:** " + result['context_name'] + "\n" + \
                                "**Daemonset Name:** " + result['daemonset_name'] + "\n" + \
                                "**Deployment Name:** " + result['deployment_name'] + "\n" + \
                                "**Pod Name:** " + result['pod_name'] + "\n" + \
                                "**Replicaset Name:** " + result['replicaset_name'] + "\n" + \
                                "**Name Space:** " + result['namespace'] + "\n" + \
                                "**Service:** " + result['service'] + "\n" + \
                                "**Resource:** " + resource + "\n" + \
                                "**Details:** " + result['control_description']+ "\n" + \
                                "**Reason:** " + result['reason'] + "\n" + \
                                "**Status:** " + result['status'] + "\n" + \
                                "**Control Id:** " + result['control_id'],

                    severity = result['severity'].title(),
                    references = reference
                    # cwe = result['control_id'],
                    # finding.notes.add(result['reason'])
                    # mitigation = result['status'],
                )
                results.append(findings)

            except:
                continue
           
        return results