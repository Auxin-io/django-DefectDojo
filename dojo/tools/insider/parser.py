import json
import dateutil.parser

from dojo.models import Finding


class InsiderParser(object):
    def get_scan_types(self):
        return ["Insider Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Insider Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Scan Java (Maven and Android), Kotlin (Android), Swift (iOS), .NET Full Framework, C#, and Javascript (Node.js) - JSON Report"

    def get_findings(self, filename, test):
        results = list()
        report = json.load(filename)

        vulnerabilities = report['vulnerabilities']
        for row in vulnerabilities:
            vuln_class = row.get('class', '')
            vuln_class_message = row.get('classMessage', None)
            vuln_column = row.get('column', '')
            vuln_cvss = row.get('cvss', '')
            vuln_cwe = row.get('cwe', '')
            vuln_description = row.get('description', '')
            vuln_line = row.get('line', None)
            vuln_method = row.get('method', '')
            vuln_recommendation = row.get('recomendation', None)
            vuln_id = row.get('vul_id', None)

            description = ''
            if vuln_class_message:
                description += "**Source Path:** " + vuln_class_message + "\n"

            if vuln_method:
                description += "**Problem:** " + vuln_method + "\n"
            
            if vuln_recommendation:
                description += "**Recommendation:** " + vuln_recommendation

            severity = self.convert_cvss(vuln_cvss)
            file_path = vuln_class_message
            cwe = int(vuln_cwe.split('-')[1])

            finding = Finding(
                title = vuln_description,
                test = test,
                description = description,
                severity = severity,
                file_path = file_path,
                line = vuln_line,
                cwe = cwe,
                vuln_id_from_tool = vuln_id,
                mitigation = vuln_recommendation
            )
            results.append(finding)

        return results

    def convert_cvss(self, vuln_cvss: int):
        if vuln_cvss <= 3:
            return 'Low'
        elif vuln_cvss <= 6:
            return 'Medium'
        elif vuln_cvss <= 8:
            return 'High'
        else:
            return 'Critical'
