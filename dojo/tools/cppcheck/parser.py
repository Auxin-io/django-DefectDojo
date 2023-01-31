import re

from defusedxml import ElementTree
from dojo.models import Finding

__author__ = 'dr3dd532'


class CppCheckParser(object):
    """Parser for CppCheck reports"""

    def get_scan_types(self):
        return ["CppCheck Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CppCheck Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Scanner for C/C++ code vulnerabilities - XML Report"

    def get_findings(self, filename, test):

        report = ElementTree.parse(filename)
        root = report.getroot()

        results = list()
        errors = root.find('errors')

        for error in errors.findall('error'):
            resource = error.get('id')
            vuln_severity = error.get('severity', 'Info')
            vuln_title = error.get('msg')
            vuln_description = error.get('verbose')
            cwe = error.get('cwe', None)

            severity = self.convert_severity(vuln_severity)
            
            description = ''
            if resource:
                description += "**Category: **" + self.format_title(resource)

            if vuln_description:
                description += "\n" + "**Details: **" + vuln_description

            source = error.find('location', None)
            vuln_file_path = None
            vuln_line = None
            if source is not None:
                file_path = source.get('file')
                file_path0 = source.get('file0')
                vuln_line = source.get('line')
                vuln_column = source.get('column')
                info = source.get('info')

                vuln_file_path = ''
                if file_path0:
                    vuln_file_path += file_path0

                if file_path:
                    vuln_file_path += "\n" + file_path

                source_path = ''
                if vuln_line:
                    source_path += "Line: " + vuln_line

                if vuln_column:
                    source_path += ", " + "Column: " + vuln_column

                description += "\n" + "**Source Path: **" + source_path
            
            finding = Finding(
                title = vuln_title,
                test = test,
                description = description,
                severity = severity,
                file_path = vuln_file_path,
                line = vuln_line,
                cwe = cwe,
                active=True,
                dynamic_finding=False,
                static_finding=True,
                false_p=False,
                out_of_scope=False,
                nb_occurences=1
            )

            results.append(finding)

        return results


    @staticmethod
    def convert_severity(value):
        if value == "error":
            return "Critical"
        elif value == "warning":
            return "High"
        elif value == "style":
            return "Medium"
        elif value == "performance":
            return "Low"
        elif value == "portability" or value == "information":
            return "Info"
        else:
            return "Info"

    @staticmethod
    def format_title(title):
        return re.sub(r'(?<!^)(?=[A-Z])', ' ', title).title()


