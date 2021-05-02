import io
import csv
import hashlib
from dojo.models import Finding


class TfsecParser(object):

    def get_scan_types(self):
        return ["Tfsec Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "CSV Report"

    def get_findings(self, filename, test):
        dupes = dict()

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        # Go through all the findings
        for row in csvarray:
            finding = Finding(test=test)
            finding.title = row["rule_id"]
            
            if row["severity"] == "ERROR":
                priority = "High"
            elif row["severity"] == "WARNING":
                priority = "Low"
            else:
                priority = row["severity"]
            
            # Set the priority
            finding.severity = priority

            description = "Description: {}\n".format(row['description'].strip())
            description += "Rule: {}\n".format(row["rule_id"].strip())
            finding.description = description
            finding.line = row["start_line"]
            # finding.line = row["start_line"] + "~" + row["end_line"]
            finding.file_path = row["file"]

            if "for more information" in row["link"]:
                try:
                    finding.url = row["link"].rsplit("for more information", 1)[0].strip().split(" ")[1].strip()
                except:
                    finding.url = row["link"].rsplit("for more information", 1)[0].strip()

            key = hashlib.sha256((finding.title + '|' + finding.line + "|" + row["rule_id"]).encode("utf-8")).hexdigest()

            if key not in dupes:
                dupes[key] = finding

        return list(dupes.values())
