__author__ = 'jis0324'

import io
import csv
import hashlib
from dojo.models import Finding


class PMDCSVParser(object):
    def __init__(self, filename, test):
        self.dupes = dict()
        self.items = ()

        if filename is None:
            self.items = ()
            return

        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(content), delimiter=',', quotechar='"')
        csvarray = []

        for row in reader:
            csvarray.append(row)

        for row in csvarray:
            finding = Finding(test=test)
            finding.title = row["Rule"].strip()
            if row["Priority"] == "5":
                priority = "Critical"
            elif row["Priority"] == "4":
                priority = "High"
            elif row["Priority"] == "3":
                priority = "Medium"
            elif row["Priority"] == "2":
                priority = "Low"
            elif row["Priority"] == "1":
                priority = "Info"
            else:
                priority = row["Priority"]
            finding.severity = priority

            description = "Description: {}\n".format(row['Description'].strip())
            description += "Rule set: {}\n".format(row["Rule set"].strip())
            description += "Problem : {}\n".format(row["Problem"])
            finding.description = description
            finding.line = row["Line"]
            finding.file_path = row["File"]
            finding.component_name = row["Package"]
            
            if finding is not None:
                if finding.title is None:
                    finding.title = ""
                if finding.description is None:
                    finding.description = ""

                key = hashlib.md5((finding.title + '|' + finding.description).encode("utf-8")).hexdigest()

                if key not in self.dupes:
                    self.dupes[key] = finding

        self.items = list(self.dupes.values())
