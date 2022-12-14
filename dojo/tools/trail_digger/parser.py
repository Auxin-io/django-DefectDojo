
import logging
import os

from dojo.models import Finding
logger = logging.getLogger(__name__)


class TrailDiggerParser(object):
    """Parser for trail digger text files."""
    
    def get_scan_types(self):
        return ["Trail Digger"]

    def get_label_for_scan_types(self, scan_type):
        return "Trail Digger"

    def get_description_for_scan_types(self, scan_type):
        return "text report format"

    def get_findings(self, filename, test):

        counter = 0
        dictionary= {"Event Type": {},"Event Source":{},"Region":{}, "Recipient Account ID":{}}
        # file = open(filename,'rb')
        file=filename.readlines()[2:]
        for f in file:
            a=f.decode()
            b=' '.join(a.split())
            c=b.split(":")
            print(c)
            if c == [''] :
                counter +=1
                continue
            if counter == 0:
                dictionary["Event Type"][c[0]]=c[1]
            elif counter ==1 :   
                dictionary["Event Source"][c[0]]=c[1]
            elif counter ==2 :
                dictionary["Region"][c[0]]=c[1]
            elif counter ==3 :
                dictionary["Recipient Account ID"][c[0]]=c[1]
            logger.debug(dictionary)
            results = list()
        # file = filename.readlines()
        # logger.debug(file)
        # warnings = file.split('\n\n')
        # logger.debug(warnings)
        # # next(file)
        # # logger.debug(file)
        # a=[line.strip() for line in file if line.strip()]
        # for line in a :
        #     b=' '.join(line.split())
        #     c=b.split(":")
                
            findingdetail = "\n".join(
                [
                   str(dictionary["Event Type"]),
                   str(dictionary["Event Source"]),
                   str(dictionary["Recipient Account ID"]),
                   str(dictionary["Region"])
                ]
            )

            finding = Finding(
                title="Log data info",
                test=test,
                # tags = account_id,
                description=findingdetail,
                # references = str(item["_source"]["event"]["original"]),
                # severity=item["issue_severity"].title(),
                severity="Info",
                # file_path=item["_source"]["log"]["file"]["path"],
                # line=item["line_number"],
                # date=find_date,
                static_finding=True,
                dynamic_finding=False,
                # vuln_id_from_tool=":".join([item["test_name"], item["test_id"]]),
                nb_occurences=1,
            )
            # manage confidence
            # confidence = self.convert_confidence(item.get("issue_confidence"))
            # if confidence:
            #     finding.scanner_confidence = confidence
            # if "more_info" in item:
            #     finding.references = item["more_info"]

            results.append(finding)

        return results

    # def convert_confidence(self, value):
    #     if "high" == value.lower():
    #         return 2
    #     elif "medium" == value.lower():
    #         return 3
    #     elif "low" == value.lower():
    #         return 6
    #     else:
    #         return None

