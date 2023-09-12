import csv
import io

from dojo.models import Finding

__author__ = 'farooq'



class AWSThriftyParser(object):

    def get_scan_types(self):
        return ["AWS Thrifty Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Benchmark Reports for AWS Thrifty - CSV Report"

    def get_findings(self, filename, test):
        
        if filename is None:
            return list()
        allowed_filenames = [
            "cloudfront.csv",
            "cloudtrail.csv",
            "cost_explorer.csv",
            "dynamodb.csv",
            "ebs.csv",
            "ec2.csv",
            "ecs.csv",
            "eks.csv",
            "elasticache.csv",
            "emr.csv",
            "lambda.csv",
            "network.csv",
            "rds.csv",
            "redshift.csv",
            "route53.csv",
            "s3.csv",
            "secretsmanager.csv",
            "cloudwatch.csv"
        ]

        if str(filename) not in allowed_filenames:
            print(filename)
            print(f"{filename} is not present in {allowed_filenames}")
            raise ValueError('File provided is not a valid AWS Thrifty CSV Report')
        
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
                    'severity': row.get('severity', 'Info').capitalize(),
                    'account_id': row.get('account_id', ''),
                    'region': row.get('region', ''),
                    'service': row.get('service', ''),
                    'group_id': row.get('group_id', ''),
                    'category': row.get('category', ''),
                    'class' : row.get('class', ''),
                    'type' : row.get('type', ''),
                    'plugin' : row.get('plugin', ''),
            }

                
            resource = result['resource']
            reference = "**Benchmark:** " + result['title'] + "\n" + result['description']
            description = ""
            if result['severity'].strip() == '':
                result['severity'] = 'High'

            elif 'account_id' in result:
                    description += "**Account Id:** " + result['account_id'] + "\n"

            elif 'region' in result:
                description += "**Region:** " + result['region'] + "\n"

            elif 'service' in result:
                description += "**Service:** " + result['service'] + "\n"

            description += "**Resource:** " + resource + "\n"

            if 'control_description' in result:
                description += "**Details:** " + result['control_description'] + "\n"

            elif 'reason' in result:
                description += "**Reason:** " + result['reason'] + "\n"

            elif 'status' in result:
                description += "**Status:** " + result['status'] + "\n"

            elif 'control_id' in result:
                description += "**Control Id:** " + result['control_id'] + "\n"

            elif 'group_id' in result:
                description += "**Group Id:** " + result['group_id'] + "\n"

            elif 'category' in result:
                description += "**Category:** " + result['category'] + "\n"

            elif 'class' in result:
                description += "**Class:** " + result['class'] + "\n"

            elif 'type' in result:
                description += "**Type:** " + result['type'] + "\n"

            elif 'plugin' in result:
                description += "**Plugin:** " + result['plugin']

            try:
                findings = Finding(
                        test=test,
                        title=result["control_title"],
                        description = description,
                        severity=result['severity'],
                        references=reference
                    )

                results.append(findings)

            except:
                continue
        
        return results
    