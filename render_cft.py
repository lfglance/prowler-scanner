#!/usr/bin/env python3

import json
import boto3


def get_stack_outputs(stack_name):
    client = boto3.client('cloudformation')
    response = client.describe_stacks(StackName=stack_name)
    outputs = response['Stacks'][0]['Outputs']
    return {output['OutputKey']: output['OutputValue'] for output in outputs}

def render_cloudformation_template(role_arn) -> dict:
    template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Description': 'Creates across-account IAM role for Prowler Scanner deployment.',
        'Outputs': {
            'RoleArn': {
                'Description': '',
                'Value': '!GetAtt CrossAccountRole.Arn'
            }
        },
        'Parameters': {
            'ExternalId': {
                'AllowedPattern': '^[a-zA-Z0-9]*$',
                'ConstraintDescription': 'ExternalId must be 5-40 characters long and consist of alphanumeric characters.',
                'Description': 'External ID used to ensure the request is coming from the intended party.',
                'MaxLength': 40,
                'MinLength': 5,
                'Type': 'String'
            }
        },
        'Resources': {
            'CrossAccountRole': {
                'Type': 'AWS::IAM::Role',
                'Properties': {
                    'RoleName': 'CrossAccountRole',
                    'MaxSessionDuration': 43200,
                    'AssumeRolePolicyDocument': {
                        'Statement': [{
                            'Action': ['sts:AssumeRole'],
                            'Condition': {
                                'StringEquals': {'sts:ExternalId': {'Ref': 'ExternalId'}}
                            },
                            'Effect': 'Allow',
                            'Principal': {'AWS': role_arn}
                        }],
                        'Version': '2012-10-17'
                    },
                    'ManagedPolicyArns': [
                        'arn:aws:iam::aws:policy/SecurityAudit',
                        'arn:aws:iam::aws:policy/job-function/ViewOnlyAccess'
                    ],
                    'Policies': [{
                        'PolicyName': 'AllowMoreReadForProwler',
                        'PolicyDocument': {
                            'Version': '2012-10-17',
                            'Statement': [{
                                'Action': [
                                    'account:Get*',
                                    'appstream:Describe*',
                                    'appstream:List*',
                                    'backup:List*',
                                    'cloudtrail:GetInsightSelectors',
                                    'codeartifact:List*',
                                    'codebuild:BatchGet*',
                                    'cognito-idp:GetUserPoolMfaConfig',
                                    'dlm:Get*',
                                    'drs:Describe*',
                                    'ds:Get*',
                                    'ds:Describe*',
                                    'ds:List*',
                                    'dynamodb:GetResourcePolicy',
                                    'ec2:GetEbsEncryptionByDefault',
                                    'ec2:GetInstanceMetadataDefaults',
                                    'ecr:Describe*',
                                    'ecr:GetRegistryScanningConfiguration',
                                    'elasticfilesystem:DescribeBackupPolicy',
                                    'glue:GetConnections',
                                    'glue:GetSecurityConfiguration*',
                                    'glue:SearchTables',
                                    'lambda:GetFunction*',
                                    'logs:FilterLogEvents',
                                    'lightsail:GetRelationalDatabases',
                                    'macie2:GetMacieSession',
                                    's3:GetAccountPublicAccessBlock',
                                    'shield:DescribeProtection',
                                    'shield:GetSubscriptionState',
                                    'securityhub:BatchImportFindings',
                                    'securityhub:GetFindings',
                                    'ssm:GetDocument',
                                    'ssm-incidents:List*',
                                    'support:Describe*',
                                    'tag:GetTagKeys',
                                    'wellarchitected:List*'
                                ],
                                'Effect': 'Allow',
                                'Resource': ['*']
                            }],
                        }
                    }],
                }
            }
        },
        'Outputs':{
            'RoleArn': {
                'Description': 'IAM role ARN which the instance will assume to run the Prowler scan.',
                'Value': {'Fn::GetAtt': ['CrossAccountRole', 'Arn']}
            },
            'ExternalId': {
                'Description': 'The External ID you have defined as additional security string.',
                'Value': {'Ref': 'ExternalId'}
            },
            'Message': {
                'Description': 'Dear Customer',
                'Value': 'Please provide these values to the Prowler Scanner administrator'
            }
        }
    }
    return template


if __name__ == '__main__':
    stack_name = 'ProwlerScannerStack'
    outputs = get_stack_outputs(stack_name)
    cft = render_cloudformation_template(outputs['CrossAccountRoleArn'])
    file_name = 'html/ProwlerScannerRemote.json'
    with open(file_name, 'w') as file:
        print(f'[+] Saved rendered template to {file_name}')
        file.write(json.dumps(cft))
