#!/usr/bin/env python3

import boto3


cloudformation_client = boto3.client('cloudformation')

response = cloudformation_client.describe_stacks(StackName='ProwlerScannerStack')
for output in response['Stacks'][0]['Outputs']:
    print(output['OutputKey'], output['OutputValue'])
    