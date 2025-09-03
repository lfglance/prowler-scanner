#!/usr/bin/env python3

from pprint import pprint

import boto3
import requests


scan_name = input('scan_name? ')
role_arn = input('role_arn? ')
external_id = input('external_id? ')


cloudformation_client = boto3.client('cloudformation')

response = cloudformation_client.describe_stacks(StackName='ProwlerScannerStack')
for output in response['Stacks'][0]['Outputs']:
    if output['OutputKey'] == 'Endpoint':
        endpoint = output['OutputValue']
        req = requests.get(endpoint, params={
            'external_id': external_id,
            'role_arn': role_arn,
            'scan_name': scan_name
        })
        req.raise_for_status()
        pprint(req.json())
