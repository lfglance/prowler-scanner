import json
from os import environ
from datetime import datetime

import boto3


aws_region = environ.get('AWS_REGION')
subnet_id = environ.get('SUBNET_ID')
bucket_name = environ.get('BUCKET_NAME')
instance_profile = environ.get('INSTANCE_PROFILE')
security_group_id = environ.get('SECURITY_GROUP_ID')
prowler_version = environ.get('PROWLER_VERSION', '4.2.4')
instance_type = environ.get('INSTANCE_TYPE', 't2.medium')
team_name = environ.get('TEAM_NAME', 'Mission')
webhook_url = environ.get('WEBHOOK_URL', '')

ec2_client = boto3.client('ec2')
s3_client = boto3.client('s3')


def run_scan(event, context):
    now = datetime.utcnow()
    ts = str(int(now.timestamp()))

    # Extract URL parameters and ensure accuracy
    params = event.get('queryStringParameters', {})
    print(f'Received new request: {params}')
    if not params:
        msg = 'Invalid url parameters provided. Needs `role_arn`, `external_id`, and `scan_name` present, i.e. https://apigw.com/?role_arn=arn:aws:xxxxxx&scan_name=yyyy&external_id=zzzzz&compliance=aws'
        print(msg)
        return {
            'statusCode': 400,
            'body': json.dumps({"error": msg})
        }
    
    role_arn = params.get('role_arn')
    scan_name = params.get('scan_name')
    external_id = params.get('external_id')

    # Confirm required parameters are provided
    if not role_arn and not scan_name and not external_id:
        msg = 'Invalid url parameters provided. Needs `role_arn`, `external_id`, and `scan_name` present, i.e. https://apigw.com/?role_arn=arn:aws:xxxxxx&scan_name=yyyy&external_id=zzzzz&compliance=aws'
        print(msg)
        return {
            'statusCode': 400,
            'body': json.dumps({'error': msg})
        }

    # Fan out tasks to all regions
    object_key = f'{scan_name}-{ts}'
    user_data = rf"""#!/bin/bash
set -xe

# get ec2 metadata token
export TOKEN=$(curl -s -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" http://169.254.169.254/latest/api/token)
export INSTANCE_ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" -i http://169.254.169.254/latest/meta-data/instance-id)

# setup shutdown script
echo /opt/venv/bin/aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region {aws_region} > /opt/shutdown.sh

# install prowler and dependencies
apt update
apt install -y python3-venv
python3 -m venv /opt/venv
source /opt/venv/bin/activate
pip install awscli
aws sts get-caller-identity
git clone https://github.com/prowler-cloud/prowler /opt/prowler
cd /opt/prowler
git checkout {prowler_version}
sed -i "s/azure.*//" pyproject.toml
sed -i "s/microsoft.*//" pyproject.toml
sed -i "s/google.*//" pyproject.toml
sed -i "s/shodan.*//" pyproject.toml
pip install .

# run prowler and collect output to /opt/results.csv
python3 prowler.py aws \
    --role {role_arn} \
    --role-session-name {team_name}-ProwlerScanner \
    --external-id {external_id} \
    --session-duration 43200 \
    --output-filename {object_key} \
    --log-level INFO \
    --log-file /opt/scan.log \
    --severity critical high medium \
    --ignore-exit-code-3
cp output/{object_key}.csv /opt/results.csv

# install nodejs (v18 LTS)
cd /opt
wget -qO node.tar.gz https://nodejs.org/dist/v18.20.4/node-v18.20.4-linux-x64.tar.xz
mkdir -p nodejs
tar xf node.tar.gz -C nodejs --strip-components=1
cp -r nodejs/* /usr/

# install prowler-ui visualizer and build site
git clone https://github.com/lfglance/prowler-ui
cd prowler-ui
npm install
mkdir -p src/data
python3 compile_prowler_data.py /opt/results.csv
npm run build

# move site files to S3
mv build {object_key}
tar czf {object_key}.tar.gz {object_key} 
aws s3 cp {object_key}.tar.gz s3://{bucket_name}/
cd /opt
aws s3 presign s3://{bucket_name}/{object_key}.tar.gz > url.txt


# notify Zapier webhook if present
if [[ "{webhook_url}" ]];
then
    echo "{{\"scan_name\": \"{scan_name}\", \"url\": \"$(cat url.txt)\"}}" > payload.json
    curl "{webhook_url}" -X POST -d "@payload.json"
fi

# shutdown after 30 minutes (if needed to debug)
sleep 1800 && bash /opt/shutdown.sh
"""

    try:
        response = ec2_client.run_instances(
            ImageId=get_ubuntu_ami(),
            InstanceType=instance_type,
            SubnetId=subnet_id,
            SecurityGroupIds=[security_group_id],
            MaxCount=1,
            MinCount=1,
            IamInstanceProfile={
                'Arn': instance_profile
            },
            UserData=user_data,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'prowler-scanner-{scan_name}'},
                        {'Key': 'Role', 'Value': 'ProwlerScanner'},
                        {'Key': 'Environment', 'Value': 'Production'},
                        {'Key': 'LaunchTimestamp', 'Value': ts}
                    ]
                }
            ]
        )
        data = response['Instances'][0]
        res_data = {
            'message': f'Launched EC2 instance to run Prowler scan ({scan_name})',
            'instance_profile': instance_profile,
            'prowler_version': prowler_version,
            'sg_id': security_group_id,
            'instance_id': data['InstanceId'],
            'instance_type': data['InstanceType'],
            'subnet_id': data['SubnetId'],
            'vpc_id': data['VpcId'],
            'ip_address': data['PrivateIpAddress'],
            'connection': f'aws ssm start-session --target {data["InstanceId"]}',
            'output_bucket': bucket_name,
            'output_object': f'{object_key}.tar.gz'
        }
        print(res_data)
        return {
            'statusCode': 200,
            'body': json.dumps(res_data)
        }
    except Exception as e:
        print(str(e))
        return {
            'statusCode': 500,
            'body': json.dumps({'message': str(e)})
        }

def get_ubuntu_ami() -> str:
    filters = [
        {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*']},
        {'Name': 'state', 'Values': ['available']}
    ]

    # Describe images with the filters
    response = ec2_client.describe_images(Filters=filters)

    # Sort images by creation date to get the latest one
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    if not images:
        raise Exception("No AMIs found")

    # Select the latest Ubuntu 22.04 AMI
    ami_id = images[0]['ImageId']

    return ami_id
