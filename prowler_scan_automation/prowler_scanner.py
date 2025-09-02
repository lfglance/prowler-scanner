import aws_cdk as core
from constructs import Construct
from aws_cdk import (
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_lambda as _lambda,
    aws_iam as iam,
    aws_s3 as s3,
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_logs
)

import config

class ProwlerScanner(core.Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create the foundation (VPC, S3, Logs, Roles)
        vpc = ec2.Vpc(self, "Vpc", max_azs=1)
        subnets = [subnet.subnet_id for subnet in vpc.private_subnets]
        subnet_id = subnets[0]

        bucket = s3.Bucket(
            self, "ProwlerResultsBucket",
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=True,
                block_public_policy=False,
                ignore_public_acls=True,
                restrict_public_buckets=False
            ),
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=core.RemovalPolicy.DESTROY,
            auto_delete_objects=True
        )

        bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[bucket.arn_for_objects("*")],
                principals=[iam.ArnPrincipal("*")]
            )
        )

        bucket.add_lifecycle_rule(
            id="ExpireNonCurrentVersions",
            noncurrent_version_expiration=core.Duration.days(120),
            enabled=True
        )

        security_group = ec2.SecurityGroup(self, "ProwlerSecurityGroup",
            vpc=vpc,
            description="Security group for EC2 instances (all egress).",
            allow_all_outbound=True
        )

        # Create roles and policies for the EC2 instance
        ec2_role = iam.Role(self, "Ec2InstanceRole",
            assumed_by=iam.ServicePrincipal("ec2.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ReadOnlyAccess"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore")
            ],
            inline_policies={
                "AssumeRoles": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["sts:AssumeRole"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"]  # Wildcard to allow any role in any account
                        )
                    ]
                ),
                "TerminateSelf": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["ec2:TerminateInstances"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    "ec2:ResourceTag/Role": "ProwlerScanner"
                                }
                            }
                        )
                    ]
                ),
                "ManageBucket": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["s3:*"],
                            effect=iam.Effect.ALLOW,
                            resources=[bucket.arn_for_objects("*"), bucket.bucket_arn]
                        )
                    ]
                )
            }
        )

        instance_profile = iam.CfnInstanceProfile(self, "InstanceProfile",
            roles=[ec2_role.role_name]
        )

        bucket.grant_write(ec2_role)

        ### Setup Lambda function to receive requests

        lambda_env = {
            "BUCKET_NAME": bucket.bucket_name,
            "SUBNET_ID": subnet_id,
            "SECURITY_GROUP_ID": security_group.security_group_id,
            "INSTANCE_PROFILE": instance_profile.attr_arn,
            "PROWLER_VERSION": config.prowler_version,
            "INSTANCE_TYPE": config.instance_type,
            "TEAM_NAME": config.team_name,
            "WEBHOOK_URL": config.webhook_url
        }

        lambda_role = iam.Role(
            self, "LambdaExecutionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaBasicExecutionRole"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2FullAccess")
            ],
            inline_policies={
                'AllowPassRole': iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["iam:PassRole"],
                            effect=iam.Effect.ALLOW,
                            resources=[ec2_role.role_arn]
                        )
                    ]
                )
            }
        )

        run_instance_function = _lambda.Function(
            self, "RunScan",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="worker.run_scan",
            code=_lambda.Code.from_asset("functions"),
            role=lambda_role,
            timeout=core.Duration.seconds(5),
            environment=lambda_env
        )

        aws_logs.LogGroup(
            self, 'RunScanLogGroup',
            log_group_name=f"/aws/lambda/{run_instance_function.function_name}",
            retention=aws_logs.RetentionDays.ONE_WEEK
        )

        ### Setup API Gateway to expose HTTP endpoint for requests

        api = apigateway.RestApi(self, "ProwlerApi",
            rest_api_name="Prowler Automation Service",
            description="This API triggers a Lambda which launches an EC2 instance running Prowler to scan remote accounts."
        )

        lambda_integration = apigateway.LambdaIntegration(run_instance_function)

        api.root.add_method("GET", lambda_integration)   # GET /

        ### Outputs

        core.CfnOutput(self, "CrossAccountRoleArn",
            value=ec2_role.role_arn,
            export_name="CrossAccountRoleArn",
            description="The IAM Role for the EC2 instance to assume to be able to assume roles to other accounts and put objects in S3."
        )

        core.CfnOutput(self, "BucketName",
            value=bucket.bucket_name,
            export_name="BucketName",
            description="The name of the bucket where resulting React sites are stored."
        )

        core.CfnOutput(self, "Endpoint",
            value=api.url,
            export_name="Endpoint",
            description="The API Gateway endpoint."
        )
