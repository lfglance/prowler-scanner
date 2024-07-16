import aws_cdk as core
import aws_cdk.assertions as assertions

from prowler_scan_automation.prowler_scan_automation_stack import ProwlerScanAutomationStack

# example tests. To run these tests, uncomment this file along with the example
# resource in prowler_scan_automation/prowler_scan_automation_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = ProwlerScanAutomationStack(app, "prowler-scan-automation")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
