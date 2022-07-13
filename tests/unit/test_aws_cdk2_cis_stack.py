import aws_cdk as core
import aws_cdk.assertions as assertions

from aws_cdk2_cis.aws_cdk2_cis_stack import AwsCdk2CisStack

# example tests. To run these tests, uncomment this file along with the example
# resource in aws_cdk2_cis/aws_cdk2_cis_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = AwsCdk2CisStack(app, "aws-cdk2-cis")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
