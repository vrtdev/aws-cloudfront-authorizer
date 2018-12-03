"""Authorizer Dummy stack."""
from troposphere import Template, Sub, GetAtt

import cfnutils.output
import custom_resources.cloudformation
import custom_resources.ssm

template = Template(Description="Authorizer dummy stack for prod")

custom_resources.use_custom_resources_stack_name_parameter(
    template=template,
)

cloudformation_tags = template.add_resource(custom_resources.cloudformation.Tags("CfnTags"))

lae_arn = template.add_resource(custom_resources.ssm.Parameter(
    "LaeArn",
    Name=Sub('/${AWS::StackName}/lae-arn'),
    Type="String",
    Value="arn:aws::1234567890:role/dummy",
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))

cfnutils.output.write_template_to_file(template)
