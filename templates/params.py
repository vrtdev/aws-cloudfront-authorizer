"""
Authorizer parameter stack.

This stack gathers the information needed to use the Authorizer in one place.
"""
from troposphere import Template, Parameter, Ref, Sub, Output, Export, Join, AWS_STACK_NAME, constants, \
    GetAtt
import custom_resources.ssm
import custom_resources.cloudformation
import cfnutils.output


template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

param_authorizer_stack = template.add_parameter(Parameter(
    "ParamAuthorizerStack",
    Default="authorizer",
    Type=constants.STRING,
))
template.set_parameter_label(param_authorizer_stack, "Authorizer StackName")

param_laearn = template.add_parameter(Parameter(
    "ParamLaeArn",
    Type=constants.STRING,
    Description="ARN of the Lambda@Edge function",
))
template.set_parameter_label(param_laearn, "Lambda@Edge ARN")

cloudformation_tags = template.add_resource(custom_resources.cloudformation.Tags("CfnTags"))


# Don't simply import-output the Lambda@Edge ARN, but do it via a Parameter
# This allows us to migrate to a new L@E function gradually (otherwise, the output value would be locked and can't
# change)
lae_arn = template.add_resource(custom_resources.ssm.Parameter(
    "LaeArn",
    Name=Sub('/${AWS::StackName}/lae-arn'),
    Type="String",
    Value=Ref(param_laearn),
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))
template.add_output(Output(
    "LaeArnParameter",
    Description='SSM Parameter containing the Lambda@Edge ARN',
    Value=Ref(lae_arn),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'lae-arn'])),
))


cfnutils.output.write_template_to_file(template)
