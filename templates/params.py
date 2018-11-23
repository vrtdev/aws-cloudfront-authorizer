"""
Authorizer parameter stack.
"""
from central_helpers import write_template_to_file
from central_helpers.vrt import add_tags, StackLinker
from troposphere import Template, Parameter, Ref, Sub, Tags, Output, Export, Join, AWS_STACK_NAME, constants, \
    ImportValue
import custom_resources.ssm

template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

stack_linker = StackLinker(template)

vrt_tags = add_tags(template)

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


template.add_output(Output(
    "ApiDomain",
    Description='Domain name of the API',
    Value=ImportValue(Sub('${' + param_authorizer_stack.title + '}-domain-name')),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'domain-name'])),
))

template.add_output(Output(
    "MagicPath",
    Description='Magic path',
    Value=ImportValue(Sub('${' + param_authorizer_stack.title + '}-magic-path')),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'magic-path'])),
))


# Don't simply import-output the Lambda@Edge ARN, but do it via a Parameter
# This allows us to migrate to a new L@E function gradually (otherwise, the output value would be locked and can't
# change)
lae_arn = template.add_resource(custom_resources.ssm.Parameter(
    "LaeArn",
    Name=Sub('/${AWS::StackName}/lae-arn'),
    Type="String",
    Value=Ref(param_laearn),
    Tags=Tags(**vrt_tags),
))
template.add_output(Output(
    "LaeArnParameter",
    Description='SSM Parameter containing the Lambda@Edge ARN',
    Value=Ref(lae_arn),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'lae-arn'])),
))


write_template_to_file(template)
