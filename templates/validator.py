"""
Validator stack.
"""
from troposphere import Template, constants, Parameter, awslambda, Ref, Output, GetAtt

import custom_resources.awslambda
import custom_resources.cloudformation
import cfnutils.output


template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

param_role = template.add_parameter(Parameter(
    "Role",
    Default="arn:aws:iam::000000000000:role/xxx",
    Type=constants.STRING,
    Description="ARN of role to run as",
))
template.set_parameter_label(param_role, "Lambda role ARN")

param_s3_bucket_name = template.add_parameter(Parameter(
    "S3BucketName",
    Default="",
    Type=constants.STRING,
    Description="Location of the Lambda ZIP file, bucket name",
))
template.set_parameter_label(param_s3_bucket_name, "Lambda S3 bucket")

param_s3_key = template.add_parameter(Parameter(
    "S3Key",
    Default="",
    Type=constants.STRING,
    Description="Location of the Lambda ZIP file, path",
))
template.set_parameter_label(param_s3_key, "Lambda S3 key")

param_config_bucket = template.add_parameter(Parameter(
    "ConfigBucket",
    Default="",
    Type=constants.STRING,
    Description="Name of the configuration bucket",
))
template.set_parameter_label(param_config_bucket, "Lambda Config S3 bucket")

cloudformation_tags = template.add_resource(custom_resources.cloudformation.Tags(
    "CfnTags",
    Set={
        'ConfigBucket': Ref(param_config_bucket),
    },
))

validator_lambda = template.add_resource(awslambda.Function(
    "ValidatorLambda",
    Code=awslambda.Code(
        S3Bucket=Ref(param_s3_bucket_name),
        S3Key=Ref(param_s3_key),
    ),
    Runtime='nodejs14.x',
    Handler='index.handler',
    Role=Ref(param_role),
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))

validator_version = template.add_resource(custom_resources.awslambda.Version(
    "ValidatorVersion",
    FunctionName=Ref(validator_lambda),
    Dummy=Ref(param_s3_key),  # Trigger update on function update
))

template.add_output(Output(
    "ValidatorLambdaFunctionARN",
    Value=Ref(validator_version),
))

cfnutils.output.write_template_to_file(template)
