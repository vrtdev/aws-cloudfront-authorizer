"""
VRT validator stack
"""
from central_helpers import MetadataHelper, write_template_to_file
from central_helpers.vrt import add_tags, StackLinker
from troposphere import Template, constants, Parameter, awslambda, Ref, Tags, Output

template = Template()

stack_linker = StackLinker(template)

template_helper = MetadataHelper(template)
vrt_tags = add_tags(template)

param_role = template.add_parameter(Parameter(
    "Role",
    Default="arn:aws:iam::000000000000:role/xxx",
    Type=constants.STRING,
    Description="ARN of role to run as",
))
template_helper.add_parameter_label(param_role, "Lambda role ARN")

param_s3_bucket_name = template.add_parameter(Parameter(
    "S3BucketName",
    Default="",
    Type=constants.STRING,
    Description="Location of the Lambda ZIP file, bucket name",
))
template_helper.add_parameter_label(param_s3_bucket_name, "Lambda S3 bucket")

param_s3_key = template.add_parameter(Parameter(
    "S3Key",
    Default="",
    Type=constants.STRING,
    Description="Location of the Lambda ZIP file, path",
))
template_helper.add_parameter_label(param_s3_key, "Lambda S3 key")


validator_lambda = template.add_resource(awslambda.Function(
    "ValidatorLambda",
    Code=awslambda.Code(
        S3Bucket=Ref(param_s3_bucket_name),
        S3Key=Ref(param_s3_key),
    ),
    Runtime='nodejs8.10',
    Handler='index.handler',
    Role=Ref(param_role),
    Tags=Tags(**vrt_tags),
))

validator_version = template.add_resource(awslambda.Version(
    # Force a new resource name when the code changes
    "ValidatorVersion",  # TODO: force new version of code changes
    FunctionName=Ref(validator_lambda),
))

template.add_output(Output(
    "ValidatorLambdaFunctionARN",
    Value=Ref(validator_version),
))

write_template_to_file(template)
