"""
VRT validator stack
"""
from central_helpers import MetadataHelper, write_template_to_file
from central_helpers.vrt import add_tags, StackLinker
from troposphere import Template, constants, Parameter, awslambda, Ref, Tags

template = Template()

stack_linker = StackLinker(template)

template_helper = MetadataHelper(template)
vrt_tags = add_tags(template)

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

param_role = template.add_parameter(Parameter(
    "Role",
    Default="",
    Type=constants.STRING,
    Description="Role to run as. Import from eu-west-1 stack.",
))
template_helper.add_parameter_label(param_s3_bucket_name, "Lambda S3 bucket")


validator_lambda = template.add_resource(awslambda.Function(
    "ValidatorLambda",
    Code=awslambda.Code(
        S3Bucket=Ref(param_s3_bucket_name),
        S3Key=Ref(param_s3_key),
    ),
    Runtime='nodejs8.10',
    Handler='index.handler',
    Role='',
    Tags=Tags(**vrt_tags),
))

write_template_to_file(template)
