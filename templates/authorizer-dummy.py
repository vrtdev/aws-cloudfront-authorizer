"""Authorizer Dummy stack."""
from troposphere import Template, Sub, Tags

from central_helpers import write_template_to_file
from central_helpers.vrt import add_tags
import custom_resources.ssm

template = Template(Description="Authorizer dummy stack for prod")
vrt_tags = add_tags(template)

custom_resources.use_custom_resources_stack_name_parameter(
    template=template,
    parameter_kwargs_dict={'Default': 'vrt-dpc-custom-resources-2'},
)

lae_arn = template.add_resource(custom_resources.ssm.Parameter(
    "LaeArn",
    Name=Sub('/${AWS::StackName}/lae-arn'),
    Type="String",
    Value="arn:aws::1234567890:role/dummy",
    Tags=Tags(**vrt_tags),
))

write_template_to_file(template)
