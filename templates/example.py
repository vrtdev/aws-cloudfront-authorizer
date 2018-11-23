from central_helpers import write_template_to_file
from troposphere import Template, cloudfront, constants, ImportValue, Sub, Join, Parameter, Ref, Output, GetAtt, \
    Equals, AWS_NO_VALUE, If, route53, FindInMap, AWS_REGION
import custom_resources.acm
import custom_resources.cloudformation
import cfnutils.mappings

template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

authorizer_stack = template.add_parameter(Parameter(
    "AuthorizerStack",
    Type=constants.STRING,
    Default="authorizer",
    Description="Authorizer stack to import from",
))
template.set_parameter_label(authorizer_stack, "Authorizer stack")

param_authorizer_lae_arn = template.add_parameter(Parameter(
    "AuthorizerLaeParam",
    Type="AWS::SSM::Parameter::Value<String>",
    Default='/authorizer/lae-arn',
    Description="Parameter name to get Lambda@Edge ARN from",
))
template.set_parameter_label("Authorizer Lambda@Edge parameter")

param_label = template.add_parameter(Parameter(
    "Label",
    Default="example.authorizer",
    Type=constants.STRING,
    Description="Label inside the Hosted Zone to create. e.g. 'authorizer' for 'authorizer.example.org'",
))
template.set_parameter_label(param_label, "Label")

param_hosted_zone_name = template.add_parameter(Parameter(
    "HostedZone",
    Default="example.org",
    Type=constants.STRING,
    Description="Name of the Hosted DNS zone (without trailing dot). e.g. 'example.org' for 'authorizer.example.org'",
))
template.set_parameter_label(param_hosted_zone_name, "Hosted Zone Name")

param_use_cert = template.add_parameter(Parameter(
    "UseCert",
    Type=constants.STRING,
    AllowedValues=['yes', 'no'],
    Default='no',  # Default to no, so new stacks request, but don't use certs
    # This avoids stacks failing since the cert is not approved yet
    Description="Use TLS certificate"
))
template.set_parameter_label(param_use_cert, "Use TLS certificate")

cloudformation_tags = template.add_resource(custom_resources.cloudformation.Tags("CfnTags"))

acm_cert = template.add_resource(custom_resources.acm.DnsValidatedCertificate(
    "AcmCert",
    Region='us-east-1',  # Api gateway is in us-east-1
    DomainName=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))
template.add_output(Output(
    "AcmCertDnsRecords",
    Value=GetAtt(acm_cert, "DnsRecords"),
))

use_cert_cond = 'UseCert'
template.add_condition(use_cert_cond, Equals(Ref(param_use_cert), 'yes'))

example_distribution = template.add_resource(cloudfront.Distribution(
    "ExampleDistribution",
    DistributionConfig=cloudfront.DistributionConfig(
        Comment="Example distribution for restricted access",
        Aliases=[Join('.', [Ref(param_label), Ref(param_hosted_zone_name)])],
        Enabled=True,
        IPV6Enabled=True,
        HttpVersion='http2',
        PriceClass='PriceClass_100',
        Origins=[
            cloudfront.Origin(
                # Your usual config goes here
                Id="RealOrigin",
                DomainName="ifconfig.io",
                CustomOriginConfig=cloudfront.CustomOrigin(
                    HTTPPort=80,
                    HTTPSPort=443,
                    OriginProtocolPolicy='https-only',
                    OriginSSLProtocols=['TLSv1.2', 'TLSv1.1', 'TLSv1']
                ),
            ),
            cloudfront.Origin(
                # You need to add this origin
                Id="Authorizer",
                DomainName=ImportValue(Sub('${' + authorizer_stack.title + '}-domain-name')),
                CustomOriginConfig=cloudfront.CustomOrigin(
                    HTTPPort=80,
                    HTTPSPort=443,
                    OriginProtocolPolicy='https-only',
                    OriginSSLProtocols=['TLSv1.2', 'TLSv1.1', 'TLSv1']
                ),
            ),
        ],
        CacheBehaviors=[
            cloudfront.CacheBehavior(
                # The authorizer hijacks a set of URL-paths from your website. All paths are prefixed
                # with `/auth-<UUID>/`, so they are very unlikely to collide with your content.
                # Insert this as the first Behaviour.
                PathPattern=Join('', [
                    ImportValue(Sub('${' + authorizer_stack.title + '}-magic-path')),
                    '/*',
                ]),
                ViewerProtocolPolicy='https-only',
                TargetOriginId='Authorizer',
                ForwardedValues=cloudfront.ForwardedValues(
                    QueryString=True,
                    Cookies=cloudfront.Cookies(
                        Forward='all',  # Needed to allow Set-Cookie:-headers
                    ),
                ),
                MinTTL=0,
                DefaultTTL=0,
                MaxTTL=0,
            )
        ],
        DefaultCacheBehavior=cloudfront.DefaultCacheBehavior(
            ViewerProtocolPolicy='redirect-to-https',  # HTTPS required. Cookies need to be sent securely
            LambdaFunctionAssociations=[
                cloudfront.LambdaFunctionAssociation(
                    EventType='viewer-request',
                    LambdaFunctionARN=Ref(param_authorizer_lae_arn)
                ),
            ],
            # Rest of config as per your needs
            TargetOriginId='RealOrigin',
            ForwardedValues=cloudfront.ForwardedValues(
                QueryString=True,
                Cookies=cloudfront.Cookies(
                    Forward='all',  # Don't do this. Done here to validate cookie-removal logic
                ),
            ),
        ),
        ViewerCertificate=cloudfront.ViewerCertificate(
            AcmCertificateArn=If(use_cert_cond, Ref(acm_cert), Ref(AWS_NO_VALUE)),
            SslSupportMethod=If(use_cert_cond, 'sni-only', Ref(AWS_NO_VALUE)),
            CloudFrontDefaultCertificate=If(use_cert_cond, Ref(AWS_NO_VALUE), True),
        ),
    ),
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))

hosted_zone_map = "HostedZoneMap"
template.add_mapping(hosted_zone_map, cfnutils.mappings.r53_hosted_zone_id())

template.add_resource(route53.RecordSetType(
    "DomainA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(example_distribution, 'DomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('DNS for ${AWS::StackName}'),
    HostedZoneName=Join('', [Ref(param_hosted_zone_name), '.']),
    Name=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Type='A',
))
template.add_resource(route53.RecordSetType(
    "DomainAAAA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(example_distribution, 'DomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('DNS for ${AWS::StackName}'),
    HostedZoneName=Join('', [Ref(param_hosted_zone_name), '.']),
    Name=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Type='AAAA',
))

write_template_to_file(template)
