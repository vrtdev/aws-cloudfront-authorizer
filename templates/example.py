from central_helpers import MetadataHelper, write_template_to_file, mappings
from central_helpers.custom_resources.certificatemanager import DnsValidatedCertificate
from central_helpers.vrt import add_tags, StackLinker
from troposphere import Template, Tags, cloudfront, constants, ImportValue, Sub, Join, Parameter, Ref, Output, GetAtt, \
    Equals, AWS_NO_VALUE, If, route53, FindInMap, AWS_REGION

template = Template()

stack_linker = StackLinker(template)

template_helper = MetadataHelper(template)
vrt_tags = add_tags(template)

authorizer_stack = template.add_parameter(Parameter(
    "AuthorizerStack",
    Type=constants.STRING,
    Default="vrt-authorizer",
    Description="Authorizer stack to import from",
))

param_authorizer_lae_arn = template.add_parameter(Parameter(
    "AuthorizerLaeParam",
    Type="AWS::SSM::Parameter::Value<String>",
    Default='/vrt-authorizer/lae-arn',
    Description="Parameter name to get Lambda@Edge ARN from",
))

param_domain_name = template.add_parameter(Parameter(
    "DomainName",
    Default="example.authorizer.a51.be",
    Type=constants.STRING,
    Description="Domain name to use",
))
template_helper.add_parameter_label(param_domain_name, "Domain name")

param_use_cert = template.add_parameter(Parameter(
    "UseCert",
    Type=constants.STRING,
    AllowedValues=['yes', 'no'],
    Default='no',  # Default to no, so new stacks requets, but don't use certs
    # This avoids stacks failing since the cert is not approved yet
    Description="Use TLS certificate"
))
template_helper.add_parameter_label(param_use_cert, "Use TLS certificate")

acm_cert = template.add_resource(DnsValidatedCertificate(
    "AcmCert",
    split_stacks=True, ServiceToken=stack_linker.CRST_DnsValidatedCertificate,
    Region='us-east-1',  # Api gateway is in us-east-1
    DomainName=Ref(param_domain_name),
    Tags=Tags(**vrt_tags),
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
        Aliases=[Ref(param_domain_name)],
        Enabled=True,
        IPV6Enabled=True,
        HttpVersion='http2',
        PriceClass='PriceClass_100',
        Origins=[
            cloudfront.Origin(
                # Your usual config goes here
                Id="RealOrigin",
                DomainName="www.whatismyip.com",
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
    Tags=Tags(**vrt_tags),
))

hosted_zone_map = "HostedZoneMap"
template.add_mapping(hosted_zone_map, mappings.hosted_zone_map())

template.add_resource(route53.RecordSetType(
    "DomainA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(example_distribution, 'DomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('DNS for ${AWS::StackName}'),
    HostedZoneId=stack_linker.hosted_zone_id,
    Name=Ref(param_domain_name),
    Type='A',
))
template.add_resource(route53.RecordSetType(
    "DomainAAAA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(example_distribution, 'DomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('DNS for ${AWS::StackName}'),
    HostedZoneId=stack_linker.hosted_zone_id,
    Name=Ref(param_domain_name),
    Type='AAAA',
))

write_template_to_file(template)
