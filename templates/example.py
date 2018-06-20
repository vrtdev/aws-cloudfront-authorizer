from central_helpers import MetadataHelper, write_template_to_file
from central_helpers.vrt import add_tags, StackLinker
from troposphere import Template, Tags, cloudfront, constants, ImportValue, Sub, Join, Parameter

template = Template()

stack_linker = StackLinker(template)

template_helper = MetadataHelper(template)
vrt_tags = add_tags(template)

authorizer_stack = template.add_parameter(Parameter(
    "AuthorizerStack",
    Type=constants.STRING,
    Description="Authorizer stack to import from",
))

example_distribution = template.add_resource(cloudfront.Distribution(
    "ExampleDistribution",
    DistributionConfig=cloudfront.DistributionConfig(
        Comment="Example distribution for restricted access",
        Enabled=True,
        IPV6Enabled=True,
        HttpVersion='http2',
        PriceClass='PriceClass_100',
        Origins=[
            cloudfront.Origin(
                # Your usual config here
                Id="RealOrigin",
                DomainName="imset.org",  # TODO https://www.whatismyip.com/
                CustomOriginConfig=cloudfront.CustomOrigin(
                    HTTPPort=80,
                    HTTPSPort=443,
                    OriginProtocolPolicy='https-only',
                    OriginSSLProtocols=['TLSv1.2', 'TLSv1.1', 'TLSv1']
                ),
            ),
            cloudfront.Origin(
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
            TrustedSigners=[ImportValue(Sub('${' + authorizer_stack.title + '}-trusted-account'))],
            # Rest of config as per your needs
            TargetOriginId='RealOrigin',
            ForwardedValues=cloudfront.ForwardedValues(
                QueryString=True,
            ),
        ),
        CustomErrorResponses=[
            cloudfront.CustomErrorResponse(
                # Catch cloudfront 403's and try to authenticate user.
                # WARNING: this may interfere with your own 403's...
                ErrorCode=403,
                ResponseCode=403,
                ResponsePagePath=Join('', [
                    ImportValue(Sub('${' + authorizer_stack.title + '}-magic-path')),
                    '/forbidden',
                ]),
            )
        ],
    ),
    Tags=Tags(**vrt_tags),
))

write_template_to_file(template)
