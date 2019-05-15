from troposphere import Template, cloudfront, constants, Sub, Join, Parameter, Ref, Output, GetAtt, \
    Equals, AWS_NO_VALUE, If, route53, FindInMap, AWS_REGION, ImportValue, s3
import custom_resources.acm
import custom_resources.cloudformation
import custom_resources.dynamodb
import custom_resources.s3
import cfnutils.mappings
import cfnutils.output


template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

param_authorizer_param_stack = template.add_parameter(Parameter(
    "AuthorizerParamStackParam",
    Type=constants.STRING,
    Default="authorizer-params",
    Description="StackName of the Params stack",
))

param_authorizer_lae_arn = template.add_parameter(Parameter(
    "AuthorizerLaeParam",
    Type="AWS::SSM::Parameter::Value<String>",
    Default='/authorizer/lae-arn',
    Description="Parameter name to get Lambda@Edge ARN from",
))
template.set_parameter_label(param_authorizer_lae_arn, "Authorizer Lambda@Edge parameter")

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

domain_name = Join('.', [Ref(param_label), Ref(param_hosted_zone_name)])

acm_cert = template.add_resource(custom_resources.acm.DnsValidatedCertificate(
    "AcmCert",
    Region='us-east-1',  # Api gateway is in us-east-1
    DomainName=domain_name,
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))
template.add_output(Output(
    "AcmCertDnsRecords",
    Value=GetAtt(acm_cert, "DnsRecords"),
))

use_cert_cond = 'UseCert'
template.add_condition(use_cert_cond, Equals(Ref(param_use_cert), 'yes'))


# Create an entry in the domain-table, so this domain is listed in the Authorizer
template.add_resource(custom_resources.dynamodb.Item(
    "AuthorizedDomain",
    TableName=ImportValue(Join('-', [Ref(param_authorizer_param_stack), "DomainTable"])),
    ItemKey={"domain": {"S": domain_name}},
))

# Create an entry in the group-table
template.add_resource(custom_resources.dynamodb.Item(
    "AuthorizedDomainExampleGroup",
    TableName=ImportValue(Join('-', [Ref(param_authorizer_param_stack), "GroupTable"])),
    ItemKey={"group": {"S": "Example Group"}},
    ItemValue={"domains": {"SS": [domain_name]}},
))


# Create a bucket with example content (only needed for this example, obviously)
example_bucket = template.add_resource(s3.Bucket(
    "ExampleBucket",
))
example_bucket_content = template.add_resource(custom_resources.s3.Object(
    "ExampleBucketContent",
    Bucket=Ref(example_bucket),
    Key="index.html",
    ContentType='text/html',
    Body="""<html>
    <head><title>Protected content</title></head>
    <body>
    <h1>Protected Content</h1>
    <p>You've reached the protected part of this example site.</p>
    </body>
    </html>
    """,
))
example_bucket_oai = template.add_resource(cloudfront.CloudFrontOriginAccessIdentity(
    "ExampleBucketOai",
    CloudFrontOriginAccessIdentityConfig=cloudfront.CloudFrontOriginAccessIdentityConfig(
        Comment=Sub("OAI for ${AWS::StackName}"),
    ),
))
example_bucket_policy = template.add_resource(s3.BucketPolicy(
    "DefaultOriginBucketPolicy",
    Bucket=Ref(example_bucket),
    PolicyDocument={
        "Version": "2012-10-17",
        "Id": "PolicyForCloudFrontPrivateContent",
        "Statement": [
            {
                "Sid": " Grant a CloudFront Origin Identity access to support private content",
                "Effect": "Allow",
                "Principal": {"CanonicalUser": GetAtt(example_bucket_oai, 'S3CanonicalUserId')},
                "Action": "s3:GetObject",
                "Resource": Join('', ["arn:aws:s3:::", Ref(example_bucket), "/*"]),
            },
        ],
    },
))

example_distribution = template.add_resource(cloudfront.Distribution(
    "ExampleDistribution",
    DistributionConfig=cloudfront.DistributionConfig(
        Comment="Example distribution for restricted access",
        Aliases=[domain_name],
        Enabled=True,
        IPV6Enabled=True,
        HttpVersion='http2',
        PriceClass='PriceClass_100',
        Origins=[
            # Your usual config goes here, example:
            cloudfront.Origin(
                Id="ExampleS3",
                DomainName=Join('', [Ref(example_bucket), '.s3.amazonaws.com']),
                S3OriginConfig=cloudfront.S3OriginConfig(
                    OriginAccessIdentity=Join('', [
                        'origin-access-identity/cloudfront/', Ref(example_bucket_oai),
                    ])
                ),
            ),
        ],
        DefaultRootObject="index.html",  # Needed for this example only, adapt to your requirements
        CacheBehaviors=[
            # If you have additional cache behaviours,
            # make sure that (at least) the behaviour matching
            # /auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie
            # has the Lambda-function associated.
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
            TargetOriginId='ExampleS3',
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
    Name=domain_name,
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
    Name=domain_name,
    Type='AAAA',
))

cfnutils.output.write_template_to_file(template)
