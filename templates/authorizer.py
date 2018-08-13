"""
VRT authorizer stack
"""
from central_helpers import MetadataHelper, write_template_to_file, \
    kms as kms_helpers, resource2var, mappings
from central_helpers.custom_resources import parameter_store as custom_ssm_ps
from central_helpers.custom_resources.certificatemanager import DnsValidatedCertificate
from central_helpers.vrt import add_tags, StackLinker
from custom_resources.CognitoUserPoolClient import CognitoUserPoolClient
from custom_resources.CognitoUserPoolDomain import CognitoUserPoolDomain
from troposphere import Template, Parameter, Ref, Sub, Tags, GetAtt, Output, Export, Join, AWS_STACK_NAME, apigateway, \
    Equals, route53, FindInMap, AWS_REGION, serverless, constants, awslambda, cognito, kms, iam

template = Template()

stack_linker = StackLinker(template)

template_helper = MetadataHelper(template)
vrt_tags = add_tags(template)

template.add_transform('AWS::Serverless-2016-10-31')

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

param_domain_name = template.add_parameter(Parameter(
    "DomainName",
    Default="authorizer.a51.be",
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

magic_path = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220'

cognito_user_pool = template.add_resource(cognito.UserPool(
    "CognitoUserPool",
    UserPoolName=Sub("StagingAccess${AWS::StackName}"),
    UserPoolTags=vrt_tags,
))

cognito_user_pool_domain = template.add_resource(CognitoUserPoolDomain(
    "CognitoUserPoolDomain",
    ServiceToken=stack_linker.CRST_CognitoUserPoolDomain2,
    UserPoolId=Ref(cognito_user_pool),
    # Domain=auto-generated
))

# Output for ADFS configuration:
template.add_output(Output(
    'SamlUrl',
    Value=Join('', [
        "https://", GetAtt(cognito_user_pool_domain, 'Domain'), ".auth.", Ref(AWS_REGION), ".amazoncognito.com/saml2/idpresponse"
    ]),
    Description='redirect or sign-in URL',
))
template.add_output(Output(
    "Urn",
    Value=Sub("urn:amazon:cognito:sp:{id}".format(id=resource2var(cognito_user_pool))),
))

cognito_user_pool_client = template.add_resource(CognitoUserPoolClient(
    "CognitoUserPoolClient",
    ServiceToken=stack_linker.CRST_CognitoUserPoolClient2,
    UserPoolId=Ref(cognito_user_pool),
    ClientName="vrt-authorizer",
    CallbackURLs=[
        Join('', [
            'https://',
            Ref(param_domain_name),
            '/',
        ]),
    ],
    AllowedOAuthFlows=["code"],
    AllowedOAuthScopes=["openid", "aws.cognito.signin.user.admin"],
    SupportedIdentityProviders=["COGNITO"],
    GenerateSecret=True,
))

lambda_role = template.add_resource(iam.Role(
    "LambdaRole",
    Path="/",
    AssumeRolePolicyDocument={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                # Lambda@Edge uses a different principal than normal lambda
                "Principal": {
                    "Service": [
                        "lambda.amazonaws.com",
                        "edgelambda.amazonaws.com"
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    },
    Policies=[
        iam.Policy(
            PolicyName='lambda-inline-policy',
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": "*"
                    },

                    # KMS permissions are defined on the key
                    # Parameter store permissions are added below to prevent dependency cirlce
                    # (ldap_key -> ldap_role -> parameter -> ldap_key)
                ],
            },
        ),
    ],
))

template.add_output(Output(
    "LambdaRoleArn",
    Description='Lambda Role ARN',
    Value=GetAtt(lambda_role, 'Arn'),
))

vrt_auth_key = template.add_resource(kms.Key(
    "VrtAuthKey",
    Description=Sub("Key for VRT-authorizer in ${AWS::StackName}"),
    KeyPolicy={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": Sub("arn:aws:iam::${AWS::AccountId}:root")},
                "Action": kms_helpers.IAM_RESTRICTED_ACTIONS,
                "Resource": "*",
            },
            # It's not possible to create a key you cannot edit yourself, however we can make sure
            # That only root can edit the key -- if we're deploying this stack with the root account
            {
                "Sid": "Allow updates to the policy",
                "Effect": "Allow",
                "Principal": {
                    "AWS": Sub("arn:aws:iam::${AWS::AccountId}:root")},
                "Action": "kms:PutKeyPolicy",
                "Resource": "*",
                # "Condition": If(is_root_deploy, kms_helpers.IAM_ONLY_ROOT,
                #                 Ref(AWS_NO_VALUE)),
                # TODO: add is_root_deploy parameter & condition, and uncomment the above
            },
            {
                "Sid": "Allow encrypting things",
                "Effect": "Allow",
                "Principal": {"AWS": stack_linker.CRR_ParameterStoreParameter},
                "Action": "kms:Encrypt",
                "Resource": "*",
            },
            {
                "Sid": "Allow decrypting things",
                "Effect": "Allow",
                "Principal": {"AWS": GetAtt(lambda_role, 'Arn')},
                "Action": kms_helpers.IAM_DECRYPT_ACTIONS,
                "Resource": "*",  # The policy is applied to only this key
            },
        ],
    },
    Tags=Tags(**vrt_tags),
))

vrt_auth_key_alias = template.add_resource(kms.Alias(
    "VrtAuthKeyAlias",
    AliasName=Sub('alias/${AWS::StackName}/vrt-auth-key'),
    TargetKeyId=Ref(vrt_auth_key),
))

jwt_secret_parameter = template.add_resource(custom_ssm_ps.ParameterStoreParameter(
    "JwtSecretParameter",
    split_stacks=True, ServiceToken=stack_linker.CRST_ParameterStoreParameter,
    Name=Sub('/${AWS::StackName}/jwt-secret'),
    # WARNING: this name is hard-coded in index.js!!!
    Type="SecureString",
    KeyId=Ref(vrt_auth_key),
    RandomValue={"Serial": '1'},  # Change this to force a new random value
    Tags=Tags(**vrt_tags),
))

template.add_resource(iam.PolicyType(
    "LambdaSharedSecretParamPermission",
    Roles=[Ref(lambda_role)],
    PolicyName='ssm-parameter-read',
    PolicyDocument={
        "Version": "2012-10-17",
        "Statement": [{
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameters",
            ],
            "Effect": "Allow",
            "Resource": [
                Sub(
                    "arn:aws:ssm:${{AWS::Region}}:${{AWS::AccountId}}:parameter{param}".format(
                        param=resource2var(p)
                    ))
                for p in [jwt_secret_parameter]
            ],
        }]
    }
))

common_lambda_options = {
    'Runtime': 'python3.6',
    'CodeUri': serverless.S3Location('unused', Bucket=Ref(param_s3_bucket_name), Key=Ref(param_s3_key)),
    'Environment': awslambda.Environment(
        Variables={
            "COGNITO_USER_POOL_ID": Ref(cognito_user_pool),
            "COGNITO_DOMAIN_PREFIX": GetAtt(cognito_user_pool_domain, 'Domain'),
            "COGNITO_CLIENT_ID": Ref(cognito_user_pool_client),
            "COGNITO_CLIENT_SECRET": GetAtt(cognito_user_pool_client, 'ClientSecret'),
            "JWT_SECRET_PARAMETER_NAME": Ref(jwt_secret_parameter),
            "DOMAIN_NAME": Ref(param_domain_name),
            "MAGIC_PATH": magic_path,
        }
    ),
    'Role': GetAtt(lambda_role, 'Arn'),
    'Tags': vrt_tags,
}

template.add_resource(serverless.Function(
    "Index",
    **common_lambda_options,
    Handler='index.handler',
    Events={
        'Index': serverless.ApiEvent(
            'unused',
            Path='/',
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "DomainList",
    **common_lambda_options,
    Handler='domain_list.handler',
    Events={
        'DomainList': serverless.ApiEvent(
            'unused',
            Path='/domain_list',
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "RequestAccess",
    **common_lambda_options,
    Handler='request_access.handler',
    Events={
        'RequestAccess': serverless.ApiEvent(
            'unused',
            Path='/request_access',
            Method='POST',
        ),
    },
))

template.add_resource(serverless.Function(
    "GrantAccess",
    **common_lambda_options,
    Handler='grant_access.handler',
    Events={
        'GrantAccess': serverless.ApiEvent(
            'unused',
            Path='/grant_access',
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "Forbidden",
    **common_lambda_options,
    Handler='forbidden.handler',
    Events={
        'Forbidden': serverless.ApiEvent(
            'unused',
            Path='/forbidden',
            Method='GET',
        ),
        'ForbiddenUuid': serverless.ApiEvent(
            'unused',
            Path=magic_path + '/forbidden',
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "VerifyAccess",
    **common_lambda_options,
    Handler='verify_access.handler',
    Events={
        'VerifyAccess': serverless.ApiEvent(
            'unused',
            Path='/verify_access',
            # WARNING: this name is hard-coded in index.js
            Method='GET',
        ),
        'VerifyAccessUuid': serverless.ApiEvent(
            'unused',
            Path=magic_path + '/verify_access',
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "SetCookie",
    **common_lambda_options,
    Handler='set_cookie.handler',
    Events={
        'SetCookie': serverless.ApiEvent(
            'unused',
            Path='/set-cookie',  # easier for testing
            Method='GET',
        ),
        'SetCookieUuid': serverless.ApiEvent(
            'unused',
            Path=magic_path + '/set-cookie',
            Method='GET',
        ),
    },
))

template.add_output(Output(
    "ApiDomain",
    Description='Domain name of the API',
    Value=Ref(param_domain_name),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'domain-name'])),
))

template.add_output(Output(
    "MagicPath",
    Description='Magic path',
    Value=magic_path,
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'magic-path'])),
))

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

api_domain = template.add_resource(apigateway.DomainName(
    "ApiDomain",
    CertificateArn=Ref(acm_cert),
    DomainName=Ref(param_domain_name),
    Condition=use_cert_cond,
))

api_domain_mapping = template.add_resource(apigateway.BasePathMapping(
    "ApiDomainMapping",
    DomainName=Ref(api_domain),
    RestApiId=Ref('ServerlessRestApi'),  # Default name of Serverless generated gateway
    Stage='Prod',  # Default name of Serverless generated Stage
    Condition=use_cert_cond,
))

hosted_zone_map = "HostedZoneMap"
template.add_mapping(hosted_zone_map, mappings.hosted_zone_map())

domain = template.add_resource(route53.RecordSetType(
    "Domain",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(api_domain, 'DistributionDomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('Default DNS for ${AWS::StackName} api'),
    HostedZoneId=stack_linker.hosted_zone_id,
    Name=Ref(param_domain_name),
    # WARNING: this name is hard-coded in index.js
    Type='A',
    Condition=use_cert_cond,
))

write_template_to_file(template)
