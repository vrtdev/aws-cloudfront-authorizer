"""Authorizer stack."""
from troposphere import Template, Parameter, Ref, Sub, GetAtt, Output, Export, Join, AWS_STACK_NAME, apigateway, \
    Equals, route53, FindInMap, AWS_REGION, serverless, constants, awslambda, kms, iam, s3, dynamodb, \
    ImportValue, Not
import custom_resources.ssm
import custom_resources.acm
import custom_resources.cognito
import custom_resources.cloudformation
import custom_resources.s3
import cfnutils.mappings
import cfnutils.kms
import cfnutils.output

template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

template.set_transform('AWS::Serverless-2016-10-31')

# Parameters

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

param_label = template.add_parameter(Parameter(
    "Label",
    Default="authorizer",
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
    Default='no',  # Default to no, so new stacks requets, but don't use certs
    # This avoids stacks failing since the cert is not approved yet
    Description="Use TLS certificate",
))
template.set_parameter_label(param_use_cert, "Use TLS certificate")

cognito_stack = template.add_parameter(Parameter(
    "CognitoStack",
    Type=constants.STRING,
    Description="Name of the UserPool Cloudformation stack",
    Default='vrt-dpc-infra-cognito-userpool-vrt-prod',
))
template.set_parameter_label(cognito_stack, "Name of the UserPool stack")

identity_pool_providers = template.add_parameter(Parameter(
    "IdentityProviders",
    Type=constants.COMMA_DELIMITED_LIST,
    Description="Comma delimited list of identity pool providers to enable in the AppClient. Available: 'AzureAD', 'adfs', 'COGNITO'",
    Default='AzureAD',
))
template.set_parameter_label(
    identity_pool_providers,
    "Comma delimited list of identity pool providers to enable in the AppClient. Available: 'AzureAD', 'adfs', 'COGNITO'",
)

lambda_idp_name = template.add_parameter(Parameter(
    "LambdaIDPName",
    Type=constants.STRING,
    Description="Identity Provider Name for Lambda use. One of: 'AzureAD', 'adfs', 'COGNITO'",
    Default='AzureAD',
))
template.set_parameter_label(lambda_idp_name, "Identity Provider Name for Lambda use. One of: 'AzureAD', 'adfs', 'COGNITO'")

ci_shared_resources_role = template.add_parameter(Parameter(
    "CiSharedResourcesRole",
    Type=constants.COMMA_DELIMITED_LIST,
    Default="",
    Description="ARN of the role of the ci instance. Leave empty to skip ci function/role creation.",
))
template.set_parameter_label(ci_shared_resources_role, "ARN of the role of the ci instance. Leave empty to skip function/role creation.")
create_ci_function = template.add_condition("CreateCiFunction", Not(Equals(Join("", Ref(ci_shared_resources_role)), "")))

ci_role_path = template.add_parameter(Parameter(
    "CiRolePath",
    Type=constants.STRING,
    Default="/",
    Description="Path to create the ci role in. Defaults to '/'",
))
template.set_parameter_label(ci_role_path, "Path to create the ci role in. Defaults to '/'")

# Resources

cloudformation_tags = template.add_resource(custom_resources.cloudformation.Tags("CfnTags"))

user_pool_client = template.add_resource(custom_resources.cognito.UserPoolClient(
    "UserPoolClient",
    UserPoolId=ImportValue(Join('-', [Ref(cognito_stack), "UserPoolId"])),
    ClientName=Ref("AWS::StackName"),
    AllowedOAuthFlows=["code"],
    AllowedOAuthScopes=["openid", "email", "profile", "aws.cognito.signin.user.admin"],
    AllowedOAuthFlowsUserPoolClient=True,
    GenerateSecret=True,
    CallbackURLs=[
        Join('', [
            'https://',
            Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
            '/authenticate',
        ]),
    ],
    SupportedIdentityProviders=Ref(identity_pool_providers),
    # AccessTokenValidity=Ref(access_token_validity),
    # IdTokenValidity=Ref(id_token_validity),
    # RefreshTokenValidity=Ref(refresh_token_validity),
    # TokenValidityUnits=cognito.TokenValidityUnits(
    #     AccessToken="hours",
    #     IdToken="hours",
    #     RefreshToken="days",
    # ),
))

# Output for IDP configuration:
template.add_output(Output(
    'SamlUrl',
    Value=Join('', [
        "https://",
        ImportValue(Join('-', [Ref(cognito_stack), "UserPoolDomain"])),
        ".auth.",
        Ref(AWS_REGION),
        ".amazoncognito.com/saml2/idpresponse",
    ]),
    Description='redirect or sign-in URL',
))
template.add_output(Output(
    "Urn",
    Value=Join(':', ['urn:amazon:cognito:sp', ImportValue(Join('-', [Ref(cognito_stack), "UserPoolId"]))]),
))

config_bucket = template.add_resource(s3.Bucket(
    "ConfigBucket",
))
template.add_output(Output(
    "ConfigBucketName",
    Description='Config bucket name',
    Value=Ref(config_bucket),
))

domain_table = template.add_resource(dynamodb.Table(
    "DomainTable",
    BillingMode="PAY_PER_REQUEST",
    AttributeDefinitions=[
        dynamodb.AttributeDefinition(
            AttributeName="domain",
            AttributeType="S",
        ),
    ],
    KeySchema=[
        dynamodb.KeySchema(
            AttributeName="domain",
            KeyType="HASH",
        ),
    ],
))
template.add_output(Output(
    "DomainTableName",
    Description="DynamoDB table for domains",
    Value=Ref(domain_table),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'DomainTable'])),
))

group_table = template.add_resource(dynamodb.Table(
    "GroupTable",
    BillingMode="PAY_PER_REQUEST",
    AttributeDefinitions=[
        dynamodb.AttributeDefinition(
            AttributeName="group",
            AttributeType="S",
        ),
    ],
    KeySchema=[
        dynamodb.KeySchema(
            AttributeName="group",
            KeyType="HASH",
        ),
    ],
))
template.add_output(Output(
    "GroupTableName",
    Description="DynamoDB table for groups",
    Value=Ref(group_table),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'GroupTable'])),
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
                        "edgelambda.amazonaws.com",
                    ],
                },
                "Action": "sts:AssumeRole",
            },
        ],
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
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    },
                    {
                        # Allow lambda to read its own configuration
                        # Needed for Lambda@Edge to pass parameters
                        "Effect": "Allow",
                        "Action": [
                            "lambda:GetFunction",
                        ],
                        "Resource": "*",
                    },
                    {
                        # Read configuration
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                        ],
                        "Resource": Join('', ["arn:aws:s3:::", Ref(config_bucket), "/*"]),
                    },
                    {
                        # Read DynamoDB
                        "Effect": "Allow",
                        "Action": [
                            "dynamodb:GetItem",
                            "dynamodb:Scan",
                        ],
                        "Resource": [
                            GetAtt(domain_table, "Arn"),
                            GetAtt(group_table, "Arn"),
                        ],
                    },

                    # KMS permissions are defined on the key
                    # Parameter store permissions are added below to prevent dependency circle
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

auth_key = template.add_resource(kms.Key(
    "AuthKey",
    Description=Sub("Key for Authorizer in ${AWS::StackName}"),
    KeyPolicy={
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": Sub("arn:aws:iam::${AWS::AccountId}:root")},
                "Action": cfnutils.kms.IAM_SAFE_ACTIONS,
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
                "Principal": {"AWS": custom_resources.ssm.Parameter.role()},
                "Action": "kms:Encrypt",
                "Resource": "*",
            },
            {
                "Sid": "Allow decrypting things",
                "Effect": "Allow",
                "Principal": {"AWS": GetAtt(lambda_role, 'Arn')},
                "Action": cfnutils.kms.IAM_DECRYPT_ACTIONS,
                "Resource": "*",  # The policy is applied to only this key
            },
        ],
    },
    Tags=GetAtt(cloudformation_tags, 'TagList'),
))

auth_key_alias = template.add_resource(kms.Alias(
    "AuthKeyAlias",
    AliasName=Sub('alias/${AWS::StackName}/auth-key'),
    TargetKeyId=Ref(auth_key),
))

jwt_secret_parameter = template.add_resource(custom_resources.ssm.Parameter(
    "JwtSecretParameter",
    Name=Sub('/${AWS::StackName}/jwt-secret'),
    # WARNING: this name is hard-coded in index.js!!!
    Type="SecureString",
    KeyId=Ref(auth_key),
    RandomValue={"Serial": '1'},  # Change this to force a new random value
    Tags=GetAtt(cloudformation_tags, 'TagList'),
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
                    "arn:aws:ssm:${{AWS::Region}}:${{AWS::AccountId}}:parameter${{{param}}}".format(
                        param=p.title,
                    ))
                for p in [jwt_secret_parameter]
            ],
        }],
    },
))

common_lambda_options = {
    'Runtime': 'python3.9',
    'Timeout': 10,  # Cold start sometimes takes longer than the default 3 seconds
    'CodeUri': serverless.S3Location('unused', Bucket=Ref(param_s3_bucket_name), Key=Ref(param_s3_key)),
    'Environment': awslambda.Environment(
        Variables={
            "COGNITO_USER_POOL_ID": ImportValue(Join('-', [Ref(cognito_stack), "UserPoolId"])),
            "COGNITO_DOMAIN_PREFIX": ImportValue(Join('-', [Ref(cognito_stack), "UserPoolDomain"])),
            "COGNITO_CLIENT_ID": Ref(user_pool_client),
            "COGNITO_CLIENT_SECRET": GetAtt(user_pool_client, 'ClientSecret'),
            "COGNITO_EF_IDP_NAME": Ref(lambda_idp_name),
            "DOMAIN_NAME": Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
            "CONFIG_BUCKET": Ref(config_bucket),
            "POWERTOOLS_SERVICE_NAME": "authorizer",
        },
    ),
    'Role': GetAtt(lambda_role, 'Arn'),
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
    "Delegate",
    **common_lambda_options,
    Handler='delegate.handler',
    Events={
        'GetDelegate': serverless.ApiEvent(
            'unused',
            Path='/delegate',
            Method='GET',
        ),
        'PostDelegate': serverless.ApiEvent(
            'unused',
            Path='/delegate',
            Method='POST',
        ),
    },
))

template.add_resource(serverless.Function(
    "UseGrant",
    **common_lambda_options,
    Handler='use_grant.handler',
    Events={
        'Authenticate': serverless.ApiEvent(
            'unused',
            Path='/use_grant',
            Method='GET',
        ),
    },
))


template.add_resource(serverless.Function(
    "Logout",
    **common_lambda_options,
    Handler='logout.handler',
    Events={
        'Logout': serverless.ApiEvent(
            'unused',
            Path='/logout',
            Method='POST',
        ),
    },
))


template.add_resource(serverless.Function(
    "Authenticate",
    **common_lambda_options,
    Handler='authenticate.handler',
    Events={
        'Authenticate': serverless.ApiEvent(
            'unused',
            Path='/authenticate',
            Method='GET',
        ),
    },
))

authorize_path = '/authorize'
template.add_resource(serverless.Function(
    "Authorize",
    **common_lambda_options,
    Handler='authorize.handler',
    Events={
        'GrantAccess': serverless.ApiEvent(
            'unused',
            Path=authorize_path,
            Method='GET',
        ),
    },
))

template.add_resource(serverless.Function(
    "BatchAuthorize",
    **common_lambda_options,
    Handler='batch_authorize.handler',
    Events={
        'BatchAuthorize': serverless.ApiEvent(
            'unused',
            Path='/batch_authorize',
            Method='GET',
        ),
    },
))


generate_ci_function = template.add_resource(serverless.Function(
    "GenerateCI",
    **common_lambda_options,
    Handler='generate_ci.handler',
    Events={
        'GenerateCi': serverless.ApiEvent(
            'unused',
            Auth=serverless.ApiFunctionAuth(
                Authorizer='AWS_IAM',
                InvokeRole='CALLER_CREDENTIALS',
            ),
            Path='/generate_ci',
            Method='POST',
        ),
    },
    Condition=create_ci_function,
))

ci_role = template.add_resource(iam.Role(
    "CiRole",
    Description="Role to allow CI token generation",
    Path=Ref(ci_role_path),
    AssumeRolePolicyDocument={
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "AWS": Ref(ci_shared_resources_role)},
            "Action": "sts:AssumeRole",
        }],
    },
    Policies=[
        iam.Policy(
            PolicyName="invoke-api-policy",
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "execute-api:Invoke",
                    "Resource": Sub(
                        "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiId}/${Stage}/${Verb}/${Path}",
                        ApiId=Ref('ServerlessRestApi'),  # Default name of Serverless generated gateway
                        Stage='Prod',  # Default name of Serverless generated Stage
                        # Path this is hard to extract from the method resource
                        # Only extracting the method does not have a lot of advantages
                        Verb='POST',
                        Path='generate_ci',
                    ),
                }],
            },
        ),
        iam.Policy(
            PolicyName="invoke-lambda-policy",
            PolicyDocument={
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "aws:InvokeLambda",
                    "Resource": GetAtt(generate_ci_function, "Arn"),
                }],
            },
        ),
    ],
    Condition=create_ci_function,
))

template.add_resource(awslambda.Permission(
    "CiFunctionPermission",
    Action="lambda:InvokeFunction",
    FunctionName=Ref(generate_ci_function),
    Principal=GetAtt(ci_role, "Arn"),
))

template.add_output(Output(
    "ApiDomain",
    Description='Domain name of the API',
    Value=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'domain-name'])),
))

magic_path = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220'
template.add_output(Output(
    "MagicPath",
    Description='Magic path',
    Value=magic_path,
    Export=Export(Join('-', [Ref(AWS_STACK_NAME), 'magic-path'])),
))

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

api_domain = template.add_resource(apigateway.DomainName(
    "ApiDomain",
    CertificateArn=Ref(acm_cert),
    DomainName=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
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
template.add_mapping(hosted_zone_map, cfnutils.mappings.r53_hosted_zone_id())

template.add_resource(route53.RecordSetType(
    "DomainA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(api_domain, 'DistributionDomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('Default DNS for ${AWS::StackName} api'),
    HostedZoneName=Join('', [Ref(param_hosted_zone_name), '.']),
    Name=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Type='A',
    Condition=use_cert_cond,
))

template.add_resource(route53.RecordSetType(
    "DomainAAAA",
    AliasTarget=route53.AliasTarget(
        DNSName=GetAtt(api_domain, 'DistributionDomainName'),
        HostedZoneId=FindInMap(hosted_zone_map, Ref(AWS_REGION), 'CloudFront'),
    ),
    Comment=Sub('Default DNS for ${AWS::StackName} api'),
    HostedZoneName=Join('', [Ref(param_hosted_zone_name), '.']),
    Name=Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
    Type='AAAA',
    Condition=use_cert_cond,
))

config_object = template.add_resource(custom_resources.s3.Object(
    "ConfigFile",
    Bucket=Ref(config_bucket),
    Key="config.json",
    Body={  # Default settings
        'parameter_store_region': Ref(AWS_REGION),
        'parameter_store_parameter_name': jwt_secret_parameter.properties['Name'],

        'authorize_url': Join('', [
            'https://',
            Join('.', [Ref(param_label), Ref(param_hosted_zone_name)]),
            authorize_path,
        ]),
        'set_cookie_path': magic_path + "/set-cookie",
        'domain_table': Ref(domain_table),
        'group_table': Ref(group_table),
    },
))

cfnutils.output.write_template_to_file(template)
