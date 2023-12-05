"""Sigv4 Lambda@Edge stack."""
from troposphere import Template, Parameter, Ref, Sub, GetAtt, awslambda, iam, constants, \
    Output, Export, If, Not, Equals
import custom_resources
import cfnutils.output

template = Template()

custom_resources.use_custom_resources_stack_name_parameter(template)

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

api_id = template.add_parameter(Parameter(
    "ApiId",
    Default="",
    Type=constants.STRING,
    Description="API Gateway ID",
))
template.set_parameter_label(api_id, "API Gateway ID")

# Conditions

HAS_API_ID = template.add_condition('HasApiId', Not(Equals(Ref(api_id), '')))

# Resources

lambda_sigv4_exec_role = template.add_resource(iam.Role(
    "Sigv4RequestLambdaFunctionExecutionRole",
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
            PolicyName='LambdaEdgeAccessPolicy',
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
                        "Resource": Sub("arn:${AWS::Partition}:logs:*:${AWS::AccountId}:log-group:*"),
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "execute-api:Invoke",
                        ],
                        "Resource": Sub(
                            "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${ApiId}/*/*/*",
                            ApiId=If(
                                HAS_API_ID,
                                Ref(api_id),
                                '*',
                            ),
                        ),
                    },
                ],
            },
        ),
    ],
))

sigv4_function = template.add_resource(awslambda.Function(
    "Sigv4RequestLambdaFunction",
    Description="Lambda function signs request with AWS Signature Version 4",
    Code=awslambda.Code(S3Bucket=Ref(param_s3_bucket_name), S3Key=Ref(param_s3_key)),
    Handler="index.handler",
    MemorySize=128,
    Role=GetAtt(lambda_sigv4_exec_role, "Arn"),
    Runtime='nodejs20.x',
))

sigv4_function_version = template.add_resource(awslambda.Version(
    "Sigv4RequestLambdaFunctionVersion",
    FunctionName=Ref(sigv4_function),
    Description="Sigv4 signing",
))

template.add_output(Output(
    "Sigv4RequestLambdaFunctionVersionArn",
    Description='Sigv4 signing function version ARN',
    Value=Ref(sigv4_function_version),
    Export=Export(Sub("${AWS::StackName}-Sigv4RequestLambdaFunctionVersionArn")),
))

cfnutils.output.write_template_to_file(template)
