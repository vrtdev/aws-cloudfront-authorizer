/*
 * Should be run at the Viewer Request state.
 *
 * The alternative would be to hook on Origin Request. This has the advantage of caching the "no cookie"-case, but
 * causes all browsers to effectively have their own private cache on CloudFront. This hides potential bugs when the
 * CloudFront configuration would cause users to see each other's cached pages.
 * This would also open up a bug when the CloudFront caching behaviour is misconfigured to ignore the authorizer cookie.
 *
 * Hence, we want to run on Viewer Request, this has the least amount of influence on the remaining flow.
 */

"use strict";

const JWT = require('jsonwebtoken');
const AWS = require('aws-sdk');


function asyncLambdaGetFunction(param, service_param = {}) {
    // Async wrapper around the Lambda GetFunction API call
    return new Promise(function(resolve, reject) {
        const lambda = new AWS.Lambda(service_param);
        lambda.getFunction(param, function(err, data) {
            if(err !== null) { reject(err); }
            else { resolve(data); }
        });
    });
}

function asyncS3GetObject(param) {
    // Async wrapper around the S3 GetObject API call
    return new Promise(function(resolve, reject) {
        const s3 = new AWS.S3();
        s3.getObject(param, function(err, data) {
            if(err !== null) { reject(err); }
            else { resolve(data); }
        });
    });
}

async function get_config_bucket(context) {
    /* Lambda@Edge does not support environment parameters.
     * We use Tags as workaround. This function gets the value of the tag.
     */
    const dot_location = context.functionName.indexOf('.');
    const functionName_without_region = context.functionName.substring(dot_location + 1);
    const lambda_description = await asyncLambdaGetFunction({
            'FunctionName': functionName_without_region,
        }, {
            region: 'us-east-1',  // Lambda@Edge is always us-east-1
        }
    );
    return lambda_description.Tags['ConfigBucket'];
}
async function get_config_(context) {
    let config = {  // Default settings
        'verify_access_url': 'https://authorizer.example.org/verify_access',
        'cookie_name': 'authorizer_access',
        'login_cookie_name': 'authorizer_login',
        'parameter_store_region': 'eu-west-1',
        'parameter_store_parameter_name': '/authorizer/jwt-secret',
    };
    const config_bucket = await get_config_bucket(context);
    try {
        const config_response = await asyncS3GetObject({
            'Bucket': config_bucket,
            'Key': 'config.json',
        });
        const body = config_response.Body.toString('utf-8');
        console.log("Retrieved config from S3:");
        console.log(body);
        const parsed_body = JSON.parse(body);
        for(let key in parsed_body) {
            config[key] = parsed_body[key];
        }
    } catch(e) {
        console.log("Could not retrieve config from S3. Using defaults.");
        console.log(e);
    }
    return config;
}
function get_config_promise(context) {
    if(typeof get_config_promise.cache === 'undefined') {
        get_config_promise.cache = get_config_(context);
    }
    return get_config_promise.cache
}

function get_jwt_secret_promise(region, param_name) {
    if(typeof get_jwt_secret_promise.cache === 'undefined') {
        get_jwt_secret_promise.cache = new Promise(function(resolve, reject) {
            const ssm = new AWS.SSM({
                'region': region,
            });
            ssm.getParameter({
                    'Name': param_name,
                    'WithDecryption': true,
                },
                function(err, data) {
                    if(err !== null) { reject(err); }
                    else { resolve(data['Parameter']['Value']); }
                }
            );
        });
    }
    return get_jwt_secret_promise.cache;
}

function encode_utf8(s) {
    return unescape(encodeURIComponent(s));
}
function decode_utf8(s) {
    return decodeURIComponent(escape(s));
}

function normalize_cookies(headers) {
    /* Parses Cookie:-headers in to a {key: value} dictionary for easier cookie access
     * Note that RFC6265 specifies cookies keys and values as a series of bytes, not characters
     * But CloudFront fails when an invalid UTF-8 sequence is encountered...
     *
     * Also, UTF-8 sequences seem to be double encoded. This functions handles this for you.
     */
    const cookie_headers = headers['cookie'] || [];
    let cookies_string = '';
    for(let header of cookie_headers) {
        /* https://tools.ietf.org/html/rfc6265#section-5.4
         * multiple `Cookie:` headers are not allowed ("MUST NOT attach more than one")
         * Try to parse them anyway by concatenating them
         */
        if( cookies_string.length > 0 ) cookies_string += "; ";
        cookies_string += header.value
    }

    let cookies_kv_pairs = cookies_string.split('; ');
    let cookies = {};
    for(let cookie of cookies_kv_pairs) {
        let t = cookie.split('=');
        const name = decode_utf8(t[0]);
        const value = decode_utf8(t.splice(1).join('='));  // everything after first =
        /* value may be doublequoted, but the quotes are considered part of the value
         * https://stackoverflow.com/questions/1969232/allowed-characters-in-cookies#1969339
         */
        cookies[name] = value;
    }

    return cookies;
}
function render_cookie_header_value(cookies) {
    /* Inverse of normalize_cookies(): recombines the cookies-dictionary
     * into a string usable as Cookie:-header value.
     */
    let cookies_array = [];
    for(let key in cookies) {
        if (cookies.hasOwnProperty(key)) {
            cookies_array.push(`${encode_utf8(key)}=${encode_utf8(cookies[key])}`)
        }
    }
    return cookies_array.join('; ');
}

class InternalServerError extends Error {}
class InvalidToken extends Error {}  // token is badly signed or expired
class BadToken extends Error {}  // token does not meet requirements
async function validate_token(config, raw_token, hostname) {
    let jwt_secret;
    try {
        const get_jwt_secret = await get_jwt_secret_promise(  // may throw
            config.parameter_store_region,
            config.parameter_store_parameter_name
        );
        jwt_secret = await get_jwt_secret;
    } catch(e) {
        throw InternalServerError(e);
    }

    let token;
    try {
        token = JWT.verify(  // may throw
            raw_token,
            jwt_secret,
            {
                "algorithms": ["HS256"],
            }
        );
        console.log("JWT decoded");  // don't log token content for privacy reasons
    } catch(e) {
        console.log("JWT validation failed" + e);  // Token is invalid anyway, no (less) privacy issues
        // Hide validation error for security reasons
        // Assume expired cookie, redirect to authz
        throw new InvalidToken();
    }

    if( !('iat' in token) ||
        !('exp' in token) ||  // exp is checked by JWT.verify(), but not required to be present
        !('domains' in token)
    ) {
        console.log("JWT is malformed");
        // Token is invalid. Assume bad intend and return 400 (instead of redirect to authz)
        throw new BadToken();
    }

    if(token['domains'].indexOf(hostname) === -1) {
        console.log(`Hostname '${hostname}' not in allowed list`);
        // Token is invalid for this domain.
        throw new BadToken();
    }

    console.log(`Token valid for ${hostname}`);

    return token;
}


function bad_request(config, request) {
    return {
        status: 400,
        statusDescription: 'Bad Request',
        headers: {},
        bodyEncoding: 'text',
        body: 'Bad request',
    };
}
function redirect_auth(config, request) {
    const request_headers = request.headers;
    const hostname = request_headers.host[0].value;  // Host:-header is required, should always be present;

    let return_url = `https://${hostname}${request.uri}`;
    if(request.querystring !== '') {
        return_url += '?' + request.querystring;
    }

    return {
        status: '302',
        statusDescription: 'Found',
        headers: {
            'location': [{
                key: 'Location',
                value: `${config.verify_access_url}?return_to=${encodeURIComponent(return_url)}`,
            }],
        },
        bodyEncoding: 'text',
        body: 'Not authorized, redirecting to authorization server',
    };
}

exports.handler = async (event, context) => {
    const config = await get_config_promise(context);

    const request = event.Records[0].cf.request;
    const request_headers = request.headers;
    const hostname = request_headers.host[0].value;  // Host:-header is required, should always be present;
    console.log(`Processing request for Host: ${hostname}`);
    const cookies = normalize_cookies(request_headers);
    // Don't log cookies for privacy reasons

    if(!(config.cookie_name in cookies)) {
        // Cookie not present. Redirect to authz
        console.log(`Could not find cookie with name "${config.cookie_name}"`);
        return redirect_auth(config, request);
    }

    const cookie_value = cookies[config.cookie_name];
    console.log(`Found cookie with name "${config.cookie_name}"`);  // don't log value for privacy reasons

    try {
        await validate_token(config, cookie_value, hostname);
    } catch(e) {
        if(e instanceof InvalidToken) return redirect_auth(config, request);
        else if(e instanceof BadToken) return bad_request(config, request);
    }

    // Remove access_token from Cookie:-header
    delete cookies[config.cookie_name];
    request.headers['cookie'] = [{'key': 'Cookie', 'value': render_cookie_header_value(cookies)}];

    // Pass through request
    return request;
};
