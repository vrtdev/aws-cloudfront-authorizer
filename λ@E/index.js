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
const querystring = require('querystring');
const url = require('url');


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
    let config = {  // Default settings, keep in sync with Lambda-code!
        'function_arn': context['invokedFunctionArn'],

        'parameter_store_region': 'eu-west-1',
        'parameter_store_parameter_name': '/authorizer/jwt-secret',

        'set_cookie_path': '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie',
        'cookie_name_access_token': 'authorizer_access',
        'cookie_name_no_redirect': 'authorizer_no_redirect',

        'authorize_url': 'https://authorizer.example.org/authorize',
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
    console.log("Issuing BadRequest");
    return {
        status: 400,
        statusDescription: 'Bad Request',
        headers: {
            'x-served-by': [{
                key: 'X-Served-By',
                value: config.function_arn,
            }],
        },
        bodyEncoding: 'text',
        body: 'Bad request',
    };
}
function forbidden(config, request) {
    console.log("Issuing Forbidden");
    return {
        status: 401,
        statusDescription: 'Forbidden',
        headers: {
            'x-served-by': [{
                key: 'X-Served-By',
                value: config.function_arn,
            }],
        },
        bodyEncoding: 'text',
        body: 'Forbidden',
    };
}
function redirect_auth(config, request, cookies) {
    if(cookies === null) cookies = {};
    if(config.cookie_name_no_redirect in cookies) {
        return forbidden(config, request);
    }

    console.log("Issuing redirect to authz");
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
            'x-served-by': [{
                key: 'X-Served-By',
                value: config.function_arn,
            }],
            'location': [{
                key: 'Location',
                value: `${config.authorize_url}?` +
                    `redirect_uri=${encodeURIComponent(return_url)}`,
            }],
        },
        bodyEncoding: 'text',
        body: 'Not authorized, redirecting to authorization server',
    };
}
function internal_server_error(config, exception) {
    console.log("Issuing Internal Server Error");
    console.log(exception);
    return {
        status: '500',
        statusDescription: 'Internal Server Error',
        headers: {
            'x-served-by': [{
                key: 'X-Served-By',
                value: config.function_arn,
            }],
        },
        bodyEncoding: 'text',
        body: 'Something went wrong...',
    };
}

exports.handler = async (event, context) => {
    const request_config = event.Records[0].cf.config;
    console.log(`Handling ${request_config.eventType} for ${request_config.distributionId}: ` +
                `id=${request_config.requestId}`);

    const config = await get_config_promise(context);

    const request = event.Records[0].cf.request;
    const request_headers = request.headers;
    const hostname = request_headers.host[0].value;  // Host:-header is required, should always be present;
    console.log(`Processing request for Host: ${hostname}`);

    if( request.uri === config.set_cookie_path ) {
        console.log("Processing set-cookie request");

        const params = querystring.parse(request.querystring);
        let headers = {};

        const raw_token = params['access_token'];  // may be undefined
        if(raw_token === undefined) {
            console.log("No token present");
            return bad_request(config, request);
        }

        let token;
        try {
            token = await validate_token(config, raw_token, hostname);  // may throw
            const now = (new Date()) / 1000;
            if(token['iat'] < (now - 30) || token['iat'] > (now + 30)) {
                console.log("Token is issued more than 30 seconds from now");
                return bad_request(config, request);
            }
        } catch(e) {
            console.log("Token not valid");
            return bad_request(config, request);
        }
        const expire = (new Date(token['exp'] * 1000)).toUTCString();  // JavaScript works in milliseconds since epoch
        headers['set-cookie'] = [{
            key: 'Set-Cookie',
            value: `${config.cookie_name_access_token}=${raw_token}; expires=${expire}; Path=/; Secure; HttpOnly`,
        }];

        let redirect_uri;
        try {
            redirect_uri = new url.parse(params['redirect_uri']);  // may throw TypeError on undefined
        } catch(e) {
            return internal_server_error(config, e);
        }
        if(redirect_uri.hostname !== hostname) {
            console.log(`Token not valid for ${hostname}`);
            return bad_request(config, request);
        }
        headers['location'] = [{
            key: 'Location',
            value: redirect_uri.href,
        }];

        /* The Refer(r)er received by the next page may include the secret
         * access_token.
         * Normally, the browser keeps the original Refer(r)er after a
         * (server side) redirect.
         * This is added as an extra precaution.
         */
        headers['referrer-policy'] = [{
            key: 'Referrer-Policy',
            value: 'no-referrer',
        }];

        headers['x-served-by'] = [{
                key: 'X-Served-By',
                value: config.function_arn,
            }];

        console.log(`Issuing redirect to ${redirect_uri.href}, with Set-Cookie:-header`);
        return {
            status: '302',
            statusDescription: 'Found',
            headers: headers,
            bodyEncoding: 'text',
            body: 'Authorized, redirecting to page',
        };
    }

    const cookies = normalize_cookies(request_headers);
    // Don't log cookies for privacy reasons

    if(!(config.cookie_name_access_token in cookies)) {
        // Cookie not present. Redirect to authz
        console.log(`Could not find cookie with name "${config.cookie_name_access_token}"`);
        return redirect_auth(config, request, cookies);
    }

    const cookie_value = cookies[config.cookie_name_access_token];
    console.log(`Found cookie with name "${config.cookie_name_access_token}"`);  // don't log value

    try {
        const token = await validate_token(config, cookie_value, hostname);
        console.log("Access granted");
        console.log(token);  // Don't log signed token, but content only
    } catch(e) {
        if(e instanceof InvalidToken) return redirect_auth(config, request, cookies);
        else if(e instanceof BadToken) return bad_request(config, request);
        else return internal_server_error(config, e);
    }

    // Remove access_token from Cookie:-header
    delete cookies[config.cookie_name_access_token];
    request.headers['cookie'] = [{'key': 'Cookie', 'value': render_cookie_header_value(cookies)}];

    // Pass through request
    console.log("Passing through request");
    return request;
};
