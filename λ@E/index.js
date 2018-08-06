/*
 * Should be run at the Viewer Request state.
 *
 * The alternative would be to hook on Origin Request. This has the advantage of caching the "no cookie"-case, but
 * causes all browsers to effectively have their own private cache on CloudFront. This hides potential bugs when the
 * CloudFront configuration would cause users to see each other's cached pages.
 *
 * Hence, we want to run on Viewer Request, this has the least amount of influence on the remaining flow.
 */

"use strict";
const JWT = require('jsonwebtoken');
const AWS = require('aws-sdk');

// TODO: these should not be hard coded
const verify_access_url = 'https://authorizer.sandbox.a51.be/verify_access';
const cookie_name = 'VRT_authorizer_access';
const parameter_store_region = 'eu-west-1';
const parameter_store_parameter_name = '/laukenn-authz/jwt-secret';


let jwt_secret_callbacks = [];
let jwt_secret = null;
function get_jwt_secret_nocache(cb) {
    let ssm = new AWS.SSM({'region': parameter_store_region});
    const params = {
        Name: parameter_store_parameter_name,
        WithDecryption: true,
    };
    ssm.getParameter(params, function(err, data) {
        if( err !== null ) {
            cb(err, data);
        } else {
            cb(null, data['Parameter']['Value']);
        }
    });
}
function get_jwt_secret(header, cb) {
    if( jwt_secret !== null ) {
        cb(null, jwt_secret);
    } else {
        jwt_secret_callbacks.push(cb);
        get_jwt_secret_nocache(function(err, data) {
            if( err === null ) {
                jwt_secret = data;
            }
            for( const cb of jwt_secret_callbacks ) {
                cb(err, data);
            }
            jwt_secret_callbacks = [];
        });
    }
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
        cookies[decode_utf8(t[0])] = decode_utf8(t[1]);
    }

    return cookies;
}

function get_host(request) {
    return request.headers.host[0].value;  // Host:-header is required, should always be present
}

function has_valid_cookie(request, cb) {
    const request_headers = request.headers;
    const cookies = normalize_cookies(request_headers);

    if(!(cookie_name in cookies)) {
        // Cookie not present. Redirect to authz
        cb(null, false);
        return;
    }

    const cookie_value = cookies[cookie_name];

    JWT.verify(
        cookie_value,
        get_jwt_secret,
        {
            "algorithms": ["HS256"],
        },
        function(err, token) {
            if( err !== null ) {
                console.log("JWT validation failed: " + err);
                // Hide validation error for security reasons
                // Assume expired cookie, redirect to authz
                cb(null, false);
                return;
            }
            console.log("JWT validated: " + JSON.stringify(token));

            if( !('iat' in token) ||
                !('exp' in token) ||  // exp is checked by JWT.verify(), but not required to be present
                !('domains' in token)
            ) {
                console.log("JWT is malformed");
                // Token is invalid. Assume bad intend and return 400 (instead of redirect to authz)
                cb('Bad token', false, 400);
                return;
            }

            let hostname = get_host(request);
            if(token['domains'].indexOf(hostname) === -1) {
                console.log(`Hostname '${hostname}' not in allowed list`);
                // Token is invalid for this domain. Assume bad intend and return 400 (instead of redirect to authz)
                cb('Bad token', false, 400);
                return;
            }

            console.log("Allowing access");
            cb(err, true);
        },
    );
}

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;

    has_valid_cookie(request, function(err, cookie_is_valid, status='500') {
        if( err !== null ) {
            callback(null, {
                status: status,
                statusDescription: 'Internal Server Error',
                headers: {},
                bodyEncoding: 'text',
                body: err.toString(),
            });

        } else if(cookie_is_valid) {
            // Pass on request to origin
            callback(null, request);

        } else {
            // Not authorized, redirect
            let return_url = `https://${get_host(request)}${request.uri}`;
            if(request.querystring !== '') {
                return_url += '?' + request.querystring;
            }

            callback(null, {
                status: '302',
                statusDescription: 'Found',
                headers: {
                    'location': [{
                        key: 'Location',
                        value: `${verify_access_url}?return_to=${encodeURIComponent(return_url)}`,
                    }],
                },
                bodyEncoding: 'text',
                body: 'Not authorized, redirecting to authorization server',
            });
        }
    });
};
