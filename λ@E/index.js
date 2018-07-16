"use strict";

const jwt = require('jsonwebtoken');

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

exports.handler = (event, context, callback) => {
    const request = event.Records[0].cf.request;
    const request_headers = request.headers;

    const cookies = normalize_cookies(request_headers);
    if(cookies['foo'] === 'bar') {  // TODO: actually check JWT
        // Pass on request to origin
        callback(null, request);

    } else {
        callback(null, {
            status: '302',
            statusDescription: 'Found',
            headers: {
                'location': [{
                    key: 'Location',
                    value: 'https://www.vrt.be/',  // TODO: make parameter
                }],
            },
            bodyEncoding: 'text',
            body: 'Not authorized, redirecting to authorization server',
        });
    }
};
