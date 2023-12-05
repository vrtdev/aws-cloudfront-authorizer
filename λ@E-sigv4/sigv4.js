// Declare constants reqiured for the signature process
const crypto = require('crypto');
const qs = require('querystring');
// CloudFront includes the x-amz-cf-id header in the signature for custom origins
const signedHeaders = 'host;x-amz-cf-id;x-amz-content-sha256;x-amz-date;x-amz-security-token';
// Retrieve the temporary IAM credentials of the function that were granted by
// the Lambda@Edge service based on the function permissions.
const { AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN } = process.env;

// Since the function is configured to be executed on origin request events, the handler
// is executed every time CloudFront needs to go back to the origin.
exports.handler = async event => {
    //console.log("Event=" + JSON.stringify(event));
    
    // Retrieve the original request that CloudFront was going to send to API Gateway
    const request = event.Records[0].cf.request;

    // Create a JSON object with the fields that should be included in the Sigv4 request,
    // including the X-Amz-Cf-Id header that CloudFront adds to every request forwarded
    // upstream. This header is exposed to Lambda@Edge in the event object
    const sigv4Options = {
        method: request.method,
        path: request.origin.custom.path + request.uri, 
        query: request.querystring,
        credentials: {
            accessKeyId: AWS_ACCESS_KEY_ID,
            secretAccessKey: AWS_SECRET_ACCESS_KEY,
            sessionToken: AWS_SESSION_TOKEN
        },
        body: Buffer.from(request.body.data, 'base64').toString(),
        host: request.headers['host'][0].value,
        xAmzCfId: event.Records[0].cf.config.requestId
    };
            
    // Compute the signature object that includes the following headers: X-Amz-Security-Token, Authorization,
    // X-Amz-Date, X-Amz-Content-Sha256, and X-Amz-Security-Token
    const signature = signV4(sigv4Options);

    // Finally, add the signature headers to the request before it is sent to API Gateway
    for(var header in signature){
        request.headers[header.toLowerCase()] = [{
            key: header,
            value: signature[header].toString()
        }];
    }               
    return request;
};


// Helper functions to sign the request using AWS Signature Version 4
function signV4(options) {
    // Create the canonical request
    const region = options.host.split('.')[2];
    const date = (new Date()).toISOString().replace(/[:-]|\.\d{3}/g, '');
    const payloadHash = hash(options.body, 'hex');
    const canonicalHeaders = ['host:'+options.host,'x-amz-cf-id:'+options.xAmzCfId,'x-amz-content-sha256:'+payloadHash, 'x-amz-date:'+date, 'x-amz-security-token:'+options.credentials.sessionToken].join('\n');
    const canonicalQueryString = createCanonicalQS(options.query);
    const canonicalURI = encodeRfc3986(encodeURIComponent(decodeURIComponent(options.path).replace(/\+/g, ' ')).replace(/%2F/g, '/'));
    const canonicalRequest = [options.method, canonicalURI, canonicalQueryString, canonicalHeaders + '\n', signedHeaders, payloadHash].join('\n');
    //console.log("canonicalRequest="+canonicalRequest);
    
    // Create string to sign
    const credentialScope = [date.slice(0, 8), region, 'execute-api/aws4_request'].join('/');
    const stringToSign = ['AWS4-HMAC-SHA256', date, credentialScope, hash(canonicalRequest, 'hex')].join('\n');
    //console.log("stringToSign="+stringToSign);
    
    // Calculate the signature
    const signature = hmac(hmac(hmac(hmac(hmac('AWS4' + options.credentials.secretAccessKey, date.slice(0, 8)), region), "execute-api"), 'aws4_request'), stringToSign, 'hex');
    //console.log("signature="+signature);
    
    // Form the authorization header
    const authorizationHeader = ['AWS4-HMAC-SHA256 Credential=' + options.credentials.accessKeyId + '/' + credentialScope, 'SignedHeaders=' + signedHeaders, 'Signature=' + signature].join(', ');
    //console.log("authorizationHeader="+authorizationHeader);

    // return required headers for Sigv4 to be added to the request
    return {
        'Authorization': authorizationHeader,
        'X-Amz-Content-Sha256' : payloadHash,
        'X-Amz-Date': date,
        'X-Amz-Security-Token': options.credentials.sessionToken
    };
}

function createCanonicalQS(input_qs){
    let canonicalQS='';
    let qsparsed = qs.parse(input_qs);
    Object.keys(qsparsed).sort().forEach((param)=>{
        canonicalQS += encodeQS(param)+'='+encodeQS(qsparsed[param])+'&';
    });
    canonicalQS = canonicalQS.slice(0, -1);

    return canonicalQS;
}

function encodeQS(input_str){
    return input_str.replace(/[!'()*=]/g, c => '%' + c.charCodeAt(0).toString(16).toUpperCase());
}

function encodeRfc3986(urlEncodedStr) {
    return urlEncodedStr.replace(/[!'()*]/g, c => '%25' + c.charCodeAt(0).toString(16).toUpperCase());
}

function hash(string, encoding) {
    return crypto.createHash('sha256').update(string, 'utf8').digest(encoding);
}

function hmac(key, string, encoding) {
    return crypto.createHmac('sha256', key).update(string, 'utf8').digest(encoding);
}