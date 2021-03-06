const assert = require('assert');
const rewire = require('../λ@E/node_modules/rewire');
const lae = rewire('../λ@E/index.js');
const JWT = require('../λ@E/node_modules/jsonwebtoken');


lae.__set__('get_config_bucket', async function(context) { return 'dummy' });
lae.__set__('asyncS3GetObject', async function(param) { return '{}' });
lae.__set__('get_jwt_secret_promise', async function(region, param_name) { return 'secret'; });


function base64url(string, encoding) {
    return Buffer
        .from(string, encoding)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}


describe('UTF8', function() {
    describe('encode', function() {
        it('should decode 0x41 to `A`', function() {
            assert.equal( lae.__get__('decode_utf8')("\x41"), "A" );
        });
        it('should decode 0xE2 0x9C 0x93 to `✓`', function() {
            assert.equal( lae.__get__('decode_utf8')("\xe2\x9c\x93"), "✓" );
        });
    });
    describe('decode', function() {
        it('should encode `A` to 0x41', function () {
           assert.equal( lae.__get__('encode_utf8')("A"), "\x41");
        });
        it('should encode `✓` to 0xE2 0x9C 0x93', function () {
            assert.equal( lae.__get__('encode_utf8')("✓"), "\xe2\x9c\x93");
        });
    })
});

describe('get_config', function() {
    it('should return defaults', async function() {

        const get_config_promise = lae.__get__('get_config_promise');
        const config = await get_config_promise({'invokedFunctionArn': 'foobar'});
        assert.notEqual(config, {});
    })
});

describe('get_jwt_secret', function() {
    it('should return a value', async function() {
        const secret = await lae.__get__('get_jwt_secret_promise')();
        assert.equal(secret, 'secret');
    });
});

describe('validate_token', function() {
    it('should throw for null token', async function() {
        const config = await lae.__get__('get_config_promise')();

        try {
            token = await lae.__get__('validate_token')(config, null, 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // Ignore
        }
    });

    it('should throw for empty token', async function() {
        const config = await lae.__get__('get_config_promise')();

        try {
            token = await lae.__get__('validate_token')(config, '', 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // Ignore
        }
    });

    it('should throw for invalid token', async function() {
        const config = await lae.__get__('get_config_promise')();

        try {
            token = await lae.__get__('validate_token')(config, 'a.b.c', 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // Ignore
        }
    });

    it('should return a valid token', async function() {
        const config = await lae.__get__('get_config_promise')();

        const now = Math.floor((new Date()) / 1000);
        let in_token = {
            'iat': now,
            'exp': now + 5,
            'domains': ['example.org'],
        };
        const signed_token = JWT.sign(
            in_token,
            'secret',
            {
                "algorithm": "HS256"
            }
        );

        const out_token = await lae.__get__('validate_token')(config, signed_token, 'example.org');

        assert.deepEqual(in_token, out_token);
    });

    it('should check expiration', async function() {
        const config = await lae.__get__('get_config_promise')();

        const now = Math.floor((new Date()) / 1000);
        let in_token = {
            'iat': now - 10,
            'exp': now - 5,
            'domains': ['example.org'],
        };
        const signed_token = JWT.sign(
            in_token,
            'secret',
            {
                "algorithm": "HS256"
            }
        );

        try {
            const out_token = await lae.__get__('validate_token')(config, signed_token, 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // pass
        }
    });

    it('should check domain', async function() {
        const config = await lae.__get__('get_config_promise')();

        const now = Math.floor((new Date()) / 1000);
        let in_token = {
            'iat': now,
            'exp': now + 5,
            'domains': ['example.com'],
        };
        const signed_token = JWT.sign(
            in_token,
            'secret',
            {
                "algorithm": "HS256"
            }
        );

        try {
            const out_token = await lae.__get__('validate_token')(config, signed_token, 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // pass
        }
    });

    it('should check algorithm', async function() {
        const config = await lae.__get__('get_config_promise')();

        const now = Math.floor((new Date()) / 1000);
        let in_token = {
            'iat': now,
            'exp': now + 5,
            'domains': ['example.com'],
        };
        const unsigned_token =
            base64url(JSON.stringify({
                "typ": "JWT",
                "alg": "None",
            }), 'utf-8') + '.' +
            base64url(JSON.stringify(in_token), 'utf-8') + '.' +
            '';  // empty signature

        try {
            const out_token = await lae.__get__('validate_token')(config, unsigned_token, 'example.org');
            assert.fail("Should have thrown");
        } catch(e) {
            // pass
        }
    });
});

describe('handler', function() {
    let request = {
        'headers': {
            'host': [{
                key: 'Host',
                value: 'example.org',
            }],
        },
    };
    let cf_event = {
        'Records': [{
            'cf': {
                'config': {
                    'eventType': 'test',
                    'distributionId': 'E1234',
                    'requestId': 'abc',
                },
                'request': request,
            },
        }],
    };
    describe('set-cookie', function() {
        it('should redirect with Set-Cookie', async function() {
            const now = Math.floor((new Date()) / 1000);
            let in_token = {
                'iat': now,
                'exp': now + 5,
                'domains': ['example.org'],
            };
            const signed_token = JWT.sign(
                in_token,
                'secret',
                {
                    "algorithm": "HS256"
                }
            );

            request.uri = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie';
            request.querystring = `access_token=${signed_token}&redirect_uri=http%3a%2f%2fexample.org%2f`;

            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, 302);
            assert.notEqual(response.headers['set-cookie'][0], null);
            assert.notEqual(response.headers['location'][0], null);
        });

        it('should 400 without token', async function() {
            request.uri = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie';
            request.querystring = '';
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, 400);
        });
        it('should 400 without valid token', async function() {
            request.uri = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie';
            request.querystring = 'token=a.b.c';
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, 400);
        });
        it('should 500 without a redirect_uri', async function() {
            const now = Math.floor((new Date()) / 1000);
            let in_token = {
                'iat': now,
                'exp': now + 5,
                'domains': ['example.org'],
            };
            const signed_token = JWT.sign(
                in_token,
                'secret',
                {
                    "algorithm": "HS256"
                }
            );

            request.uri = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie';
            request.querystring = `access_token=${signed_token}`;
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, 500);
        });

        it('should 400 on redirect_uri mismatch', async function() {
            const now = Math.floor((new Date()) / 1000);
            let in_token = {
                'iat': now,
                'exp': now + 5,
                'domains': ['example.org'],
            };
            const signed_token = JWT.sign(
                in_token,
                'secret',
                {
                    "algorithm": "HS256"
                }
            );

            request.uri = '/auth-89CE3FEF-FCF6-43B3-9DBA-7C410CAAE220/set-cookie';
            request.querystring = `access_token=${signed_token}&redirect_uri=http%3a%2f%2fexample.com%2f`;

            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, 400);
            assert.equal(response.headers['set-cookie'], null);
        });
    });

    describe('validate cookie', function() {
        it('should pass through valid requests', async function() {
            const config = await lae.__get__('get_config_promise')();

            const now = Math.floor((new Date()) / 1000);
            let in_token = {
                'iat': now,
                'exp': now + 5,
                'domains': ['example.org'],
            };
            const signed_token = JWT.sign(
                in_token,
                'secret',
                {
                    "algorithm": "HS256"
                }
            );

            request.uri = '/whatever';
            request.querystring = '';
            request.headers['cookie'] = [{
                key: 'Cookie',
                value: `${config.cookie_name_access_token}=${signed_token}`,
            }];
            request.tag = 'foobar';

            const response = await lae.handler(cf_event, {});
            assert.equal(response, request);
        });
    });

    describe('redirect logic', function () {
        it('should redirect when not logged in', async function() {
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, "302");
        });

        it('should not redirect when asked not to', async function() {
            const config = await lae.__get__('get_config_promise')();

            request.headers['cookie'] = [{
                key: 'Cookie',
                value: `${config.cookie_name_no_redirect}=whatever_not_checked`,
            }];
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, "401");
        });

        it('should not redirect when asked not to, invalid cookie case', async function() {
            const config = await lae.__get__('get_config_promise')();

            const now = Math.floor((new Date()) / 1000);
            let in_token = {
                'iat': now,
                'exp': now + 5,
                'domains': ['example.org'],
            };
            const signed_token = JWT.sign(
                in_token,
                'bad_secret',
                {
                    "algorithm": "HS256"
                }
            );

            request.headers['cookie'] = [{
                key: 'Cookie',
                value: `${config.cookie_name_no_redirect}=whatever_not_checked; ` +
                    `${config.cookie_name_access_token}=${signed_token}`,
            }];
            const response = await lae.handler(cf_event, {});
            assert.equal(response.status, "401");
        });
    });
});
