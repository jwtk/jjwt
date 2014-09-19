/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken

import org.testng.annotations.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

import static org.testng.Assert.*

class JWTsTest {

    @Test
    void testPlaintextJwtString() {

        // Assert exact output per example at https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1

        // The base64url encoding of the example claims set in the spec shows that their original payload ends lines with
        // carriage return + newline, so we have to include them in the test payload to assert our encoded output
        // matches what is in the spec:

        def payload = '{"iss":"joe",\r\n' +
                ' "exp":1300819380,\r\n' +
                ' "http://example.com/is_root":true}'

        String val = JWTs.builder().setPayload(payload).compact();

        def specOutput = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'

        assertEquals val, specOutput
    }

    @Test
    void testParsePlaintextToken() {

        def claims = [iss: 'joe', exp: 1300819380, 'http://example.com/is_root':true]

        String jwt = JWTs.builder().setClaims(claims).compact();

        def token = JWTs.parser().parse(jwt);

        assertEquals token.body, claims
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseNull() {
        JWTs.parser().parse(null)
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseEmptyString() {
        JWTs.parser().parse('')
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseWhitespaceString() {
        JWTs.parser().parse('   ')
    }

    @Test
    void testParseWithNoPeriods() {
        try {
            JWTs.parser().parse('foo')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT strings must contain exactly 2 period characters. Found: 0"
        }
    }

    @Test
    void testParseWithOnePeriodOnly() {
        try {
            JWTs.parser().parse('.')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT strings must contain exactly 2 period characters. Found: 1"
        }
    }

    @Test
    void testParseWithTwoPeriodsOnly() {
        try {
            JWTs.parser().parse('..')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string '..' is missing a body/payload."
        }
    }

    @Test
    void testParseWithHeaderOnly() {
        try {
            JWTs.parser().parse('foo..')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string 'foo..' is missing a body/payload."
        }
    }

    @Test
    void testParseWithSignatureOnly() {
        try {
            JWTs.parser().parse('..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string '..bar' is missing a body/payload."
        }
    }

    @Test
    void testParseWithHeaderAndSignatureOnly() {
        try {
            JWTs.parser().parse('foo..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string 'foo..bar' is missing a body/payload."
        }
    }

    @Test
    void testHS256() {
        testHmac(SignatureAlgorithm.HS256);
    }

    @Test
    void testHS384() {
        testHmac(SignatureAlgorithm.HS384);
    }

    @Test
    void testHS512() {
        testHmac(SignatureAlgorithm.HS512);
    }

    @Test
    void testRS256() {
        testRsa(SignatureAlgorithm.RS256);
    }

    @Test
    void testRS384() {
        testRsa(SignatureAlgorithm.RS384);
    }

    @Test
    void testRS512() {
        testRsa(SignatureAlgorithm.RS512);
    }

    @Test
    void testPS256() {
        testRsa(SignatureAlgorithm.PS256);
    }

    @Test
    void testPS384() {
        testRsa(SignatureAlgorithm.PS384);
    }

    @Test
    void testPS512() {
        testRsa(SignatureAlgorithm.PS512, 2048, false);
    }

    @Test
    void testRSA256WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithm.RS256, 1024, true);
    }

    @Test
    void testRSA384WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithm.RS384, 1024, true);
    }

    @Test
    void testRSA512WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithm.RS512, 1024, true);
    }

    static void testRsa(SignatureAlgorithm alg) {
        testRsa(alg, 1024, false);
    }

    static void testRsa(SignatureAlgorithm alg, int keySize, boolean verifyWithPrivateKey) {

        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
        keyGenerator.initialize(keySize);

        KeyPair kp = keyGenerator.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        def claims = [iss: 'joe', exp: 1300819380, 'http://example.com/is_root':true]

        String jwt = JWTs.builder().setClaims(claims).signWith(alg, privateKey).compact();

        def key = publicKey;
        if (verifyWithPrivateKey) {
            key = privateKey;
        }

        def token = JWTs.parser().setSigningKey(key).parse(jwt);

        assertEquals token.header, [alg: alg.name()]

        assertEquals token.body, claims

    }

    static void testHmac(SignatureAlgorithm alg) {
        //create random signing key for testing:
        Random random = new SecureRandom();
        byte[] key = new byte[64];
        random.nextBytes(key);

        def claims = [iss: 'joe', exp: 1300819380, 'http://example.com/is_root':true]

        String jwt = JWTs.builder().setClaims(claims).signWith(alg, key).compact();

        def token = JWTs.parser().setSigningKey(key).parse(jwt)

        assertEquals token.header, [alg: alg.name()]

        assertEquals token.body, claims
    }
}

