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

import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import org.testng.annotations.Test

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom

import static org.testng.Assert.*

class JwtsTest {

    @Test
    void testHeaderWithNoArgs() {
        def header = Jwts.header()
        assertTrue header instanceof DefaultHeader
    }

    @Test
    void testHeaderWithMapArg() {
        def header = Jwts.header([alg: "HS256"])
        assertTrue header instanceof DefaultHeader
        assertEquals header.alg, 'HS256'
    }

    @Test
    void testJwsHeaderWithNoArgs() {
        def header = Jwts.jwsHeader()
        assertTrue header instanceof DefaultJwsHeader
    }

    @Test
    void testJwsHeaderWithMapArg() {
        def header = Jwts.jwsHeader([alg: "HS256"])
        assertTrue header instanceof DefaultJwsHeader
        assertEquals header.getAlgorithm(), 'HS256'
    }

    @Test
    void testClaims() {
        Claims claims = Jwts.claims()
        assertNotNull claims
    }

    @Test
    void testClaimsWithMapArg() {
        Claims claims = Jwts.claims([sub: 'Joe'])
        assertNotNull claims
        assertEquals claims.getSubject(), 'Joe'
    }

    @Test
    void testPlaintextJwtString() {

        // Assert exact output per example at https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25#section-6.1

        // The base64url encoding of the example claims set in the spec shows that their original payload ends lines with
        // carriage return + newline, so we have to include them in the test payload to assert our encoded output
        // matches what is in the spec:

        def payload = '{"iss":"joe",\r\n' +
                ' "exp":1300819380,\r\n' +
                ' "http://example.com/is_root":true}'

        String val = Jwts.builder().setPayload(payload).compact();

        def specOutput = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'

        assertEquals val, specOutput
    }

    @Test
    void testParsePlaintextToken() {

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).compact();

        def token = Jwts.parser().parse(jwt);

        assertEquals token.body, claims
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseNull() {
        Jwts.parser().parse(null)
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseEmptyString() {
        Jwts.parser().parse('')
    }

    @Test(expectedExceptions = IllegalArgumentException)
    void testParseWhitespaceString() {
        Jwts.parser().parse('   ')
    }

    @Test
    void testParseWithNoPeriods() {
        try {
            Jwts.parser().parse('foo')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT strings must contain exactly 2 period characters. Found: 0"
        }
    }

    @Test
    void testParseWithOnePeriodOnly() {
        try {
            Jwts.parser().parse('.')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT strings must contain exactly 2 period characters. Found: 1"
        }
    }

    @Test
    void testParseWithTwoPeriodsOnly() {
        try {
            Jwts.parser().parse('..')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string '..' is missing a body/payload."
        }
    }

    @Test
    void testParseWithHeaderOnly() {
        try {
            Jwts.parser().parse('foo..')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string 'foo..' is missing a body/payload."
        }
    }

    @Test
    void testParseWithSignatureOnly() {
        try {
            Jwts.parser().parse('..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string '..bar' is missing a body/payload."
        }
    }

    @Test
    void testParseWithHeaderAndSignatureOnly() {
        try {
            Jwts.parser().parse('foo..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals e.message, "JWT string 'foo..bar' is missing a body/payload."
        }
    }

    @Test
    void testConvenienceIssuer() {
        String compact = Jwts.builder().setIssuer("Me").compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        assertEquals claims.getIssuer(), "Me"

        compact = Jwts.builder().setSubject("Joe")
                .setIssuer("Me") //set it
                .setIssuer(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getIssuer()
    }

    @Test
    void testConvenienceSubject() {
        String compact = Jwts.builder().setSubject("Joe").compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        assertEquals claims.getSubject(), "Joe"

        compact = Jwts.builder().setIssuer("Me")
                .setSubject("Joe") //set it
                .setSubject(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getSubject()
    }

    @Test
    void testConvenienceAudience() {
        String compact = Jwts.builder().setAudience("You").compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        assertEquals claims.getAudience(), "You"

        compact = Jwts.builder().setIssuer("Me")
                .setAudience("You") //set it
                .setAudience(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getAudience()
    }

    private static Date now() {
        return dateWithOnlySecondPrecision(System.currentTimeMillis());
    }

    private static int later() {
        return laterDate().getTime() / 1000;
    }

    private static Date laterDate(int seconds) {
        return dateWithOnlySecondPrecision(System.currentTimeMillis() + (seconds * 1000));
    }

    private static Date laterDate() {
        return laterDate(10000);
    }

    private static Date dateWithOnlySecondPrecision(long millis) {
        long seconds = millis / 1000;
        long secondOnlyPrecisionMillis = seconds * 1000;
        return new Date(secondOnlyPrecisionMillis);
    }

    @Test
    void testConvenienceExpiration() {
        Date then = laterDate();
        String compact = Jwts.builder().setExpiration(then).compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        def claimedDate = claims.getExpiration()
        assertEquals claimedDate, then

        compact = Jwts.builder().setIssuer("Me")
                .setExpiration(then) //set it
                .setExpiration(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getExpiration()
    }

    @Test
    void testConvenienceNotBefore() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setNotBefore(now).compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        def claimedDate = claims.getNotBefore()
        assertEquals claimedDate, now

        compact = Jwts.builder().setIssuer("Me")
                .setNotBefore(now) //set it
                .setNotBefore(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getNotBefore()
    }

    @Test
    void testConvenienceIssuedAt() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setIssuedAt(now).compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        def claimedDate = claims.getIssuedAt()
        assertEquals claimedDate, now

        compact = Jwts.builder().setIssuer("Me")
                .setIssuedAt(now) //set it
                .setIssuedAt(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getIssuedAt()
    }

    @Test
    void testConvenienceId() {
        String id = UUID.randomUUID().toString();
        String compact = Jwts.builder().setId(id).compact();
        Claims claims = Jwts.parser().parse(compact).body as Claims
        assertEquals claims.getId(), id

        compact = Jwts.builder().setIssuer("Me")
                .setId(id) //set it
                .setId(null) //null should remove it
                .compact();

        claims = Jwts.parser().parse(compact).body as Claims
        assertNull claims.getId()
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

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).signWith(alg, privateKey).compact();

        def key = publicKey;
        if (verifyWithPrivateKey) {
            key = privateKey;
        }

        def token = Jwts.parser().setSigningKey(key).parse(jwt);

        assertEquals token.header, [alg: alg.name()]

        assertEquals token.body, claims

    }

    static void testHmac(SignatureAlgorithm alg) {
        //create random signing key for testing:
        Random random = new SecureRandom();
        byte[] key = new byte[64];
        random.nextBytes(key);

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).signWith(alg, key).compact();

        def token = Jwts.parser().setSigningKey(key).parse(jwt)

        assertEquals token.header, [alg: alg.name()]

        assertEquals token.body, claims
    }
}

