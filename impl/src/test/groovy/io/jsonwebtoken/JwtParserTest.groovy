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

import io.jsonwebtoken.impl.DefaultClock
import io.jsonwebtoken.impl.DefaultJwtParser
import io.jsonwebtoken.impl.FixedClock
import io.jsonwebtoken.impl.JwtTokenizer
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.SecretKey
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

import static io.jsonwebtoken.DateTestUtils.truncateMillis
import static io.jsonwebtoken.impl.DefaultJwtParser.INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE
import static io.jsonwebtoken.impl.DefaultJwtParser.MISSING_EXPECTED_CLAIM_VALUE_MESSAGE_TEMPLATE
import static org.junit.Assert.*

@SuppressWarnings('GrDeprecatedAPIUsage')
class JwtParserTest {

    private static final SecureRandom random = new SecureRandom() //doesn't need to be seeded - just testing

    protected static byte[] randomKey() {
        //create random signing key for testing:
        byte[] key = new byte[64]
        random.nextBytes(key)
        return key
    }

    protected static String base64Url(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8)
        return Encoders.BASE64URL.encode(bytes)
    }

    @Test
    void testIsSignedWithNullArgument() {
        assertFalse Jwts.parser().build().isSigned(null)
    }

    @Test
    void testIsSignedWithJunkArgument() {
        assertFalse Jwts.parser().build().isSigned('hello')
    }

    @Test
    void testParseWithJunkArgument() {

        String junkPayload = '{;aklsjd;fkajsd;fkjasd;lfkj}'

        String bad = base64Url('{"alg":"none"}') + '.' + base64Url(junkPayload) + '.'

        try {
            Jwts.parser().enableUnsecured().build().parse(bad)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals 'Unable to read claims JSON: ' + junkPayload, expected.getMessage()
        }
    }

    @Test
    void testParseJwsWithBadAlgHeader() {

        String badAlgorithmName = 'whatever'

        String header = "{\"alg\":\"$badAlgorithmName\"}"

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(badSig)

        try {
            Jwts.parser().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (SignatureException se) {
            assertEquals se.getMessage(), "Unsupported signature algorithm '$badAlgorithmName'".toString()
        }
    }

    @Test
    void testParseWithInvalidSignature() {

        String header = '{"alg":"HS256"}'

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(badSig)

        try {
            Jwts.parser().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (SignatureException se) {
            assertEquals se.getMessage(), 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.'
        }

    }

    @Test
    void testParseContentJwsWithIncorrectAlg() {

        def header = '{"alg":"none"}'

        def payload = '{"subject":"Joe"}'

        def badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(badSig)

        try {
            Jwts.parser().enableUnsecured().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'The JWS header references signature algorithm \'none\' yet the compact JWS string contains a signature. This is not permitted per https://tools.ietf.org/html/rfc7518#section-3.6.', se.getMessage()
        }

    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseUnsecuredJwsDefault() {
        // not signed - unsecured by default.  Parsing should be disabled automatically
        def header = '{"alg":"none"}'
        def payload = '{"subject":"Joe"}'
        String unsecured = base64Url(header) + '.' + base64Url(payload) + '.'
        try {
            Jwts.parser().build().parse(unsecured)
            fail()
        } catch (UnsupportedJwtException expected) {
            String msg = DefaultJwtParser.UNSECURED_DISABLED_MSG_PREFIX + '{alg=none}'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testParseWithBase64EncodedSigningKey() {

        byte[] key = randomKey()

        String base64Encodedkey = Encoders.BASE64.encode(key)

        String payload = 'Hello world!'

        //noinspection GrDeprecatedAPIUsage
        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, base64Encodedkey).compact()

        assertTrue Jwts.parser().build().isSigned(compact)

        def jwt = Jwts.parser().setSigningKey(base64Encodedkey).build().parse(compact)

        assertEquals payload, new String(jwt.payload as byte[], StandardCharsets.UTF_8)
    }

    @Test
    void testParseEmptyPayload() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String payload = ''

        String compact = Jwts.builder().setPayload(payload).signWith(key).compact()

        assertTrue Jwts.parser().build().isSigned(compact)

        def jwt = Jwts.parser().setSigningKey(key).build().parse(compact)

        assertEquals payload, new String(jwt.payload as byte[], StandardCharsets.UTF_8)
    }

    @Test
    void testParseNullPayload() {
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256)
        String compact = Jwts.builder().signWith(key).compact()
        assertTrue Jwts.parser().build().isSigned(compact)

        def jwt = Jwts.parser().setSigningKey(key).build().parse(compact)
        assertEquals '', new String(jwt.payload as byte[], StandardCharsets.UTF_8)
    }

    @Test
    void testParseNullPayloadWithoutKey() {
        String compact = Jwts.builder().compact()
        def jwt = Jwts.parser().enableUnsecured().build().parse(compact)
        assertEquals 'none', jwt.header.alg
        assertEquals '', new String(jwt.payload as byte[], StandardCharsets.UTF_8)
    }

    @Test
    void testParseWithExpiredJwt() {

        // Test with a fixed clock to assert full exception message
        long testTime = 1657552537573L
        Clock fixedClock = new FixedClock(testTime)

        Date exp = new Date(testTime - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().enableUnsecured().setClock(fixedClock).build().parse(compact)
            fail()
        } catch (ExpiredJwtException e) {
            // https://github.com/jwtk/jjwt/issues/107 (the Z designator at the end of the timestamp):
            // https://github.com/jwtk/jjwt/issues/660 (show differences as now - expired)
            assertEquals e.getMessage(), "JWT expired at 2022-07-11T15:15:36Z. Current time: " +
                    "2022-07-11T15:15:37Z, a difference of 1573 milliseconds.  Allowed clock skew: 0 milliseconds."
        }
    }

    @Test
    void testParseWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(nbf).compact()

        try {
            Jwts.parser().enableUnsecured().build().parse(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')

            //https://github.com/jwtk/jjwt/issues/107 (the Z designator at the end of the timestamp):
            assertTrue e.getMessage().contains('Z, a difference of ')
        }
    }

    @Test
    void testParseWithExpiredJwtWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() - 3000)

        String subject = 'Joe'
        String compact = Jwts.builder().setSubject(subject).setExpiration(exp).compact()

        Jwt<Header, Claims> jwt = Jwts.parser().enableUnsecured().setAllowedClockSkewSeconds(10).build().parse(compact)

        assertEquals jwt.getPayload().getSubject(), subject
    }

    @Test
    void testParseWithExpiredJwtNotWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() - 3000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().enableUnsecured().setAllowedClockSkewSeconds(1).build().parse(compact)
            fail()
        } catch (ExpiredJwtException e) {
            assertTrue e.getMessage().startsWith('JWT expired at ')
        }
    }

    @Test
    void testParseWithPrematureJwtWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() + 3000)

        String subject = 'Joe'
        String compact = Jwts.builder().setSubject(subject).setNotBefore(exp).compact()

        Jwt<Header, Claims> jwt = Jwts.parser().enableUnsecured().setAllowedClockSkewSeconds(10).build().parse(compact)

        assertEquals jwt.getPayload().getSubject(), subject
    }

    @Test
    void testParseWithPrematureJwtNotWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() + 3000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(exp).compact()

        try {
            Jwts.parser().enableUnsecured().setAllowedClockSkewSeconds(1).build().parse(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
        }
    }

    // ========================================================================
    // parseContentJwt tests
    // ========================================================================

    @Test
    void testParseContentJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        def jwt = Jwts.parser().enableUnsecured().build().parseContentJwt(compact)

        assertEquals payload, new String(jwt.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testParseContentJwtWithClaimsJwt() {

        String compact = Jwts.builder().setSubject('Joe').compact()

        try {
            Jwts.parser().enableUnsecured().build().parseContentJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unprotected Claims JWTs are not supported.'
        }
    }

    @Test
    void testParseContentJwtWithContentJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().build().parseContentJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Cannot verify JWS signature: unable to locate signature verification key for JWS with header: {alg=HS256}', e.getMessage()
        }
    }

    @Test
    void testParseContentJwtWithClaimsJws() {

        def key = randomKey()
        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed Claims JWTs are not supported.', e.getMessage()
        }
    }

    // ========================================================================
    // parseClaimsJwt tests
    // ========================================================================

    @Test
    void testParseClaimsJwt() {

        String subject = 'Joe'

        String compact = Jwts.builder().setSubject(subject).compact()

        Jwt<Header, Claims> jwt = Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)

        assertEquals jwt.getPayload().getSubject(), subject
    }

    @Test
    void testParseClaimsJwtWithContentJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseClaimsJwtWithContentJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().build().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Cannot verify JWS signature: unable to locate signature verification key for JWS with header: {alg=HS256}', e.getMessage()
        }
    }

    @Test
    void testParseClaimsJwtWithClaimsJws() {

        def key = randomKey()
        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed Claims JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseClaimsJwtWithExpiredJwt() {

        long nowMillis = System.currentTimeMillis()
        //some time in the past:
        Date exp = new Date(nowMillis - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)
            fail()
        } catch (ExpiredJwtException e) {
            assertTrue e.getMessage().startsWith('JWT expired at ')
        }
    }

    @Test
    void testParseClaimsJwtWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(nbf).compact()

        try {
            Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
        }
    }

    // ========================================================================
    // parseContentJws tests
    // ========================================================================

    @Test
    void testParseContentJws() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        def jwt = Jwts.parser().
                setSigningKey(key).
                build().
                parseContentJws(compact)

        assertEquals payload, new String(jwt.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testParseContentJwsWithContentJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseContentJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected Claims JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseContentJwsWithClaimsJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed Claims JWTs are not supported.', e.getMessage()
        }
    }

    // ========================================================================
    // parseClaimsJws tests
    // ========================================================================

    @Test
    void testParseClaimsJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(sub).signWith(SignatureAlgorithm.HS256, key).compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).build().parseClaimsJws(compact)

        assertEquals jwt.getPayload().getSubject(), sub
    }

    @Test
    void testParseClaimsJwsWithExpiredJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        long nowMillis = System.currentTimeMillis()
        //some time in the past:
        Date exp = new Date(nowMillis - 1000)

        String compact = Jwts.builder().setSubject(sub).signWith(SignatureAlgorithm.HS256, key).setExpiration(exp).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJwt(compact)
            fail()
        } catch (ExpiredJwtException e) {
            assertTrue e.getMessage().startsWith('JWT expired at ')
            assertEquals e.getClaims().getSubject(), sub
            assertEquals e.getHeader().getAlgorithm(), "HS256"
        }
    }

    @Test
    void testParseClaimsJwsWithPrematureJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject(sub).setNotBefore(nbf).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
            assertEquals e.getClaims().getSubject(), sub
            assertEquals e.getHeader().getAlgorithm(), "HS256"
        }
    }

    @Test
    void testParseClaimsJwsWithContentJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected content JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseClaimsJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Unprotected Claims JWTs are not supported.', e.getMessage()
        }
    }

    @Test
    void testParseClaimsJwsWithContentJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals 'Signed Claims JWTs are not supported.', e.getMessage()
        }
    }

    // ========================================================================
    // parseClaimsJws with signingKey resolver.
    // ========================================================================

    @Test
    void testParseClaimsWithSigningKeyResolver() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return key
            }
        }

        Jws jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(compact)

        assertEquals jws.getPayload().getSubject(), subject
    }

    @Test
    void testParseClaimsWithSigningKeyResolverInvalidKey() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey()
            }
        }

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(compact)
            fail()
        } catch (SignatureException se) {
            assertEquals 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.', se.getMessage()
        }
    }

    @Test
    void testParseClaimsWithNullSigningKeyResolver() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKeyResolver(null).build().parseClaimsJws(compact)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals 'SigningKeyResolver cannot be null.', iae.getMessage()
        }
    }

    @Test
    void testParseClaimsWithInvalidSigningKeyResolverAdapter() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException ex) {
            assertEquals 'The specified SigningKeyResolver implementation does not support ' +
                    'Claims JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, Claims) method ' +
                    'or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, Claims) method.', ex.getMessage()
        }
    }

    @Test
    void testParseClaimsJwsWithNumericTypes() {
        byte[] key = randomKey()

        def b = (byte) 42
        def s = (short) 42
        def i = 42

        def smallLong = (long) 42
        def bigLong = ((long) Integer.MAX_VALUE) + 42

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim("byte", b).
                claim("short", s).
                claim("int", i).
                claim("long_small", smallLong).
                claim("long_big", bigLong).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).build().parseClaimsJws(compact)

        Claims claims = jwt.getPayload()

        assertEquals(b, claims.get("byte", Byte.class))
        assertEquals(s, claims.get("short", Short.class))
        assertEquals(i, claims.get("int", Integer.class))
        assertEquals(smallLong, claims.get("long_small", Long.class))
        assertEquals(bigLong, claims.get("long_big", Long.class))
    }

    // ========================================================================
    // parseContentJws with signingKey resolver.
    // ========================================================================

    @Test
    void testParseContentJwsWithSigningKeyResolverAdapter() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, byte[] payload) {
                return key
            }
        }

        def jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseContentJws(compact)

        assertEquals inputPayload, new String(jws.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testParseContentJwsWithSigningKeyResolverInvalidKey() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, byte[] payload) {
                return randomKey()
            }
        }

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseContentJws(compact)
            fail()
        } catch (SignatureException se) {
            assertEquals 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.', se.getMessage()
        }
    }

    @Test
    void testParseContentJwsWithInvalidSigningKeyResolverAdapter() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).build().parseContentJws(compact)
            fail()
        } catch (UnsupportedJwtException ex) {
            assertEquals ex.getMessage(), 'The specified SigningKeyResolver implementation does not support content ' +
                    'JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, byte[]) ' +
                    'method or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, byte[]) method.'
        }
    }

    @Test
    void testParseRequireDontAllowNullClaimName() {
        def expectedClaimValue = 'A Most Awesome Claim Value'

        byte[] key = randomKey()

        // not setting expected claim name in JWT
        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).setIssuer('Dummy').compact()

        try {
            // expecting null claim name, but with value
            Jwts.parser().setSigningKey(key).require(null, expectedClaimValue).build().parseClaimsJws(compact)
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "claim name cannot be null or empty.",
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireDontAllowEmptyClaimName() {
        def expectedClaimValue = 'A Most Awesome Claim Value'

        byte[] key = randomKey()

        // not setting expected claim name in JWT
        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuer('Dummy').
                compact()

        try {
            // expecting null claim name, but with value
            Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                    require("", expectedClaimValue).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "claim name cannot be null or empty.",
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireDontAllowNullClaimValue() {
        def expectedClaimName = 'A Most Awesome Claim Name'

        byte[] key = randomKey()

        // not setting expected claim name in JWT
        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).setIssuer('Dummy').compact()

        try {
            // expecting claim name, but with null value
            Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                    require(expectedClaimName, null).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IllegalArgumentException e) {
            assertEquals(
                    "The value cannot be null for claim name: " + expectedClaimName,
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireGeneric_Success() {
        def expectedClaimName = 'A Most Awesome Claim Name'
        def expectedClaimValue = 'A Most Awesome Claim Value'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim(expectedClaimName, expectedClaimValue).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                require(expectedClaimName, expectedClaimValue).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().get(expectedClaimName), expectedClaimValue
    }

    @Test
    void testParseRequireGeneric_Incorrect_Fail() {
        def goodClaimName = 'A Most Awesome Claim Name'
        def goodClaimValue = 'A Most Awesome Claim Value'

        def badClaimValue = 'A Most Bogus Claim Value'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim(goodClaimName, badClaimValue).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    require(goodClaimName, goodClaimValue).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, goodClaimName, goodClaimValue, badClaimValue),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireedGeneric_Missing_Fail() {
        def claimName = 'A Most Awesome Claim Name'
        def claimValue = 'A Most Awesome Claim Value'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuer('Dummy').
                compact()

        try {
            Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                    require(claimName, claimValue).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing '$claimName' claim. Expected value: $claimValue"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testParseRequireIssuedAt_Success() {

        def issuedAt = new Date(System.currentTimeMillis())

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuedAt(issuedAt).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireIssuedAt(issuedAt).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getIssuedAt().getTime(), truncateMillis(issuedAt), 0
    }

    @Test(expected = IncorrectClaimException)
    void testParseRequireIssuedAt_Incorrect_Fail() {
        def goodIssuedAt = new Date(System.currentTimeMillis())
        def badIssuedAt = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuedAt(badIssuedAt).
                compact()

        Jwts.parser().setSigningKey(key).
                requireIssuedAt(goodIssuedAt).
                build().
                parseClaimsJws(compact)
    }

    @Test(expected = MissingClaimException)
    void testParseRequireIssuedAt_Missing_Fail() {
        def issuedAt = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject("Dummy").
                compact()

        Jwts.parser().setSigningKey(key).
                requireIssuedAt(issuedAt).
                build().
                parseClaimsJws(compact)
    }

    @Test
    void testParseRequireIssuer_Success() {
        def issuer = 'A Most Awesome Issuer'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuer(issuer).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireIssuer(issuer).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getIssuer(), issuer
    }

    @Test
    void testParseRequireIssuer_Incorrect_Fail() {
        def goodIssuer = 'A Most Awesome Issuer'
        def badIssuer = 'A Most Bogus Issuer'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuer(badIssuer).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireIssuer(goodIssuer).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.ISSUER, goodIssuer, badIssuer),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireIssuer_Missing_Fail() {
        def issuer = 'A Most Awesome Issuer'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setId('id').
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireIssuer(issuer).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing 'iss' claim. Expected value: $issuer"
            assertEquals msg, e.message
        }
    }

    @Test
    void testParseRequireAudience_Success() {
        def audience = 'A Most Awesome Audience'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setAudience(audience).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireAudience(audience).
                build().
                parseClaimsJws(compact)

        assertEquals audience, jwt.getPayload().getAudience().iterator().next()
    }

    @Test
    void testParseExpectedEqualAudiences() {
        def one = 'one'
        def two = 'two'
        def expected = [one, two]
        String jwt = Jwts.builder().audience(one).audience(two).compact()
        def aud = Jwts.parser().enableUnsecured().requireAudience(one).requireAudience(two).build()
                .parseClaimsJwt(jwt).getPayload().getAudience()
        assertEquals expected.size(), aud.size()
        assertTrue aud.containsAll(expected)
    }

    @Test
    void testParseAtLeastOneAudiences() {
        def one = 'one'

        String jwt = Jwts.builder().audience(one).audience('two').compact() // more audiences than required

        def aud = Jwts.parser().enableUnsecured().requireAudience(one) // require only one
                .build().parseClaimsJwt(jwt).getPayload().getAudience()

        assertNotNull aud
        assertTrue aud.contains(one)
    }

    @Test
    void testParseMissingAudiences() {
        def one = 'one'
        def two = 'two'
        String jwt = Jwts.builder().id('foo').compact()
        try {
            Jwts.parser().enableUnsecured().requireAudience(one).requireAudience(two).build().parseClaimsJwt(jwt)
            fail()
        } catch (MissingClaimException expected) {
            String msg = "Missing 'aud' claim. Expected values: [$one, $two]"
            assertEquals msg, expected.message
        }
    }

    @Test
    void testParseSingleValueClaimExpectingMultipleValues() {
        def one = 'one'
        def two = 'two'
        def expected = [one, two]
        String jwt = Jwts.builder().claim('custom', one).compact()
        try {
            Jwts.parser().enableUnsecured().require('custom', expected).build().parseClaimsJwt(jwt)
        } catch (IncorrectClaimException e) {
            String msg = "Missing expected '$two' value in 'custom' claim [$one]."
            assertEquals msg, e.message
        }
    }

    @Test
    void testParseRequireAudience_Incorrect_Fail() {
        def goodAudience = 'A Most Awesome Audience'
        def badAudience = 'A Most Bogus Audience'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setAudience(badAudience).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireAudience(goodAudience).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            String msg = String.format(MISSING_EXPECTED_CLAIM_VALUE_MESSAGE_TEMPLATE, goodAudience,
                    Claims.AUDIENCE, [badAudience])
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testParseRequireAudience_Missing_Fail() {
        def audience = 'A Most Awesome audience'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setId('id').
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireAudience(audience).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing 'aud' claim. Expected values: [$audience]"
            assertEquals msg, e.message
        }
    }

    @Test
    void testParseRequireSubject_Success() {
        def subject = 'A Most Awesome Subject'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject(subject).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireSubject(subject).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getSubject(), subject
    }

    @Test
    void testParseRequireSubject_Incorrect_Fail() {
        def goodSubject = 'A Most Awesome Subject'
        def badSubject = 'A Most Bogus Subject'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject(badSubject).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireSubject(goodSubject).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.SUBJECT, goodSubject, badSubject),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireSubject_Missing_Fail() {
        def subject = 'A Most Awesome Subject'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setId('id').
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireSubject(subject).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing 'sub' claim. Expected value: $subject"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testParseRequireId_Success() {
        def id = 'A Most Awesome id'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setId(id).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireId(id).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getId(), id
    }

    @Test
    void testParseRequireId_Incorrect_Fail() {
        def goodId = 'A Most Awesome Id'
        def badId = 'A Most Bogus Id'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setId(badId).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireId(goodId).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.ID, goodId, badId),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireId_Missing_Fail() {
        def id = 'A Most Awesome Id'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setIssuer('me').
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    requireId(id).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing 'jti' claim. Expected value: $id"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testParseRequireExpiration_Success() {
        // expire in the future
        def expiration = new Date(System.currentTimeMillis() + 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setExpiration(expiration).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireExpiration(expiration).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getExpiration().getTime(), truncateMillis(expiration)
    }

    @Test(expected = IncorrectClaimException)
    void testParseRequireExpirationAt_Incorrect_Fail() {
        def goodExpiration = new Date(System.currentTimeMillis() + 20000)
        def badExpiration = new Date(System.currentTimeMillis() + 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setExpiration(badExpiration).
                compact()

        Jwts.parser().setSigningKey(key).
                requireExpiration(goodExpiration).
                build().
                parseClaimsJws(compact)
    }

    @Test(expected = MissingClaimException)
    void testParseRequireExpiration_Missing_Fail() {
        def expiration = new Date(System.currentTimeMillis() + 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject("Dummy").
                compact()

        Jwts.parser().setSigningKey(key).
                requireExpiration(expiration).
                build().
                parseClaimsJws(compact)
    }

    @Test
    void testParseRequireNotBefore_Success() {
        // expire in the future
        def notBefore = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setNotBefore(notBefore).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                requireNotBefore(notBefore).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().getNotBefore().getTime(), truncateMillis(notBefore)
    }

    @Test(expected = IncorrectClaimException)
    void testParseRequireNotBefore_Incorrect_Fail() {
        def goodNotBefore = new Date(System.currentTimeMillis() - 20000)
        def badNotBefore = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setNotBefore(badNotBefore).
                compact()

        Jwts.parser().setSigningKey(key).
                requireNotBefore(goodNotBefore).
                build().
                parseClaimsJws(compact)
    }

    @Test(expected = MissingClaimException)
    void testParseRequireNotBefore_Missing_Fail() {
        def notBefore = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject("Dummy").
                compact()

        Jwts.parser().setSigningKey(key).
                requireNotBefore(notBefore).
                build().
                parseClaimsJws(compact)
    }

    @Test
    void testParseRequireCustomDate_Success() {

        def aDate = new Date(System.currentTimeMillis())

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim("aDate", aDate).
                compact()

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).
                require("aDate", aDate).
                build().
                parseClaimsJws(compact)

        assertEquals jwt.getPayload().get("aDate", Date.class), aDate
    }

    @Test
    //since 0.10.0
    void testParseRequireCustomDateWhenClaimIsNotADate() {

        def goodDate = new Date(System.currentTimeMillis())
        def badDate = 'hello'

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim("aDate", badDate).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    require("aDate", goodDate).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            String expected = 'JWT Claim \'aDate\' was expected to be a Date, but its value cannot be converted to a ' +
                    'Date using current heuristics.  Value: hello'
            assertEquals expected, e.getMessage()
        }
    }

    @Test
    void testParseRequireCustomDate_Incorrect_Fail() {

        def goodDate = new Date(System.currentTimeMillis())
        def badDate = new Date(System.currentTimeMillis() - 10000)

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                claim("aDate", badDate).
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    require("aDate", goodDate).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, "aDate", goodDate, badDate),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseRequireCustomDate_Missing_Fail() {
        def aDate = new Date(System.currentTimeMillis())

        byte[] key = randomKey()

        String compact = Jwts.builder().signWith(SignatureAlgorithm.HS256, key).
                setSubject("Dummy").
                compact()

        try {
            Jwts.parser().setSigningKey(key).
                    require("aDate", aDate).
                    build().
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            String msg = "Missing 'aDate' claim. Expected value: $aDate"
            assertEquals msg, e.getMessage()
        }
    }

    @Test
    void testParseClockManipulationWithFixedClock() {
        def then = System.currentTimeMillis() - 1000
        Date expiry = new Date(then)
        Date beforeExpiry = new Date(then - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(expiry).compact()

        Jwts.parser().enableUnsecured().setClock(new FixedClock(beforeExpiry)).build().parse(compact)
    }

    @Test
    void testParseClockManipulationWithNullClock() {
        JwtParserBuilder parser = Jwts.parser();
        try {
            parser.setClock(null)
            fail()
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    void testParseClockManipulationWithDefaultClock() {
        Date expiry = new Date(System.currentTimeMillis() - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(expiry).compact()

        try {
            Jwts.parser().enableUnsecured().setClock(new DefaultClock()).build().parse(compact)
            fail()
        } catch (ExpiredJwtException e) {
            assertTrue e.getMessage().startsWith('JWT expired at ')
        }
    }

    @Test
    void testParseMalformedJwt() {

        String header = '{"alg":"none"}'

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bogus = 'bogus'

        String bad = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(badSig) + '.' + base64Url(bogus)

        try {
            Jwts.parser().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (MalformedJwtException se) {
            String expected = JwtTokenizer.DELIM_ERR_MSG_PREFIX + '3'
            assertEquals expected, se.message
        }
    }

    @Test
    void testNoHeaderNoSig() {

        String payload = '{"subject":"Joe"}'

        String jwtStr = '.' + base64Url(payload) + '.'

        try {
            Jwts.parser().build().parse(jwtStr)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals 'Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).', e.getMessage()
        }
    }

    @Test
    void testNoHeaderSig() {

        String payload = '{"subject":"Joe"}'

        String sig = ";aklsjdf;kajsd;fkjas;dklfj"

        String jwtStr = '.' + base64Url(payload) + '.' + base64Url(sig)

        try {
            Jwts.parser().build().parse(jwtStr)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).', se.message
        }
    }

    @Test
    void testBadHeaderSig() {

        String header = '{"alg":"none"}'

        String payload = '{"subject":"Joe"}'

        String sig = ";aklsjdf;kajsd;fkjas;dklfj"

        String jwtStr = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(sig)

        try {
            Jwts.parser().enableUnsecured().build().parse(jwtStr)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'The JWS header references signature algorithm \'none\' yet the compact JWS string contains a signature. This is not permitted per https://tools.ietf.org/html/rfc7518#section-3.6.', se.message
        }
    }
}
