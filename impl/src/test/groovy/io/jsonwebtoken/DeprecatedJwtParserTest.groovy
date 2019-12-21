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
import io.jsonwebtoken.impl.FixedClock
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.SignatureException
import org.junit.Test

import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

import static ClaimJwtException.INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE
import static ClaimJwtException.MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE
import static org.junit.Assert.*

class DeprecatedJwtParserTest {

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
    void testSetDuplicateSigningKeys() {

        byte[] keyBytes = randomKey()

        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256")

        String compact = Jwts.builder().setPayload('Hello World!').signWith(SignatureAlgorithm.HS256, keyBytes).compact()

        try {
            Jwts.parser().setSigningKey(keyBytes).setSigningKey(key).parse(compact)
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.getMessage(), 'A key object and key bytes cannot both be specified. Choose either.'
        }
    }

    @Test
    void testIsSignedWithNullArgument() {
        assertFalse Jwts.parser().isSigned(null)
    }

    @Test
    void testIsSignedWithJunkArgument() {
        assertFalse Jwts.parser().isSigned('hello')
    }

    @Test
    void testParseWithJunkArgument() {

        String junkPayload = '{;aklsjd;fkajsd;fkjasd;lfkj}'

        String bad = base64Url('{"alg":"none"}') + '.' + base64Url(junkPayload) + '.'

        try {
            Jwts.parser().parse(bad)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals expected.getMessage(), 'Unable to read JSON value: ' + junkPayload
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
            Jwts.parser().setSigningKey(randomKey()).parse(bad)
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
            Jwts.parserBuilder().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (SignatureException se) {
            assertEquals se.getMessage(), 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.'
        }

    }

    @Test
    void testParsePlaintextJwsWithIncorrectAlg() {

        def header = '{"alg":"none"}'

        def payload = '{"subject":"Joe"}'

        def badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(badSig)

        try {
            Jwts.parserBuilder().setSigningKey(randomKey()).build().parse(bad)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals se.getMessage(), 'JWT string has a digest/signature, but the header does not reference a valid signature algorithm.'
        }

    }

    @Test
    void testParseWithBase64EncodedSigningKey() {

        byte[] key = randomKey()

        String base64Encodedkey = Encoders.BASE64.encode(key)

        String payload = 'Hello world!'

        //noinspection GrDeprecatedAPIUsage
        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, base64Encodedkey).compact()

        assertTrue Jwts.parser().isSigned(compact)

        Jwt<Header, String> jwt = Jwts.parser().setSigningKey(base64Encodedkey).parse(compact)

        assertEquals jwt.body, payload
    }

    @Test
    void testParseWithExpiredJwt() {

        Date exp = new Date(System.currentTimeMillis() - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().parse(compact)
            fail()
        } catch (ExpiredJwtException e) {
            assertTrue e.getMessage().startsWith('JWT expired at ')

            //https://github.com/jwtk/jjwt/issues/107 (the Z designator at the end of the timestamp):
            assertTrue e.getMessage().contains('Z, a difference of ')
        }
    }

    @Test
    void testParseWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(nbf).compact()

        try {
            Jwts.parser().parse(compact)
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

        Jwt<Header, Claims> jwt = Jwts.parser().setAllowedClockSkewSeconds(10).parse(compact)

        assertEquals jwt.getBody().getSubject(), subject
    }

    @Test
    void testParseWithExpiredJwtNotWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() - 3000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().setAllowedClockSkewSeconds(1).parse(compact)
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

        Jwt<Header, Claims> jwt = Jwts.parser().setAllowedClockSkewSeconds(10).parse(compact)

        assertEquals jwt.getBody().getSubject(), subject
    }

    @Test
    void testParseWithPrematureJwtNotWithinAllowedClockSkew() {
        Date exp = new Date(System.currentTimeMillis() + 3000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(exp).compact()

        try {
            Jwts.parser().setAllowedClockSkewSeconds(1).parse(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
        }
    }

    // ========================================================================
    // parsePlaintextJwt tests
    // ========================================================================

    @Test
    void testParsePlaintextJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        Jwt<Header, String> jwt = Jwts.parser().parsePlaintextJwt(compact)

        assertEquals jwt.getBody(), payload
    }

    @Test
    void testParsePlaintextJwtWithClaimsJwt() {

        String compact = Jwts.builder().setSubject('Joe').compact()

        try {
            Jwts.parser().parsePlaintextJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned Claims JWTs are not supported.'
        }
    }

    @Test
    void testParsePlaintextJwtWithPlaintextJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed JWSs are not supported.'
        }
    }

    @Test
    void testParsePlaintextJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed JWSs are not supported.'
        }
    }

    // ========================================================================
    // parseClaimsJwt tests
    // ========================================================================

    @Test
    void testParseClaimsJwt() {

        String subject = 'Joe'

        String compact = Jwts.builder().setSubject(subject).compact()

        Jwt<Header, Claims> jwt = Jwts.parser().parseClaimsJwt(compact)

        assertEquals jwt.getBody().getSubject(), subject
    }

    @Test
    void testParseClaimsJwtWithPlaintextJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned plaintext JWTs are not supported.'
        }
    }

    @Test
    void testParseClaimsJwtWithPlaintextJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed JWSs are not supported.'
        }
    }

    @Test
    void testParseClaimsJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        try {
            Jwts.parser().parseClaimsJwt(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed JWSs are not supported.'
        }
    }

    @Test
    void testParseClaimsJwtWithExpiredJwt() {

        long nowMillis = System.currentTimeMillis()
        //some time in the past:
        Date exp = new Date(nowMillis - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        try {
            Jwts.parser().parseClaimsJwt(compact)
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
            Jwts.parser().parseClaimsJwt(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
        }
    }

    // ========================================================================
    // parsePlaintextJws tests
    // ========================================================================

    @Test
    void testParsePlaintextJws() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        Jwt<Header, String> jwt = Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

        assertEquals jwt.getBody(), payload
    }

    @Test
    void testParsePlaintextJwsWithPlaintextJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned plaintext JWTs are not supported.'
        }
    }

    @Test
    void testParsePlaintextJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned Claims JWTs are not supported.'
        }
    }

    @Test
    void testParsePlaintextJwsWithClaimsJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed Claims JWSs are not supported.'
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

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        assertEquals jwt.getBody().getSubject(), sub
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
            Jwts.parser().setSigningKey(key).parseClaimsJwt(compact)
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
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact)
            fail()
        } catch (PrematureJwtException e) {
            assertTrue e.getMessage().startsWith('JWT must not be accepted before ')
            assertEquals e.getClaims().getSubject(), sub
            assertEquals e.getHeader().getAlgorithm(), "HS256"
        }
    }

    @Test
    void testParseClaimsJwsWithPlaintextJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned plaintext JWTs are not supported.'
        }
    }

    @Test
    void testParseClaimsJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Unsigned Claims JWTs are not supported.'
        }
    }

    @Test
    void testParseClaimsJwsWithPlaintextJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            assertEquals e.getMessage(), 'Signed Claims JWSs are not supported.'
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

        Jws jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

        assertEquals jws.getBody().getSubject(), subject
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
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)
            fail()
        } catch (SignatureException se) {
            assertEquals se.getMessage(), 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.'
        }
    }

    @Test
    void testParseClaimsWithSigningKeyResolverAndKey() {

        String subject = 'Joe'

        SecretKeySpec key = new SecretKeySpec(randomKey(), "HmacSHA256")

        String compact = Jwts.builder().setSubject(subject).signWith(key, SignatureAlgorithm.HS256).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey()
            }
        }

        try {
            Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.getMessage(), 'A signing key resolver and a key object cannot both be specified. Choose either.'
        }
    }

    @Test
    void testParseClaimsWithSigningKeyResolverAndKeyBytes() {

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
            Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.getMessage(), 'A signing key resolver and key bytes cannot both be specified. Choose either.'
        }
    }

    @Test
    void testParseClaimsWithNullSigningKeyResolver() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        try {
            Jwts.parser().setSigningKeyResolver(null).parseClaimsJws(compact)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals iae.getMessage(), 'SigningKeyResolver cannot be null.'
        }
    }

    @Test
    void testParseClaimsWithInvalidSigningKeyResolverAdapter() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)
            fail()
        } catch (UnsupportedJwtException ex) {
            assertEquals ex.getMessage(), 'The specified SigningKeyResolver implementation does not support ' +
                    'Claims JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, Claims) method ' +
                    'or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, Claims) method.'
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

        Jwt<Header, Claims> jwt = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        Claims claims = jwt.getBody()

        assertEquals(b, claims.get("byte", Byte.class))
        assertEquals(s, claims.get("short", Short.class))
        assertEquals(i, claims.get("int", Integer.class))
        assertEquals(smallLong, claims.get("long_small", Long.class))
        assertEquals(bigLong, claims.get("long_big", Long.class))
    }

    // ========================================================================
    // parsePlaintextJws with signingKey resolver.
    // ========================================================================

    @Test
    void testParsePlaintextJwsWithSigningKeyResolverAdapter() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return key
            }
        }

        Jws<String> jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)

        assertEquals jws.getBody(), inputPayload
    }

    @Test
    void testParsePlaintextJwsWithSigningKeyResolverInvalidKey() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return randomKey()
            }
        }

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)
            fail()
        } catch (SignatureException se) {
            assertEquals se.getMessage(), 'JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.'
        }
    }

    @Test
    void testParsePlaintextJwsWithInvalidSigningKeyResolverAdapter() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        try {
            Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)
            fail()
        } catch (UnsupportedJwtException ex) {
            assertEquals ex.getMessage(), 'The specified SigningKeyResolver implementation does not support plaintext ' +
                    'JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, String) ' +
                    'method or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, String) method.'
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
            Jwts.parser().setSigningKey(key).require(null, expectedClaimValue).parseClaimsJws(compact)
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().get(expectedClaimName), expectedClaimValue
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, claimName, claimValue),
                    e.getMessage()
            )
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getIssuedAt().getTime(), truncateMillis(issuedAt)
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getIssuer(), issuer
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.ISSUER, issuer),
                    e.getMessage()
            )
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getAudience(), audience
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
                    parseClaimsJws(compact)
            fail()
        } catch (IncorrectClaimException e) {
            assertEquals(
                    String.format(INCORRECT_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.AUDIENCE, goodAudience, badAudience),
                    e.getMessage()
            )
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.AUDIENCE, audience),
                    e.getMessage()
            )
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getSubject(), subject
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.SUBJECT, subject),
                    e.getMessage()
            )
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getId(), id
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, Claims.ID, id),
                    e.getMessage()
            )
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getExpiration().getTime(), truncateMillis(expiration)
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().getNotBefore().getTime(), truncateMillis(notBefore)
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
                parseClaimsJws(compact)

        assertEquals jwt.getBody().get("aDate", Date.class), aDate
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
                    parseClaimsJws(compact)
            fail()
        } catch (MissingClaimException e) {
            assertEquals(
                    String.format(MISSING_EXPECTED_CLAIM_MESSAGE_TEMPLATE, "aDate", aDate),
                    e.getMessage()
            )
        }
    }

    @Test
    void testParseClockManipulationWithFixedClock() {
        def then = System.currentTimeMillis() - 1000
        Date expiry = new Date(then)
        Date beforeExpiry = new Date(then - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(expiry).compact()

        Jwts.parser().setClock(new FixedClock(beforeExpiry)).parse(compact)
    }

    @Test
    void testParseClockManipulationWithNullClock() {
        JwtParser parser = Jwts.parser();
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
            Jwts.parser().setClock(new DefaultClock()).parse(compact)
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
            Jwts.parser().setSigningKey(randomKey()).parse(bad)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'JWT strings must contain exactly 2 period characters. Found: 3', se.message
        }
    }

    @Test
    void testNoHeaderNoSig() {

        String payload = '{"subject":"Joe"}'

        String jwtStr = '.' + base64Url(payload) + '.'

        Jwt jwt = Jwts.parser().parse(jwtStr)

        assertTrue jwt.header == null
        assertEquals 'Joe', jwt.body.get('subject')
    }

    @Test
    void testNoHeaderSig() {

        String payload = '{"subject":"Joe"}'

        String sig = ";aklsjdf;kajsd;fkjas;dklfj"

        String jwtStr = '.' + base64Url(payload) + '.' + base64Url(sig)

        try {
            Jwts.parser().parse(jwtStr)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'JWT string has a digest/signature, but the header does not reference a valid signature algorithm.', se.message
        }
    }

    @Test
    void testBadHeaderSig() {

        String header = '{"alg":"none"}'

        String payload = '{"subject":"Joe"}'

        String sig = ";aklsjdf;kajsd;fkjas;dklfj"

        String jwtStr = base64Url(header) + '.' + base64Url(payload) + '.' + base64Url(sig)

        try {
            Jwts.parser().parse(jwtStr)
            fail()
        } catch (MalformedJwtException se) {
            assertEquals 'JWT string has a digest/signature, but the header does not reference a valid signature algorithm.', se.message
        }
    }

    /**
     * Date util method for lopping truncate the millis from a date.
     * @param date input date
     * @return The date time in millis with the precision of seconds
     */
    private long truncateMillis(Date date) {
        Calendar cal = Calendar.getInstance()
        cal.setTime(date)
        cal.set(Calendar.MILLISECOND, 0)
        return cal.getTimeInMillis()
    }
}
