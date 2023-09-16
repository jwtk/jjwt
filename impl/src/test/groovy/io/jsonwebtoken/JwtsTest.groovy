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

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.*
import io.jsonwebtoken.impl.compression.GzipCompressionAlgorithm
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.*
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.*
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

import static org.junit.Assert.*

class JwtsTest {

    private static Date now() {
        return dateWithOnlySecondPrecision(System.currentTimeMillis())
    }

    private static int later() {
        def date = laterDate(10000)
        def seconds = date.getTime() / 1000
        return seconds as int
    }

    private static Date laterDate(int seconds) {
        def millis = seconds * 1000L
        def time = System.currentTimeMillis() + millis
        return dateWithOnlySecondPrecision(time)
    }

    private static Date dateWithOnlySecondPrecision(long millis) {
        long seconds = (millis / 1000) as long
        long secondOnlyPrecisionMillis = seconds * 1000
        return new Date(secondOnlyPrecisionMillis)
    }

    protected static String base64Url(String s) {
        byte[] bytes = s.getBytes(Strings.UTF_8)
        return Encoders.BASE64URL.encode(bytes)
    }

    protected static String toJson(o) {
        def serializer = Services.loadFirst(Serializer)
        byte[] bytes = serializer.serialize(o)
        return new String(bytes, Strings.UTF_8)
    }

    @Test
    void testPrivateCtor() { // for code coverage only
        //noinspection GroovyAccessibility
        new Jwts()
    }

    @Test
    void testHeaderWithNoArgs() {
        def header = Jwts.header().build()
        assertTrue header instanceof DefaultHeader
    }

    @Test
    void testHeaderWithMapArg() {
        def header = Jwts.header().add([alg: "HS256"]).build()
        assertTrue header instanceof DefaultJwsHeader
        assertEquals 'HS256', header.getAlgorithm()
        assertEquals 'HS256', header.alg
    }

    @Test
    void testClaims() {
        Claims claims = Jwts.claims().build()
        assertNotNull claims
    }

    @Test
    void testClaimsWithMapArg() {
        Claims claims = Jwts.claims([sub: 'Joe'])
        assertNotNull claims
        assertEquals 'Joe', claims.getSubject()
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseMalformedHeader() {
        def headerString = '{"jku":42}' // cannot be parsed as a URI --> malformed header
        def claimsString = '{"sub":"joe"}'
        def encodedHeader = base64Url(headerString)
        def encodedClaims = base64Url(claimsString)
        def compact = encodedHeader + '.' + encodedClaims + '.AAD='
        try {
            Jwts.parser().build().parseClaimsJws(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Invalid protected header: Invalid JWS header \'jku\' (JWK Set URL) value: 42. ' +
                    'Values must be either String or java.net.URI instances. Value type found: java.lang.Integer.'
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseMalformedClaims() {
        def key = TestKeys.HS256
        def h = base64Url('{"alg":"HS256"}')
        def c = base64Url('{"sub":"joe","exp":"-42-"}')
        def payload = ("$h.$c" as String).getBytes(StandardCharsets.UTF_8)
        def request = new DefaultSecureRequest<byte[], SecretKey>(payload, null, null, key)
        def result = Jwts.SIG.HS256.digest(request)
        def sig = Encoders.BASE64URL.encode(result)
        def compact = "$h.$c.$sig" as String
        try {
            Jwts.parser().setSigningKey(key).build().parseClaimsJws(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Invalid claims: Invalid JWT Claim \'exp\' (Expiration Time) value: -42-. ' +
                    'String value is not a JWT NumericDate, nor is it ISO-8601-formatted. All heuristics exhausted. ' +
                    'Cause: Unparseable date: "-42-"'
            assertEquals expected, e.getMessage()
        }
    }

    @Test
    void testContentJwtString() {
        // Assert exact output per example at https://www.rfc-editor.org/rfc/rfc7519.html#section-6.1
        String encodedBody = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        String payload = new String(Decoders.BASE64URL.decode(encodedBody), StandardCharsets.UTF_8)
        String val = Jwts.builder().setPayload(payload).compact()
        String RFC_VALUE = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        assertEquals RFC_VALUE, val
    }

    @Test
    void testSetContentWithContentType() {
        String s = 'Hello JJWT'
        String cty = 'text/plain'
        String compact = Jwts.builder().content(s.getBytes(StandardCharsets.UTF_8), cty).compact()
        def jwt = Jwts.parser().enableUnsecured().build().parseContentJwt(compact)
        assertEquals cty, jwt.header.getContentType()
        assertEquals s, new String(jwt.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testSetContentWithApplicationContentType() {
        String s = 'Hello JJWT'
        String subtype = 'foo'
        String cty = "application/$subtype"
        String compact = Jwts.builder().content(s.getBytes(StandardCharsets.UTF_8), cty).compact()
        def jwt = Jwts.parser().enableUnsecured().build().parseContentJwt(compact)
        // assert raw value is compact form:
        assertEquals subtype, jwt.header.get('cty')
        // assert getter reflects normalized form per https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.10:
        assertEquals cty, jwt.header.getContentType()
        assertEquals s, new String(jwt.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testSetContentWithNonCompactApplicationContentType() {
        String s = 'Hello JJWT'
        String subtype = 'foo'
        String cty = "application/$subtype;part=1/2"
        String compact = Jwts.builder().content(s.getBytes(StandardCharsets.UTF_8), cty).compact()
        def jwt = Jwts.parser().enableUnsecured().build().parseContentJwt(compact)
        assertEquals cty, jwt.header.getContentType() // two slashes, can't compact
        assertEquals s, new String(jwt.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testParseContentToken() {

        def claims = [iss: 'joe', exp: later(), 'https://example.com/is_root': true]

        String jwt = Jwts.builder().claims().add(claims).and().compact()

        def token = Jwts.parser().enableUnsecured().build().parse(jwt)

        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.payload == claims
    }

    @Test(expected = IllegalArgumentException)
    void testParseNull() {
        Jwts.parser().build().parse(null)
    }

    @Test(expected = IllegalArgumentException)
    void testParseEmptyString() {
        Jwts.parser().build().parse('')
    }

    @Test(expected = IllegalArgumentException)
    void testParseWhitespaceString() {
        Jwts.parser().build().parse('   ')
    }

    @Test
    void testParseClaimsWithLeadingAndTrailingWhitespace() {
        String whitespaceChars = ' \t \n \r '
        String claimsJson = whitespaceChars + '{"sub":"joe"}' + whitespaceChars

        String header = Encoders.BASE64URL.encode('{"alg":"none"}'.getBytes(StandardCharsets.UTF_8))
        String claims = Encoders.BASE64URL.encode(claimsJson.getBytes(StandardCharsets.UTF_8))

        String compact = header + '.' + claims + '.'
        def jwt = Jwts.parser().enableUnsecured().build().parseClaimsJwt(compact)
        assertEquals 'none', jwt.header.getAlgorithm()
        assertEquals 'joe', jwt.payload.getSubject()
    }

    @Test
    void testParseWithNoPeriods() {
        try {
            Jwts.parser().build().parse('foo')
            fail()
        } catch (MalformedJwtException e) {
            //noinspection GroovyAccessibility
            String expected = JwtTokenizer.DELIM_ERR_MSG_PREFIX + '0'
            assertEquals expected, e.message
        }
    }

    @Test
    void testParseWithOnePeriodOnly() {
        try {
            Jwts.parser().build().parse('.')
            fail()
        } catch (MalformedJwtException e) {
            //noinspection GroovyAccessibility
            String expected = JwtTokenizer.DELIM_ERR_MSG_PREFIX + '1'
            assertEquals expected, e.message
        }
    }

    @Test
    void testParseWithTwoPeriodsOnly() {
        try {
            Jwts.parser().build().parse('..')
            fail()
        } catch (MalformedJwtException e) {
            String msg = 'Compact JWT strings MUST always have a Base64Url protected header per ' +
                    'https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).'
            assertEquals msg, e.message
        }
    }

    @Test
    void testParseWithHeaderOnly() {
        String unsecuredJwt = base64Url("{\"alg\":\"none\"}") + ".."
        Jwt jwt = Jwts.parser().enableUnsecured().build().parse(unsecuredJwt)
        assertEquals "none", jwt.getHeader().get("alg")
    }

    @Test
    void testParseWithSignatureOnly() {
        try {
            Jwts.parser().build().parse('..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals 'Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).', e.message
        }
    }

    @Test
    void testParseWithMissingRequiredSignature() {
        Key key = Jwts.SIG.HS256.key().build()
        String compact = Jwts.builder().setSubject('foo').signWith(key).compact()
        int i = compact.lastIndexOf('.')
        String missingSig = compact.substring(0, i + 1)
        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parseClaimsJws(missingSig)
            fail()
        } catch (MalformedJwtException expected) {
            String s = String.format(DefaultJwtParser.MISSING_JWS_DIGEST_MSG_FMT, 'HS256')
            assertEquals s, expected.getMessage()
        }
    }

    @Test
    void testWithInvalidCompressionAlgorithm() {
        try {
            Jwts.builder().header().add('zip', 'CUSTOM').and().id("andId").compact()
        } catch (CompressionException e) {
            assertEquals "Unsupported compression algorithm 'CUSTOM'", e.getMessage()
        }
    }

    @Test
    void testConvenienceIssuer() {
        String compact = Jwts.builder().setIssuer("Me").compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertEquals 'Me', claims.getIssuer()

        compact = Jwts.builder().setSubject("Joe")
                .setIssuer("Me") //set it
                .setIssuer(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getIssuer()
    }

    @Test
    void testConvenienceSubject() {
        String compact = Jwts.builder().setSubject("Joe").compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertEquals 'Joe', claims.getSubject()

        compact = Jwts.builder().setIssuer("Me")
                .setSubject("Joe") //set it
                .setSubject(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getSubject()
    }

    @Test
    void testConvenienceAudience() {
        String compact = Jwts.builder().setAudience("You").compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertEquals 'You', claims.getAudience().iterator().next()

        compact = Jwts.builder().setIssuer("Me")
                .setAudience("You") //set it
                .setAudience(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getAudience()
    }

    @Test
    void testConvenienceExpiration() {
        Date then = laterDate(10000)
        String compact = Jwts.builder().setExpiration(then).compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        def claimedDate = claims.getExpiration()
        assertEquals then, claimedDate

        compact = Jwts.builder().setIssuer("Me")
                .setExpiration(then) //set it
                .setExpiration(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getExpiration()
    }

    @Test
    void testConvenienceNotBefore() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setNotBefore(now).compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        def claimedDate = claims.getNotBefore()
        assertEquals now, claimedDate

        compact = Jwts.builder().setIssuer("Me")
                .setNotBefore(now) //set it
                .setNotBefore(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getNotBefore()
    }

    @Test
    void testConvenienceIssuedAt() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setIssuedAt(now).compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        def claimedDate = claims.getIssuedAt()
        assertEquals now, claimedDate

        compact = Jwts.builder().setIssuer("Me")
                .setIssuedAt(now) //set it
                .setIssuedAt(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getIssuedAt()
    }

    @Test
    void testConvenienceId() {
        String id = UUID.randomUUID().toString()
        String compact = Jwts.builder().setId(id).compact()
        Claims claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertEquals id, claims.getId()

        compact = Jwts.builder().setIssuer("Me")
                .setId(id) //set it
                .setId(null) //null should remove it
                .compact()

        claims = Jwts.parser().enableUnsecured().build().parse(compact).payload as Claims
        assertNull claims.getId()
    }

    @Test
    void testUncompressedJwt() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().id(id).issuer("an issuer").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compact()

        def jws = Jwts.parser().verifyWith(key).build().parseClaimsJws(compact)

        Claims claims = jws.payload

        assertNull jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an issuer", claims.getIssuer()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithDeflate() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().id(id).issuer("an issuer").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(Jwts.ZIP.DEF).compact()

        def jws = Jwts.parser().verifyWith(key).build().parseClaimsJws(compact)

        Claims claims = jws.payload

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an issuer", claims.getIssuer()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithGZIP() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().id(id).issuer("an issuer").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(Jwts.ZIP.GZIP).compact()

        def jws = Jwts.parser().verifyWith(key).build().parseClaimsJws(compact)

        Claims claims = jws.payload

        assertEquals "GZIP", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an issuer", claims.getIssuer()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedWithCustomResolver() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().id(id).issuer("an issuer").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionAlgorithm() {
            @Override
            String getId() {
                return "CUSTOM"
            }
        }).compact()

        def jws = Jwts.parser().verifyWith(key).setCompressionCodecResolver(new CompressionCodecResolver() {
            @Override
            CompressionCodec resolveCompressionCodec(Header header) throws CompressionException {
                String algorithm = header.getCompressionAlgorithm()
                //noinspection ChangeToOperator
                if ("CUSTOM".equals(algorithm)) {
                    return Jwts.ZIP.GZIP as CompressionCodec
                } else {
                    return null
                }
            }
        }).build().parseClaimsJws(compact)

        Claims claims = jws.payload

        assertEquals "CUSTOM", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an issuer", claims.getIssuer()
        assertEquals "hello this is an amazing jwt", claims.state

    }

    @Test(expected = UnsupportedJwtException.class)
    void testCompressedJwtWithUnrecognizedHeader() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionAlgorithm() {
            @Override
            String getId() {
                return "CUSTOM"
            }
        }).compact()

        Jwts.parser().setSigningKey(key).build().parseClaimsJws(compact)
    }

    @Test
    void testCompressStringPayloadWithDeflate() {

        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String payload = "this is my test for a payload"

        String compact = Jwts.builder().setPayload(payload).signWith(key, alg)
                .compressWith(Jwts.ZIP.DEF).compact()

        def jws = Jwts.parser().setSigningKey(key).build().parseContentJws(compact)

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals "this is my test for a payload", new String(jws.payload, StandardCharsets.UTF_8)
    }

    @Test
    void testHS256() {
        testHmac(Jwts.SIG.HS256)
    }

    @Test
    void testHS384() {
        testHmac(Jwts.SIG.HS384)
    }

    @Test
    void testHS512() {
        testHmac(Jwts.SIG.HS512)
    }

    @Test
    void testRS256() {
        testRsa(Jwts.SIG.RS256)
    }

    @Test
    void testRS384() {
        testRsa(Jwts.SIG.RS384)
    }

    @Test
    void testRS512() {
        testRsa(Jwts.SIG.RS512)
    }

    @Test
    void testPS256() {
        testRsa(Jwts.SIG.PS256)
    }

    @Test
    void testPS384() {
        testRsa(Jwts.SIG.PS384)
    }

    @Test
    void testPS512() {
        testRsa(Jwts.SIG.PS512)
    }

    @Test
    void testES256() {
        testEC(Jwts.SIG.ES256)
    }

    @Test
    void testES384() {
        testEC(Jwts.SIG.ES384)
    }

    @Test
    void testES512() {
        testEC(Jwts.SIG.ES512)
    }

    @Test
    void testEdDSA() {
        testEC(Jwts.SIG.EdDSA)
    }

    @Test
    void testEd25519() {
        testEC(Jwts.SIG.EdDSA, TestKeys.forAlgorithm(Jwks.CRV.Ed25519).pair)
    }

    @Test
    void testEd448() {
        testEC(Jwts.SIG.EdDSA, TestKeys.forAlgorithm(Jwks.CRV.Ed448).pair)
    }

    @Test
    void testES256WithPrivateKeyValidation() {
        def alg = Jwts.SIG.ES256
        try {
            testEC(alg, true)
            fail("EC private keys cannot be used to validate EC signatures.")
        } catch (IllegalArgumentException e) {
            assertEquals DefaultJwtParser.PRIV_KEY_VERIFY_MSG, e.getMessage()
        }
    }

    @Test(expected = WeakKeyException)
    void testParseClaimsJwsWithWeakHmacKey() {

        def alg = Jwts.SIG.HS384
        def key = alg.key().build()
        def weakKey = Jwts.SIG.HS256.key().build()

        String jws = Jwts.builder().setSubject("Foo").signWith(key, alg).compact()

        Jwts.parser().setSigningKey(weakKey).build().parseClaimsJws(jws)
        fail('parseClaimsJws must fail for weak keys')
    }

    /**
     * @since 0.11.5
     */
    @Test
    void testBuilderWithEcdsaPublicKey() {
        def builder = Jwts.builder().setSubject('foo')
        def pair = TestKeys.ES256.pair
        try {
            builder.signWith(pair.public, SignatureAlgorithm.ES256) //public keys can't be used to create signatures
        } catch (InvalidKeyException expected) {
            String msg = "ECDSA signing keys must be PrivateKey instances."
            assertEquals msg, expected.getMessage()
        }
    }

    /**
     * @since 0.11.5 as part of testing guards against JVM CVE-2022-21449
     */
    @Test
    void testBuilderWithMismatchedEllipticCurveKeyAndAlgorithm() {
        def builder = Jwts.builder().setSubject('foo')
        def pair = TestKeys.ES384.pair
        try {
            builder.signWith(pair.private, SignatureAlgorithm.ES256)
            //ES384 keys can't be used to create ES256 signatures
        } catch (InvalidKeyException expected) {
            String msg = "EllipticCurve key has a field size of 48 bytes (384 bits), but ES256 requires a " +
                    "field size of 32 bytes (256 bits) per [RFC 7518, Section 3.4 (validation)]" +
                    "(https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4)."
            assertEquals msg, expected.getMessage()
        }
    }

    /**
     * @since 0.11.5 as part of testing guards against JVM CVE-2022-21449
     */
    @Test
    void testParserWithMismatchedEllipticCurveKeyAndAlgorithm() {
        def pair = TestKeys.ES256.pair
        def jws = Jwts.builder().setSubject('foo').signWith(pair.private).compact()
        def parser = Jwts.parser().setSigningKey(TestKeys.ES384.pair.public).build()
        try {
            parser.parseClaimsJws(jws)
        } catch (UnsupportedJwtException expected) {
            String msg = 'The parsed JWT indicates it was signed with the \'ES256\' signature algorithm, but ' +
                    'the provided sun.security.ec.ECPublicKeyImpl key may not be used to verify ES256 signatures.  ' +
                    'Because the specified key reflects a specific and expected algorithm, and the JWT does not ' +
                    'reflect this algorithm, it is likely that the JWT was not expected and therefore should not ' +
                    'be trusted.  Another possibility is that the parser was provided the incorrect signature ' +
                    'verification key, but this cannot be assumed for security reasons.'
            assertEquals msg, expected.getMessage()
        }
    }

    /**
     * @since 0.11.5 as part of testing guards against JVM CVE-2022-21449
     */
    @Test(expected = io.jsonwebtoken.security.SignatureException)
    void testEcdsaInvalidSignatureValue() {
        def withoutSignature = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCIsImlhdCI6MTQ2NzA2NTgyN30"
        def invalidEncodedSignature = "_____wAAAAD__________7zm-q2nF56E87nKwvxjJVH_____AAAAAP__________vOb6racXnoTzucrC_GMlUQ"
        String jws = withoutSignature + '.' + invalidEncodedSignature
        def keypair = Jwts.SIG.ES256.keyPair().build()
        Jwts.parser().setSigningKey(keypair.public).build().parseClaimsJws(jws)
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testParseClaimsJwsWithUnsignedJwt() {

        //create random signing key for testing:
        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        String notSigned = Jwts.builder().setSubject("Foo").compact()

        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parseClaimsJws(notSigned)
            fail('parseClaimsJws must fail for unsigned JWTs')
        } catch (UnsupportedJwtException expected) {
            assertEquals 'Unprotected Claims JWTs are not supported.', expected.message
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweMissingAlg() {
        def h = base64Url('{"enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.ecek.iv.' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals DefaultJwtParser.MISSING_JWE_ALG_MSG, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweEmptyAlg() {
        def h = base64Url('{"alg":"","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.ecek.iv.' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals DefaultJwtParser.MISSING_JWE_ALG_MSG, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWhitespaceAlg() {
        def h = base64Url('{"alg":"  ","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.ecek.iv.' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals DefaultJwtParser.MISSING_JWE_ALG_MSG, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithNoneAlg() {
        def h = base64Url('{"alg":"none","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.ecek.iv.' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals DefaultJwtParser.JWE_NONE_MSG, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithMissingAadTag() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.ecek.iv.' + c + '.'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = String.format(DefaultJwtParser.MISSING_JWE_DIGEST_MSG_FMT, 'dir')
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithEmptyAadTag() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        // our decoder skips invalid Base64Url characters, so this decodes to empty which is not allowed:
        def tag = '&'
        def compact = h + '.IA==.IA==.' + c + '.' + tag
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Compact JWE strings must always contain an AAD Authentication Tag.'
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithMissingRequiredBody() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def compact = h + '.ecek.iv..tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Compact JWE strings MUST always contain a payload (ciphertext).'
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithEmptyEncryptedKey() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        // our decoder skips invalid Base64Url characters, so this decodes to empty which is not allowed:
        def encodedKey = '&'
        def compact = h + '.' + encodedKey + '.iv.' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Compact JWE string represents an encrypted key, but the key is empty.'
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithMissingInitializationVector() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def compact = h + '.IA==..' + c + '.tag'
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            String expected = 'Compact JWE strings must always contain an Initialization Vector.'
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithMissingEncHeader() {
        def h = base64Url('{"alg":"dir"}')
        def c = base64Url('{"sub":"joe"}')
        def ekey = 'IA=='
        def iv = 'IA=='
        def tag = 'IA=='
        def compact = "$h.$ekey.$iv.$c.$tag" as String
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (MalformedJwtException e) {
            assertEquals DefaultJwtParser.MISSING_ENC_MSG, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithUnrecognizedEncValue() {
        def h = base64Url('{"alg":"dir","enc":"foo"}')
        def c = base64Url('{"sub":"joe"}')
        def ekey = 'IA=='
        def iv = 'IA=='
        def tag = 'IA=='
        def compact = "$h.$ekey.$iv.$c.$tag" as String
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            String expected = "Unrecognized JWE 'enc' (Encryption Algorithm) header value: foo"
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithUnrecognizedAlgValue() {
        def h = base64Url('{"alg":"bar","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def ekey = 'IA=='
        def iv = 'IA=='
        def tag = 'IA=='
        def compact = "$h.$ekey.$iv.$c.$tag" as String
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            String expected = "Unrecognized JWE 'alg' (Algorithm) header value: bar"
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJwsWithUnrecognizedAlgValue() {
        def h = base64Url('{"alg":"bar"}')
        def c = base64Url('{"sub":"joe"}')
        def sig = 'IA=='
        def compact = "$h.$c.$sig" as String
        try {
            Jwts.parser().build().parseClaimsJws(compact)
            fail()
        } catch (io.jsonwebtoken.security.SignatureException e) {
            String expected = "Unsupported signature algorithm 'bar'"
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithUnlocatableKey() {
        def h = base64Url('{"alg":"dir","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def ekey = 'IA=='
        def iv = 'IA=='
        def tag = 'IA=='
        def compact = "$h.$ekey.$iv.$c.$tag" as String
        try {
            Jwts.parser().build().parseClaimsJwe(compact)
            fail()
        } catch (UnsupportedJwtException e) {
            String expected = "Cannot decrypt JWE payload: unable to locate key for JWE with header: {alg=dir, enc=A128GCM}"
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJwsWithCustomSignatureAlgorithm() {
        def realAlg = Jwts.SIG.HS256 // any alg will do, we're going to wrap it
        def key = TestKeys.HS256
        def id = realAlg.getId() + 'X' // custom id
        def alg = new MacAlgorithm() {
            @Override
            SecretKeyBuilder key() {
                return realAlg.key()
            }

            @Override
            int getKeyBitLength() {
                return realAlg.keyBitLength
            }

            @Override
            byte[] digest(SecureRequest<byte[], SecretKey> request) {
                return realAlg.digest(request)
            }

            @Override
            boolean verify(VerifySecureDigestRequest<SecretKey> request) {
                return realAlg.verify(request)
            }

            @Override
            String getId() {
                return id
            }
        }

        def jws = Jwts.builder().setSubject("joe").signWith(key, alg).compact()

        assertEquals 'joe', Jwts.parser()
                .addSignatureAlgorithms([alg])
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jws).payload.getSubject()
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithCustomEncryptionAlgorithm() {
        def realAlg = Jwts.ENC.A128GCM // any alg will do, we're going to wrap it
        def key = realAlg.key().build()
        def enc = realAlg.getId() + 'X' // custom id
        def encAlg = new AeadAlgorithm() {
            @Override
            AeadResult encrypt(AeadRequest request) throws SecurityException {
                return realAlg.encrypt(request)
            }

            @Override
            Message<byte[]> decrypt(DecryptAeadRequest request) throws SecurityException {
                return realAlg.decrypt(request)
            }

            @Override
            String getId() {
                return enc
            }

            @Override
            SecretKeyBuilder key() {
                return realAlg.key()
            }

            @Override
            int getKeyBitLength() {
                return realAlg.getKeyBitLength()
            }
        }

        def jwe = Jwts.builder().setSubject("joe").encryptWith(key, encAlg).compact()

        assertEquals 'joe', Jwts.parser()
                .addEncryptionAlgorithms([encAlg])
                .decryptWith(key)
                .build()
                .parseClaimsJwe(jwe).payload.getSubject()
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseJweWithBadKeyAlg() {
        def alg = 'foo'
        def h = base64Url('{"alg":"foo","enc":"A128GCM"}')
        def c = base64Url('{"sub":"joe"}')
        def ekey = 'IA=='
        def iv = 'IA=='
        def tag = 'IA=='
        def compact = "$h.$ekey.$iv.$c.$tag" as String

        def badKeyAlg = new KeyAlgorithm() {
            @Override
            KeyResult getEncryptionKey(KeyRequest request) throws SecurityException {
                return null
            }

            @Override
            SecretKey getDecryptionKey(DecryptionKeyRequest request) throws SecurityException {
                return null // bad implementation here - returns null, and that's not good
            }

            @Override
            String getId() {
                return alg
            }
        }

        try {
            Jwts.parser()
                    .keyLocator(new ConstantKeyLocator(TestKeys.HS256, TestKeys.A128GCM))
                    .addKeyAlgorithms([badKeyAlg]) // <-- add bad alg here
                    .build()
                    .parseClaimsJwe(compact)
            fail()
        } catch (IllegalStateException e) {
            String expected = "The 'foo' JWE key algorithm did not return a decryption key. " +
                    "Unable to perform 'A128GCM' decryption."
            assertEquals expected, e.getMessage()
        }
    }

    /**
     * @since JJWT_RELEASE_VERSION
     */
    @Test
    void testParseRequiredInt() {
        def key = TestKeys.HS256
        def jws = Jwts.builder().signWith(key).claim("foo", 42).compact()
        Jwts.parser().setSigningKey(key)
                .require("foo", 42L) //require a long, but jws contains int, should still work
                .build().parseClaimsJws(jws)
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testForgedTokenWithSwappedHeaderUsingNoneAlgorithm() {

        //create random signing key for testing:
        def alg = Jwts.SIG.HS256
        SecretKey key = alg.key().build()

        //this is a 'real', valid JWT:
        String compact = Jwts.builder().setSubject("Joe").signWith(key, alg).compact()

        //Now strip off the signature so we can add it back in later on a forged token:
        int i = compact.lastIndexOf('.')
        String signature = compact.substring(i + 1)

        //now let's create a fake header and payload with whatever we want (without signing):
        String forged = Jwts.builder().setSubject("Not Joe").compact()

        //assert that our forged header has a 'NONE' algorithm:
        assertEquals 'none', Jwts.parser().enableUnsecured().build().parseClaimsJwt(forged).getHeader().get('alg')

        //now let's forge it by appending the signature the server expects:
        forged += signature

        //now assert that, when the server tries to parse the forged token, parsing fails:
        try {
            Jwts.parser().enableUnsecured().setSigningKey(key).build().parse(forged)
            fail("Parsing must fail for a forged token.")
        } catch (MalformedJwtException expected) {
            assertEquals 'The JWS header references signature algorithm \'none\' yet the compact JWS string contains a signature. This is not permitted per https://tools.ietf.org/html/rfc7518#section-3.6.', expected.message
        }
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20 and https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedRsaPublicKeyAsHmacTokenVerifiedWithTheRsaPrivateKey() {

        //Create a legitimate RSA public and private key pair:
        KeyPair kp = TestKeys.RS256.pair
        PublicKey publicKey = kp.getPublic()
        PrivateKey privateKey = kp.getPrivate()

        String header = base64Url(toJson(['alg': 'HS256']))
        String body = base64Url(toJson('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the RSA public key to sign a token, but
        // using it as an HMAC signing key instead of RSA:
        Mac mac = Mac.getInstance('HmacSHA256')
        byte[] raw = ((RSAPublicKey) publicKey).getModulus().toByteArray()
        if (raw.length > 256) {
            raw = Arrays.copyOfRange(raw, 1, raw.length)
        }
        mac.init(new SecretKeySpec(raw, 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the server does not recognized the forged token:
        try {
            Jwts.parser().verifyWith(publicKey).build().parse(forged)
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    //Asserts correct behavior for https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedRsaPublicKeyAsHmacTokenVerifiedWithTheRsaPublicKey() {

        //Create a legitimate RSA public and private key pair:
        KeyPair kp = TestKeys.RS256.pair
        PublicKey publicKey = kp.getPublic()
        //PrivateKey privateKey = kp.getPrivate();

        String header = base64Url(toJson(['alg': 'HS256']))
        String body = base64Url(toJson('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the RSA public key to sign a token, but
        // using it as an HMAC signing key instead of RSA:
        Mac mac = Mac.getInstance('HmacSHA256')
        byte[] raw = ((RSAPublicKey) publicKey).getModulus().toByteArray()
        if (raw.length > 256) {
            raw = Arrays.copyOfRange(raw, 1, raw.length)
        }
        mac.init(new SecretKeySpec(raw, 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parser().setSigningKey(publicKey).build().parse(forged)
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    //Asserts correct behavior for https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedEllipticCurvePublicKeyAsHmacToken() {

        //Create a legitimate EC public and private key pair:
        KeyPair kp = TestKeys.ES256.pair
        PublicKey publicKey = kp.getPublic()
        //PrivateKey privateKey = kp.getPrivate();

        String header = base64Url(toJson(['alg': 'HS256']))
        String body = base64Url(toJson('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the Elliptic Curve public key to sign a token, but
        // using it as an HMAC signing key instead of Elliptic Curve:
        Mac mac = Mac.getInstance('HmacSHA256')
        byte[] raw = ((ECPublicKey) publicKey).getParams().getOrder().toByteArray()
        if (raw.length > 32) {
            raw = Arrays.copyOfRange(raw, 1, raw.length)
        }
        mac.init(new SecretKeySpec(raw, 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parser().setSigningKey(publicKey).build().parse(forged)
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    @Test
    void testSecretKeyJwes() {

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it instanceof DirectKeyAlgorithm || it instanceof SecretKeyAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        for (KeyAlgorithm alg : algs) {

            for (AeadAlgorithm enc : Jwts.ENC.get().values()) {

                SecretKey key = alg instanceof SecretKeyAlgorithm ?
                        ((SecretKeyAlgorithm) alg).key().build() :
                        enc.key().build()

                // encrypt:
                String jwe = Jwts.builder()
                        .claim('foo', 'bar')
                        .encryptWith(key, alg, enc)
                        .compact()

                //decrypt:
                def jwt = Jwts.parser()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getPayload().get('foo')
            }
        }
    }

    @Test
    void testJweCompression() {

        def codecs = [Jwts.ZIP.DEF, Jwts.ZIP.GZIP]

        for (CompressionCodec codec : codecs) {

            for (AeadAlgorithm enc : Jwts.ENC.get().values()) {

                SecretKey key = enc.key().build()

                // encrypt and compress:
                String jwe = Jwts.builder()
                        .claim('foo', 'bar')
                        .compressWith(codec)
                        .encryptWith(key, enc)
                        .compact()

                //decompress and decrypt:
                def jwt = Jwts.parser()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getPayload().get('foo')
            }
        }
    }

    @Test
    void testPasswordJwes() {

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it instanceof Pbes2HsAkwAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        Password key = Keys.password("12345678".toCharArray())

        for (KeyAlgorithm alg : algs) {

            for (AeadAlgorithm enc : Jwts.ENC.get().values()) {

                // encrypt:
                String jwe = Jwts.builder()
                        .claim('foo', 'bar')
                        .encryptWith(key, alg, enc)
                        .compact()

                //decrypt:
                def jwt = Jwts.parser()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getPayload().get('foo')
            }
        }
    }

    @Test
    void testPasswordJweWithoutSpecifyingAlg() {

        Password key = Keys.password("12345678".toCharArray())

        // encrypt:
        String jwe = Jwts.builder()
                .claim('foo', 'bar')
                .encryptWith(key, Jwts.ENC.A256GCM) // should auto choose KeyAlg PBES2_HS512_A256KW
                .compact()

        //decrypt:
        def jwt = Jwts.parser()
                .decryptWith(key)
                .build()
                .parseClaimsJwe(jwe)
        assertEquals 'bar', jwt.getPayload().get('foo')
        assertEquals Jwts.KEY.PBES2_HS512_A256KW, Jwts.KEY.get().forKey(jwt.getHeader().getAlgorithm())
    }

    @Test
    void testRsaJwes() {

        def pairs = [TestKeys.RS256.pair, TestKeys.RS384.pair, TestKeys.RS512.pair]

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it instanceof DefaultRsaKeyAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        for (KeyPair pair : pairs) {

            def pubKey = pair.getPublic()
            def privKey = pair.getPrivate()

            for (KeyAlgorithm alg : algs) {

                for (AeadAlgorithm enc : Jwts.ENC.get().values()) {

                    // encrypt:
                    String jwe = Jwts.builder()
                            .claim('foo', 'bar')
                            .encryptWith(pubKey, alg, enc)
                            .compact()

                    //decrypt:
                    def jwt = Jwts.parser()
                            .decryptWith(privKey)
                            .build()
                            .parseClaimsJwe(jwe)
                    assertEquals 'bar', jwt.getPayload().get('foo')
                }
            }
        }
    }

    @Test
    void testEcJwes() {

        def pairs = [TestKeys.ES256.pair, TestKeys.ES384.pair, TestKeys.ES512.pair]

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it.getId().startsWith("ECDH-ES")
        })

        for (KeyPair pair : pairs) {

            def pubKey = pair.getPublic()
            def privKey = pair.getPrivate()

            for (KeyAlgorithm alg : algs) {

                for (AeadAlgorithm enc : Jwts.ENC.get().values()) {

                    // encrypt:
                    String jwe = Jwts.builder()
                            .claim('foo', 'bar')
                            .encryptWith(pubKey, alg, enc)
                            .compact()

                    //decrypt:
                    def jwt = Jwts.parser()
                            .decryptWith(privKey)
                            .build()
                            .parseClaimsJwe(jwe)
                    assertEquals 'bar', jwt.getPayload().get('foo')
                }
            }
        }
    }

    @Test
    void testEdwardsCurveJwes() { // ensures encryption works with Edwards Curve keys (X25519 and X448)

        def pairs = [TestKeys.X25519.pair, TestKeys.X448.pair]

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it.getId().startsWith("ECDH-ES")
        })

        for (KeyPair pair : pairs) {

            def pubKey = pair.getPublic()
            def privKey = pair.getPrivate()

            for (KeyAlgorithm alg : algs) {
                for (AeadAlgorithm enc : Jwts.ENC.get().values()) {
                    String jwe = encrypt(pubKey, alg, enc)
                    def jwt = decrypt(jwe, privKey)
                    assertEquals 'bar', jwt.getPayload().get('foo')
                }
            }
        }
    }

    /**
     * Asserts that Edwards Curve signing keys cannot be used for encryption (key agreement) per
     * https://www.rfc-editor.org/rfc/rfc8037#section-3.1
     */
    @Test
    void testEdwardsCurveEncryptionWithSigningKeys() {
        def pairs = [TestKeys.Ed25519.pair, TestKeys.Ed448.pair] // signing keys, can't be used

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it.getId().startsWith("ECDH-ES")
        })

        for (KeyPair pair : pairs) {
            def pubKey = pair.getPublic()
            for (KeyAlgorithm alg : algs) {
                for (AeadAlgorithm enc : Jwts.ENC.get().values()) {
                    try {
                        encrypt(pubKey, alg, enc)
                        fail()
                    } catch (InvalidKeyException expected) {
                        String id = EdwardsCurve.forKey(pubKey).getId()
                        String msg = id + " keys may not be used with ECDH-ES key " +
                                "agreement algorithms per https://www.rfc-editor.org/rfc/rfc8037#section-3.1."
                        assertEquals msg, expected.getMessage()
                    }
                }
            }
        }
    }

    /**
     * Asserts that Edwards Curve signing keys cannot be used for decryption (key agreement) per
     * https://www.rfc-editor.org/rfc/rfc8037#section-3.1
     */
    @Test
    void testEdwardsCurveDecryptionWithSigningKeys() {

        def pairs = [ // private keys are invalid signing keys to test decryption:
                      new KeyPair(TestKeys.X25519.pair.public, TestKeys.Ed25519.pair.private),
                      new KeyPair(TestKeys.X448.pair.public, TestKeys.Ed448.pair.private)
        ]

        def algs = Jwts.KEY.get().values().findAll({ it ->
            it.getId().startsWith("ECDH-ES")
        })

        for (KeyPair pair : pairs) {
            for (KeyAlgorithm alg : algs) {
                for (AeadAlgorithm enc : Jwts.ENC.get().values()) {
                    String jwe = encrypt(pair.getPublic(), alg, enc)
                    PrivateKey key = pair.getPrivate()
                    try {
                        decrypt(jwe, key) // invalid signing key
                        fail()
                    } catch (InvalidKeyException expected) {
                        String id = EdwardsCurve.forKey(key).getId()
                        String msg = id + " keys may not be used with ECDH-ES key " +
                                "agreement algorithms per https://www.rfc-editor.org/rfc/rfc8037#section-3.1."
                        assertEquals msg, expected.getMessage()
                    }
                }
            }
        }
    }

    static String encrypt(PublicKey key, KeyAlgorithm alg, AeadAlgorithm enc) {
        return Jwts.builder().claim('foo', 'bar').encryptWith(key, alg, enc).compact()
    }

    static Jwe<Claims> decrypt(String jwe, PrivateKey key) {
        return Jwts.parser().decryptWith(key).build().parseClaimsJwe(jwe)
    }

    static void testRsa(io.jsonwebtoken.security.SignatureAlgorithm alg) {

        KeyPair kp = TestKeys.forAlgorithm(alg).pair
        PublicKey publicKey = kp.getPublic()
        PrivateKey privateKey = kp.getPrivate()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().claims().add(claims).and().signWith(privateKey, alg).compact()

        def token = Jwts.parser().verifyWith(publicKey).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.payload)
    }

    static void testHmac(MacAlgorithm alg) {

        //create random signing key for testing:
        SecretKey key = alg.key().build()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().claims().add(claims).and().signWith(key, alg).compact()

        def token = Jwts.parser().verifyWith(key).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.payload)
    }

    static void testEC(io.jsonwebtoken.security.SignatureAlgorithm alg, boolean verifyWithPrivateKey = false) {
        testEC(alg, TestKeys.forAlgorithm(alg).pair, verifyWithPrivateKey)
    }

    static void testEC(io.jsonwebtoken.security.SignatureAlgorithm alg, KeyPair pair, boolean verifyWithPrivateKey = false) {

        PublicKey publicKey = pair.getPublic()
        PrivateKey privateKey = pair.getPrivate()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().claims().add(claims).and().signWith(privateKey, alg).compact()

        def key = publicKey
        if (verifyWithPrivateKey) {
            key = privateKey
        }

        def token = Jwts.parser().verifyWith(key).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.payload)

    }
}

