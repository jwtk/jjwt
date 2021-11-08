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

import io.jsonwebtoken.impl.DefaultClaims
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJweHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.JwtTokenizer
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver
import io.jsonwebtoken.impl.compression.GzipCompressionCodec
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.DirectKeyAlgorithm
import io.jsonwebtoken.impl.security.Pbes2HsAkwAlgorithm
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.lang.Strings
import io.jsonwebtoken.security.AeadAlgorithm
import io.jsonwebtoken.security.AsymmetricKeySignatureAlgorithm
import io.jsonwebtoken.security.EcKeyAlgorithm
import io.jsonwebtoken.security.EncryptionAlgorithms
import io.jsonwebtoken.security.KeyAlgorithm
import io.jsonwebtoken.security.KeyAlgorithms
import io.jsonwebtoken.security.Keys
import io.jsonwebtoken.security.PasswordKey
import io.jsonwebtoken.security.RsaKeyAlgorithm
import io.jsonwebtoken.security.SecretKeyAlgorithm
import io.jsonwebtoken.security.SecretKeySignatureAlgorithm
import io.jsonwebtoken.security.SignatureAlgorithm
import io.jsonwebtoken.security.SignatureAlgorithms
import io.jsonwebtoken.security.WeakKeyException
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

import static org.junit.Assert.*

class JwtsTest {

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
    void testJweHeaderWithNoArgs() {
        def header = Jwts.jweHeader()
        assertTrue header instanceof DefaultJweHeader
    }

    @Test
    void testJweHeaderWithMapArg() {
        def header = Jwts.jweHeader([enc: 'foo'])
        assertTrue header instanceof DefaultJweHeader
        assertEquals header.getEncryptionAlgorithm(), 'foo'
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
        // Assert exact output per example at https://datatracker.ietf.org/doc/html/rfc7519#section-6.1
        String encodedBody = 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ'
        String payload = new String(Decoders.BASE64URL.decode(encodedBody), StandardCharsets.UTF_8)
        String val = Jwts.builder().setPayload(payload).compact()
        String RFC_VALUE = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        assertEquals val, RFC_VALUE
    }

    @Test
    void testParsePlaintextToken() {

        def claims = [iss: 'joe', exp: later(), 'https://example.com/is_root': true]

        String jwt = Jwts.builder().setClaims(claims).compact()

        def token = Jwts.parserBuilder().enableUnsecuredJws().build().parse(jwt)

        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.body == claims
    }

    @Test(expected = IllegalArgumentException)
    void testParseNull() {
        Jwts.parserBuilder().build().parse(null)
    }

    @Test(expected = IllegalArgumentException)
    void testParseEmptyString() {
        Jwts.parserBuilder().build().parse('')
    }

    @Test(expected = IllegalArgumentException)
    void testParseWhitespaceString() {
        Jwts.parserBuilder().build().parse('   ')
    }

    @Test
    void testParseWithNoPeriods() {
        try {
            Jwts.parserBuilder().build().parse('foo')
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
            Jwts.parserBuilder().build().parse('.')
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
            Jwts.parserBuilder().build().parse('..')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals 'Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).', e.message
        }
    }

    @Test
    void testParseWithHeaderOnly() {
        String unsecuredJwt = base64Url("{\"alg\":\"none\"}") + ".."
        Jwt jwt = Jwts.parserBuilder().enableUnsecuredJws().build().parse(unsecuredJwt)
        assertEquals("none", jwt.getHeader().get("alg"))
    }

    @Test
    void testParseWithSignatureOnly() {
        try {
            Jwts.parserBuilder().build().parse('..bar')
            fail()
        } catch (MalformedJwtException e) {
            assertEquals 'Compact JWT strings MUST always have a Base64Url protected header per https://tools.ietf.org/html/rfc7519#section-7.2 (steps 2-4).', e.message
        }
    }

    @Test
    void testParseWithMissingRequiredSignature() {
        Key key = SignatureAlgorithms.HS256.keyBuilder().build()
        String compact = Jwts.builder().setSubject('foo').signWith(key).compact()
        int i = compact.lastIndexOf('.')
        String missingSig = compact.substring(0, i + 1)
        try {
            Jwts.parserBuilder().enableUnsecuredJws().setSigningKey(key).build().parseClaimsJws(missingSig)
            fail()
        } catch (MalformedJwtException expected) {
            assertEquals 'The JWS header references signature algorithm \'HS256\' but the compact JWS string is missing the required signature.', expected.getMessage()
        }
    }

    @Test
    void testWithInvalidCompressionAlgorithm() {
        try {

            Jwts.builder().setHeaderParam(Header.COMPRESSION_ALGORITHM, "CUSTOM").setId("andId").compact()
        } catch (CompressionException e) {
            assertEquals "Unsupported compression algorithm 'CUSTOM'", e.getMessage()
        }
    }

    @Test
    void testConvenienceIssuer() {
        String compact = Jwts.builder().setIssuer("Me").compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertEquals claims.getIssuer(), "Me"

        compact = Jwts.builder().setSubject("Joe")
                .setIssuer("Me") //set it
                .setIssuer(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getIssuer()
    }

    @Test
    void testConvenienceSubject() {
        String compact = Jwts.builder().setSubject("Joe").compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertEquals claims.getSubject(), "Joe"

        compact = Jwts.builder().setIssuer("Me")
                .setSubject("Joe") //set it
                .setSubject(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getSubject()
    }

    @Test
    void testConvenienceAudience() {
        String compact = Jwts.builder().setAudience("You").compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertEquals claims.getAudience(), "You"

        compact = Jwts.builder().setIssuer("Me")
                .setAudience("You") //set it
                .setAudience(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getAudience()
    }

    private static Date now() {
        return dateWithOnlySecondPrecision(System.currentTimeMillis())
    }

    private static int later() {
        return laterDate().getTime() / 1000
    }

    private static Date laterDate(int seconds) {
        return dateWithOnlySecondPrecision(System.currentTimeMillis() + (seconds * 1000))
    }

    private static Date laterDate() {
        return laterDate(10000)
    }

    private static Date dateWithOnlySecondPrecision(long millis) {
        long seconds = (long) (millis / 1000)
        long secondOnlyPrecisionMillis = seconds * 1000
        return new Date(secondOnlyPrecisionMillis)
    }

    @Test
    void testConvenienceExpiration() {
        Date then = laterDate()
        String compact = Jwts.builder().setExpiration(then).compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        def claimedDate = claims.getExpiration()
        assertEquals claimedDate, then

        compact = Jwts.builder().setIssuer("Me")
                .setExpiration(then) //set it
                .setExpiration(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getExpiration()
    }

    @Test
    void testConvenienceNotBefore() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setNotBefore(now).compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        def claimedDate = claims.getNotBefore()
        assertEquals claimedDate, now

        compact = Jwts.builder().setIssuer("Me")
                .setNotBefore(now) //set it
                .setNotBefore(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getNotBefore()
    }

    @Test
    void testConvenienceIssuedAt() {
        Date now = now() //jwt exp only supports *seconds* since epoch:
        String compact = Jwts.builder().setIssuedAt(now).compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        def claimedDate = claims.getIssuedAt()
        assertEquals claimedDate, now

        compact = Jwts.builder().setIssuer("Me")
                .setIssuedAt(now) //set it
                .setIssuedAt(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getIssuedAt()
    }

    @Test
    void testConvenienceId() {
        String id = UUID.randomUUID().toString()
        String compact = Jwts.builder().setId(id).compact()
        Claims claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertEquals claims.getId(), id

        compact = Jwts.builder().setIssuer("Me")
                .setId(id) //set it
                .setId(null) //null should remove it
                .compact()

        claims = Jwts.parserBuilder().enableUnsecuredJws().build().parse(compact).body as Claims
        assertNull claims.getId()
    }

    @Test
    void testUncompressedJwt() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compact()

        def jws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(compact)

        Claims claims = jws.body

        assertNull jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithDeflate() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(CompressionCodecs.DEFLATE).compact()

        def jws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithGZIP() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(CompressionCodecs.GZIP).compact()

        def jws = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "GZIP", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedWithCustomResolver() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionCodec() {
            @Override
            String getAlgorithmName() {
                return "CUSTOM"
            }
        }).compact()

        def jws = Jwts.parserBuilder().setSigningKey(key).setCompressionCodecResolver(new DefaultCompressionCodecResolver() {
            @Override
            CompressionCodec resolveCompressionCodec(Header header) {
                String algorithm = header.getCompressionAlgorithm()
                //noinspection ChangeToOperator
                if ("CUSTOM".equals(algorithm)) {
                    return CompressionCodecs.GZIP
                } else {
                    return null
                }
            }
        }).build().parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "CUSTOM", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state

    }

    @Test(expected = CompressionException.class)
    void testCompressedJwtWithUnrecognizedHeader() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(key, alg)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionCodec() {
            @Override
            String getAlgorithmName() {
                return "CUSTOM"
            }
        }).compact()

        Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(compact)
    }

    @Test
    void testCompressStringPayloadWithDeflate() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String payload = "this is my test for a payload"

        String compact = Jwts.builder().setPayload(payload).signWith(key, alg)
                .compressWith(CompressionCodecs.DEFLATE).compact()

        def jws = Jwts.parserBuilder().setSigningKey(key).build().parsePlaintextJws(compact)

        String parsed = jws.body

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals "this is my test for a payload", parsed
    }

    @Test
    void testHS256() {
        testHmac(SignatureAlgorithms.HS256)
    }

    @Test
    void testHS384() {
        testHmac(SignatureAlgorithms.HS384)
    }

    @Test
    void testHS512() {
        testHmac(SignatureAlgorithms.HS512)
    }

    @Test
    void testRS256() {
        testRsa(SignatureAlgorithms.RS256)
    }

    @Test
    void testRS384() {
        testRsa(SignatureAlgorithms.RS384)
    }

    @Test
    void testRS512() {
        testRsa(SignatureAlgorithms.RS512)
    }

    @Test
    void testPS256() {
        testRsa(SignatureAlgorithms.PS256)
    }

    @Test
    void testPS384() {
        testRsa(SignatureAlgorithms.PS384)
    }

    @Test
    void testPS512() {
        testRsa(SignatureAlgorithms.PS512)
    }

    @Test
    void testRSA256WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithms.RS256, true)
    }

    @Test
    void testRSA384WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithms.RS384, true)
    }

    @Test
    void testRSA512WithPrivateKeyValidation() {
        testRsa(SignatureAlgorithms.RS512, true)
    }

    @Test
    void testES256() {
        testEC(SignatureAlgorithms.ES256)
    }

    @Test
    void testES384() {
        testEC(SignatureAlgorithms.ES384)
    }

    @Test
    void testES512() {
        testEC(SignatureAlgorithms.ES512)
    }

    @Test
    void testES256WithPrivateKeyValidation() {
        try {
            testEC(SignatureAlgorithms.ES256, true)
            fail("EC private keys cannot be used to validate EC signatures.")
        } catch (UnsupportedJwtException e) {
            assertEquals e.cause.message, "Elliptic Curve signature validation requires an ECPublicKey instance."
        }
    }

    @Test(expected = WeakKeyException)
    void testParseClaimsJwsWithWeakHmacKey() {

        SignatureAlgorithm alg = SignatureAlgorithms.HS384
        def key = alg.keyBuilder().build()
        def weakKey = SignatureAlgorithms.HS256.keyBuilder().build()

        String jws = Jwts.builder().setSubject("Foo").signWith(key, alg).compact()

        Jwts.parserBuilder().setSigningKey(weakKey).build().parseClaimsJws(jws)
        fail('parseClaimsJws must fail for weak keys')
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testParseClaimsJwsWithUnsignedJwt() {

        //create random signing key for testing:
        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        String notSigned = Jwts.builder().setSubject("Foo").compact()

        try {
            Jwts.parserBuilder().enableUnsecuredJws().setSigningKey(key).build().parseClaimsJws(notSigned)
            fail('parseClaimsJws must fail for unsigned JWTs')
        } catch (UnsupportedJwtException expected) {
            assertEquals expected.message, 'Unsigned Claims JWTs are not supported.'
        }
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testForgedTokenWithSwappedHeaderUsingNoneAlgorithm() {

        //create random signing key for testing:
        SignatureAlgorithm alg = SignatureAlgorithms.HS256
        SecretKey key = alg.keyBuilder().build()

        //this is a 'real', valid JWT:
        String compact = Jwts.builder().setSubject("Joe").signWith(key, alg).compact()

        //Now strip off the signature so we can add it back in later on a forged token:
        int i = compact.lastIndexOf('.')
        String signature = compact.substring(i + 1)

        //now let's create a fake header and payload with whatever we want (without signing):
        String forged = Jwts.builder().setSubject("Not Joe").compact()

        //assert that our forged header has a 'NONE' algorithm:
        assertEquals Jwts.parserBuilder().enableUnsecuredJws().build().parseClaimsJwt(forged).getHeader().get('alg'), 'none'

        //now let's forge it by appending the signature the server expects:
        forged += signature

        //now assert that, when the server tries to parse the forged token, parsing fails:
        try {
            Jwts.parserBuilder().enableUnsecuredJws().setSigningKey(key).build().parse(forged)
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
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the server (that should always use the private key) does not recognized the forged token:
        try {
            Jwts.parserBuilder().setSigningKey(privateKey).build().parse(forged)
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
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parse(forged)
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
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'))
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = Encoders.BASE64URL.encode(signatureBytes)

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parse(forged)
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    @Test
    void testSecretKeyJwes() {

        def algs = KeyAlgorithms.values().findAll({ it ->
            it instanceof DirectKeyAlgorithm || it instanceof SecretKeyAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        for (KeyAlgorithm alg : algs) {

            for (AeadAlgorithm enc : EncryptionAlgorithms.values()) {

                SecretKey key = alg instanceof SecretKeyAlgorithm ?
                        ((SecretKeyAlgorithm) alg).keyBuilder().build() :
                        enc.keyBuilder().build()

                // encrypt:
                String jwe = Jwts.jweBuilder()
                        .claim('foo', 'bar')
                        .encryptWith(enc)
                        .withKeyFrom(key, alg)
                        .compact()

                //decrypt:
                def jwt = Jwts.parserBuilder()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getBody().get('foo')
            }
        }
    }

    @Test
    void testJweCompression() {

        def codecs = [CompressionCodecs.DEFLATE, CompressionCodecs.GZIP]

        for (CompressionCodec codec : codecs) {

            for (AeadAlgorithm enc : EncryptionAlgorithms.values()) {

                SecretKey key = enc.keyBuilder().build()

                // encrypt and compress:
                String jwe = Jwts.jweBuilder()
                        .claim('foo', 'bar')
                        .compressWith(codec)
                        .encryptWith(enc)
                        .withKey(key)
                        .compact()

                //decompress and decrypt:
                def jwt = Jwts.parserBuilder()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getBody().get('foo')
            }
        }
    }

    @Test
    void testPasswordJwes() {

        def algs = KeyAlgorithms.values().findAll({ it ->
            it instanceof Pbes2HsAkwAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        PasswordKey key = Keys.forPassword("12345678".toCharArray())

        for (KeyAlgorithm alg : algs) {

            for (AeadAlgorithm enc : EncryptionAlgorithms.values()) {

                // encrypt:
                String jwe = Jwts.jweBuilder()
                        .claim('foo', 'bar')
                        .encryptWith(enc)
                        .withKeyFrom(key, alg)
                        .compact()

                //decrypt:
                def jwt = Jwts.parserBuilder()
                        .decryptWith(key)
                        .build()
                        .parseClaimsJwe(jwe)
                assertEquals 'bar', jwt.getBody().get('foo')
            }
        }
    }

    @Test
    void testPasswordJweWithoutSpecifyingAlg() {

        PasswordKey key = Keys.forPassword("12345678".toCharArray())

        // encrypt:
        String jwe = Jwts.jweBuilder()
                .claim('foo', 'bar')
                .encryptWith(EncryptionAlgorithms.A256GCM)
                .withKey(key) // does not use 'withKeyFrom', should default to strongest PBES2_HS512_A256KW
                .compact()

        //decrypt:
        def jwt = Jwts.parserBuilder()
                .decryptWith(key)
                .build()
                .parseClaimsJwe(jwe)
        assertEquals 'bar', jwt.getBody().get('foo')
        assertEquals KeyAlgorithms.PBES2_HS512_A256KW, KeyAlgorithms.forId(jwt.getHeader().getAlgorithm())
    }

    @Test
    void testRsaJwes() {

        def pairs = [TestKeys.RS256.pair, TestKeys.RS384.pair, TestKeys.RS512.pair]

        def algs = KeyAlgorithms.values().findAll({ it ->
            it instanceof RsaKeyAlgorithm
        })// as Collection<KeyAlgorithm<SecretKey, SecretKey>>

        for (KeyPair pair : pairs) {

            def pubKey = pair.getPublic()
            def privKey = pair.getPrivate()

            for (KeyAlgorithm alg : algs) {

                for (AeadAlgorithm enc : EncryptionAlgorithms.values()) {

                    // encrypt:
                    String jwe = Jwts.jweBuilder()
                            .claim('foo', 'bar')
                            .encryptWith(enc) // does not use 'withKeyFrom'
                            .withKeyFrom(pubKey, alg)
                            .compact()

                    //decrypt:
                    def jwt = Jwts.parserBuilder()
                            .decryptWith(privKey)
                            .build()
                            .parseClaimsJwe(jwe)
                    assertEquals 'bar', jwt.getBody().get('foo')
                }
            }
        }
    }

    @Test
    void testEcJwes() {

        def pairs = [TestKeys.ES256.pair, TestKeys.ES384.pair, TestKeys.ES512.pair]

        def algs = KeyAlgorithms.values().findAll({ it ->
            it instanceof EcKeyAlgorithm
        })

        for (KeyPair pair : pairs) {

            def pubKey = pair.getPublic()
            def privKey = pair.getPrivate()

            for (KeyAlgorithm alg : algs) {

                for (AeadAlgorithm enc : EncryptionAlgorithms.values()) {

                    // encrypt:
                    String jwe = Jwts.jweBuilder()
                            .claim('foo', 'bar')
                            .encryptWith(enc)
                            .withKeyFrom(pubKey, alg)
                            .compact()

                    //decrypt:
                    def jwt = Jwts.parserBuilder()
                            .decryptWith(privKey)
                            .build()
                            .parseClaimsJwe(jwe)
                    assertEquals 'bar', jwt.getBody().get('foo')
                }
            }
        }
    }

    static void testRsa(AsymmetricKeySignatureAlgorithm alg, boolean verifyWithPrivateKey = false) {

        KeyPair kp = TestKeys.forAlgorithm(alg).pair
        PublicKey publicKey = kp.getPublic()
        PrivateKey privateKey = kp.getPrivate()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().setClaims(claims).signWith(privateKey, alg).compact()

        def key = publicKey
        if (verifyWithPrivateKey) {
            key = privateKey
        }

        def token = Jwts.parserBuilder().setSigningKey(key).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.body)
    }

    static void testHmac(SecretKeySignatureAlgorithm alg) {

        //create random signing key for testing:
        SecretKey key = alg.keyBuilder().build()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().setClaims(claims).signWith(key, alg).compact()

        def token = Jwts.parserBuilder().setSigningKey(key).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.body)
    }

    static void testEC(AsymmetricKeySignatureAlgorithm alg, boolean verifyWithPrivateKey = false) {

        KeyPair pair = TestKeys.forAlgorithm(alg).pair
        PublicKey publicKey = pair.getPublic()
        PrivateKey privateKey = pair.getPrivate()

        def claims = new DefaultClaims([iss: 'joe', exp: later(), 'https://example.com/is_root': true])

        String jwt = Jwts.builder().setClaims(claims).signWith(privateKey, alg).compact()

        def key = publicKey
        if (verifyWithPrivateKey) {
            key = privateKey
        }

        def token = Jwts.parserBuilder().setSigningKey(key).build().parse(jwt)

        assertEquals([alg: alg.getId()], token.header)
        assertEquals(claims, token.body)
    }
}

