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

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.impl.DefaultHeader
import io.jsonwebtoken.impl.DefaultJwsHeader
import io.jsonwebtoken.impl.TextCodec
import io.jsonwebtoken.impl.compression.CompressionCodecs
import io.jsonwebtoken.impl.compression.DefaultCompressionCodecResolver
import io.jsonwebtoken.impl.compression.GzipCompressionCodec
import io.jsonwebtoken.impl.crypto.EllipticCurveProvider
import io.jsonwebtoken.impl.crypto.MacProvider
import io.jsonwebtoken.impl.crypto.RsaProvider
import io.jsonwebtoken.lang.Strings
import org.junit.Test

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

import static org.junit.Assert.*

class JwtsTest {

    @Test
    void testSubclass() {
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

        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.body == claims
    }

    @Test(expected = IllegalArgumentException)
    void testParseNull() {
        Jwts.parser().parse(null)
    }

    @Test(expected = IllegalArgumentException)
    void testParseEmptyString() {
        Jwts.parser().parse('')
    }

    @Test(expected = IllegalArgumentException)
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
    void testWithInvalidCompressionAlgorithm() {
        try {

            Jwts.builder().setHeaderParam(Header.COMPRESSION_ALGORITHM, "CUSTOM").setId("andId").compact()
        } catch (CompressionException e) {
            assertEquals "Unsupported compression algorithm 'CUSTOM'", e.getMessage()
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
    void testUncompressedJwt() {

        byte[] key = MacProvider.generateKey().getEncoded()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(SignatureAlgorithm.HS256, key)
                .claim("state", "hello this is an amazing jwt").compact()

        def jws = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        Claims claims = jws.body

        assertNull jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithDeflate() {

        byte[] key = MacProvider.generateKey().getEncoded()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(SignatureAlgorithm.HS256, key)
                .claim("state", "hello this is an amazing jwt").compressWith(CompressionCodecs.DEFLATE).compact()

        def jws = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedJwtWithGZIP() {

        byte[] key = MacProvider.generateKey().getEncoded()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(SignatureAlgorithm.HS256, key)
                .claim("state", "hello this is an amazing jwt").compressWith(CompressionCodecs.GZIP).compact()

        def jws = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "GZIP", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state
    }

    @Test
    void testCompressedWithCustomResolver() {
        byte[] key = MacProvider.generateKey().getEncoded()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(SignatureAlgorithm.HS256, key)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionCodec() {
            @Override
            String getAlgorithmName() {
                return "CUSTOM"
            }
        }).compact()

        def jws = Jwts.parser().setSigningKey(key).setCompressionCodecResolver(new DefaultCompressionCodecResolver() {
            @Override
            CompressionCodec resolveCompressionCodec(Header header) {
                String algorithm = header.getCompressionAlgorithm()
                if ("CUSTOM".equals(algorithm)) {
                    return CompressionCodecs.GZIP
                } else {
                    return null
                }
            }
        }).parseClaimsJws(compact)

        Claims claims = jws.body

        assertEquals "CUSTOM", jws.header.getCompressionAlgorithm()

        assertEquals id, claims.getId()
        assertEquals "an audience", claims.getAudience()
        assertEquals "hello this is an amazing jwt", claims.state

    }
    @Test(expected = CompressionException.class)
    void testCompressedJwtWithUnrecognizedHeader() {
        byte[] key = MacProvider.generateKey().getEncoded()

        String id = UUID.randomUUID().toString()

        String compact = Jwts.builder().setId(id).setAudience("an audience").signWith(SignatureAlgorithm.HS256, key)
                .claim("state", "hello this is an amazing jwt").compressWith(new GzipCompressionCodec() {
            @Override
            String getAlgorithmName() {
                return "CUSTOM"
            }
        }).compact()

        Jwts.parser().setSigningKey(key).parseClaimsJws(compact)
    }

    @Test
    void testCompressStringPayloadWithDeflate() {

        byte[] key = MacProvider.generateKey().getEncoded()

        String payload = "this is my test for a payload"

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key)
                .compressWith(CompressionCodecs.DEFLATE).compact()

        def jws = Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

        String parsed = jws.body

        assertEquals "DEF", jws.header.getCompressionAlgorithm()

        assertEquals "this is my test for a payload", parsed
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

    @Test
    void testES256() {
        testEC(SignatureAlgorithm.ES256)
    }

    @Test
    void testES384() {
        testEC(SignatureAlgorithm.ES384)
    }

    @Test
    void testES512() {
        testEC(SignatureAlgorithm.ES512)
    }

    @Test
    void testES256WithPrivateKeyValidation() {
        try {
            testEC(SignatureAlgorithm.ES256, true)
            fail("EC private keys cannot be used to validate EC signatures.")
        } catch (UnsupportedJwtException e) {
            assertEquals e.cause.message, "Elliptic Curve signature validation requires an ECPublicKey instance."
        }
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testParseClaimsJwsWithUnsignedJwt() {

        //create random signing key for testing:
        byte[] key = MacProvider.generateKey().getEncoded()

        String notSigned = Jwts.builder().setSubject("Foo").compact();

        try {
            Jwts.parser().setSigningKey(key).parseClaimsJws(notSigned);
            fail('parseClaimsJws must fail for unsigned JWTs')
        } catch (UnsupportedJwtException expected) {
            assertEquals expected.message, 'Unsigned Claims JWTs are not supported.'
        }
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20
    @Test
    void testForgedTokenWithSwappedHeaderUsingNoneAlgorithm() {

        //create random signing key for testing:
        byte[] key = MacProvider.generateKey().getEncoded()

        //this is a 'real', valid JWT:
        String compact = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS256, key).compact();

        //Now strip off the signature so we can add it back in later on a forged token:
        int i = compact.lastIndexOf('.');
        String signature = compact.substring(i+1);

        //now let's create a fake header and payload with whatever we want (without signing):
        String forged = Jwts.builder().setSubject("Not Joe").compact();

        //assert that our forged header has a 'NONE' algorithm:
        assertEquals Jwts.parser().parseClaimsJwt(forged).getHeader().get('alg'), 'none'

        //now let's forge it by appending the signature the server expects:
        forged += signature;

        //now assert that, when the server tries to parse the forged token, parsing fails:
        try {
            Jwts.parser().setSigningKey(key).parse(forged);
            fail("Parsing must fail for a forged token.")
        } catch (MalformedJwtException expected) {
            assertEquals expected.message, 'JWT string has a digest/signature, but the header does not reference a valid signature algorithm.'
        }
    }

    //Asserts correct/expected behavior discussed in https://github.com/jwtk/jjwt/issues/20 and https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedRsaPublicKeyAsHmacTokenVerifiedWithTheRsaPrivateKey() {

        //Create a legitimate RSA public and private key pair:
        KeyPair kp = RsaProvider.generateKeyPair(1024)
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        ObjectMapper om = new ObjectMapper()
        String header = TextCodec.BASE64URL.encode(om.writeValueAsString(['alg': 'HS256']))
        String body = TextCodec.BASE64URL.encode(om.writeValueAsString('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the RSA public key to sign a token, but
        // using it as an HMAC signing key instead of RSA:
        Mac mac = Mac.getInstance('HmacSHA256');
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'));
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = TextCodec.BASE64URL.encode(signatureBytes);

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature;

        // Assert that the server (that should always use the private key) does not recognized the forged token:
        try {
            Jwts.parser().setSigningKey(privateKey).parse(forged);
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    //Asserts correct behavior for https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedRsaPublicKeyAsHmacTokenVerifiedWithTheRsaPublicKey() {

        //Create a legitimate RSA public and private key pair:
        KeyPair kp = RsaProvider.generateKeyPair(1024)
        PublicKey publicKey = kp.getPublic();
        //PrivateKey privateKey = kp.getPrivate();

        ObjectMapper om = new ObjectMapper()
        String header = TextCodec.BASE64URL.encode(om.writeValueAsString(['alg': 'HS256']))
        String body = TextCodec.BASE64URL.encode(om.writeValueAsString('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the RSA public key to sign a token, but
        // using it as an HMAC signing key instead of RSA:
        Mac mac = Mac.getInstance('HmacSHA256');
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'));
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = TextCodec.BASE64URL.encode(signatureBytes);

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature;

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parser().setSigningKey(publicKey).parse(forged);
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    //Asserts correct behavior for https://github.com/jwtk/jjwt/issues/25
    @Test
    void testParseForgedEllipticCurvePublicKeyAsHmacToken() {

        //Create a legitimate RSA public and private key pair:
        KeyPair kp = EllipticCurveProvider.generateKeyPair()
        PublicKey publicKey = kp.getPublic();
        //PrivateKey privateKey = kp.getPrivate();

        ObjectMapper om = new ObjectMapper()
        String header = TextCodec.BASE64URL.encode(om.writeValueAsString(['alg': 'HS256']))
        String body = TextCodec.BASE64URL.encode(om.writeValueAsString('foo'))
        String compact = header + '.' + body + '.'

        // Now for the forgery: simulate an attacker using the Elliptic Curve public key to sign a token, but
        // using it as an HMAC signing key instead of Elliptic Curve:
        Mac mac = Mac.getInstance('HmacSHA256');
        mac.init(new SecretKeySpec(publicKey.getEncoded(), 'HmacSHA256'));
        byte[] signatureBytes = mac.doFinal(compact.getBytes(Charset.forName('US-ASCII')))
        String encodedSignature = TextCodec.BASE64URL.encode(signatureBytes);

        //Finally, the forged token is the header + body + forged signature:
        String forged = compact + encodedSignature;

        // Assert that the parser does not recognized the forged token:
        try {
            Jwts.parser().setSigningKey(publicKey).parse(forged);
            fail("Forged token must not be successfully parsed.")
        } catch (UnsupportedJwtException expected) {
            assertTrue expected.getMessage().startsWith('The parsed JWT indicates it was signed with the')
        }
    }

    static void testRsa(SignatureAlgorithm alg, int keySize=1024, boolean verifyWithPrivateKey=false) {

        KeyPair kp = RsaProvider.generateKeyPair(keySize)
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).signWith(alg, privateKey).compact();

        def key = publicKey;
        if (verifyWithPrivateKey) {
            key = privateKey;
        }

        def token = Jwts.parser().setSigningKey(key).parse(jwt);

        assert [alg: alg.name()] == token.header
        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.body == claims
    }

    static void testHmac(SignatureAlgorithm alg) {
        //create random signing key for testing:
        byte[] key = MacProvider.generateKey().encoded

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).signWith(alg, key).compact();

        def token = Jwts.parser().setSigningKey(key).parse(jwt)

        assert token.header == [alg: alg.name()]
        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.body == claims
    }

    static void testEC(SignatureAlgorithm alg, boolean verifyWithPrivateKey=false) {

        KeyPair pair = EllipticCurveProvider.generateKeyPair(alg)
        PublicKey publicKey = pair.getPublic()
        PrivateKey privateKey = pair.getPrivate()

        def claims = [iss: 'joe', exp: later(), 'http://example.com/is_root':true]

        String jwt = Jwts.builder().setClaims(claims).signWith(alg, privateKey).compact();

        def key = publicKey;
        if (verifyWithPrivateKey) {
            key = privateKey;
        }

        def token = Jwts.parser().setSigningKey(key).parse(jwt);

        assert token.header == [alg: alg.name()]
        //noinspection GrEqualsBetweenInconvertibleTypes
        assert token.body == claims
    }
}

