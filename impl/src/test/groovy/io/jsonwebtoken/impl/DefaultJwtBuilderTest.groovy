/*
 * Copyright (C) 2015 jsonwebtoken.io
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
package io.jsonwebtoken.impl

import com.fasterxml.jackson.databind.ObjectMapper
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.io.Streams
import io.jsonwebtoken.impl.io.TestSerializer
import io.jsonwebtoken.impl.lang.Services
import io.jsonwebtoken.impl.security.Randoms
import io.jsonwebtoken.impl.security.TestKey
import io.jsonwebtoken.impl.security.TestKeys
import io.jsonwebtoken.io.*
import io.jsonwebtoken.security.*
import org.junit.Before
import org.junit.Test

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom

import static org.easymock.EasyMock.*
import static org.junit.Assert.*

class DefaultJwtBuilderTest {

    private static ObjectMapper objectMapper = new ObjectMapper()

    private DefaultJwtBuilder builder

    private static byte[] serialize(Map<String, ?> map) {
        def serializer = Services.get(Serializer)
        ByteArrayOutputStream out = new ByteArrayOutputStream(512)
        serializer.serialize(map, out)
        return out.toByteArray()
    }

    private static Map<String, ?> deser(byte[] data) {
        def reader = Streams.reader(data)
        Map<String, ?> m = Services.get(Deserializer).deserialize(reader) as Map<String, ?>
        return m
    }

    @Before
    void setUp() {
        this.builder = new DefaultJwtBuilder()
    }

    @Test
    void testSetProvider() {

        Provider provider = createMock(Provider)

        final boolean[] called = new boolean[1]

        io.jsonwebtoken.security.SignatureAlgorithm alg = new io.jsonwebtoken.security.SignatureAlgorithm() {
            @Override
            byte[] digest(SecureRequest request) throws SignatureException, KeyException {
                assertSame provider, request.getProvider()
                called[0] = true
                //simulate a digest:
                byte[] bytes = new byte[32]
                Randoms.secureRandom().nextBytes(bytes)
                return bytes
            }

            @Override
            boolean verify(VerifySecureDigestRequest request) throws SignatureException, KeyException {
                throw new IllegalStateException("should not be called during build")
            }

            @Override
            KeyPairBuilder keyPair() {
                throw new IllegalStateException("should not be called during build")
            }

            @Override
            String getId() {
                return "test"
            }
        }

        replay provider
        def b = new DefaultJwtBuilder().provider(provider)
                .setSubject('me').signWith(Jwts.SIG.HS256.key().build(), alg)
        assertSame provider, b.provider
        b.compact()
        verify provider
        assertTrue called[0]
    }

    @Test
    void testSetSecureRandom() {

        final SecureRandom random = new SecureRandom()

        final boolean[] called = new boolean[1]

        io.jsonwebtoken.security.SignatureAlgorithm alg = new io.jsonwebtoken.security.SignatureAlgorithm() {
            @Override
            byte[] digest(SecureRequest request) throws SignatureException, KeyException {
                assertSame random, request.getSecureRandom()
                called[0] = true
                //simulate a digest:
                byte[] bytes = new byte[32]
                Randoms.secureRandom().nextBytes(bytes)
                return bytes
            }

            @Override
            boolean verify(VerifySecureDigestRequest request) throws SignatureException, KeyException {
                throw new IllegalStateException("should not be called during build")
            }

            @Override
            KeyPairBuilder keyPair() {
                throw new IllegalStateException("should not be called during build")
            }

            @Override
            String getId() {
                return "test"
            }
        }

        def b = new DefaultJwtBuilder().random(random)
                .setSubject('me').signWith(Jwts.SIG.HS256.key().build(), alg)
        assertSame random, b.secureRandom
        b.compact()
        assertTrue called[0]
    }

    @Test
    void testSetHeader() {
        def h = Jwts.header().add('foo', 'bar').build()
        builder.setHeader(h)
        assertEquals h, builder.headerBuilder.build()
    }

    @Test
    void testSetHeaderFromMap() {
        def m = [foo: 'bar']
        builder.setHeader(m)
        assertEquals builder.headerBuilder.build().foo, 'bar'
    }

    @Test
    void testSetHeaderParams() {
        def m = [a: 'b', c: 'd']
        builder.setHeaderParams(m)
        assertEquals builder.headerBuilder.build().a, 'b'
        assertEquals builder.headerBuilder.build().c, 'd'
    }

    @Test
    void testSetHeaderParam() {
        builder.setHeaderParam('foo', 'bar')
        assertEquals builder.headerBuilder.build().foo, 'bar'
    }

    @Test
    void testSetClaims() {
        Claims c = Jwts.claims().add('foo', 'bar').build()
        builder.setClaims(c)
        assertEquals c, builder.claimsBuilder
    }

    @Test
    void testSetClaimsMap() {
        def m = [foo: 'bar']
        builder.setClaims(m)
        assertEquals 1, builder.claimsBuilder.size()
        assertTrue builder.claimsBuilder.containsKey('foo')
        assertTrue builder.claimsBuilder.containsValue('bar')
    }

    @Test
    void testAddClaims() {
        def b = new DefaultJwtBuilder()
        def c = Jwts.claims([initial: 'initial'])
        b.claims().add(c)
        def c2 = [foo: 'bar', baz: 'buz']
        b.addClaims(c2)
        assertEquals 'initial', b.claimsBuilder.get('initial')
        assertEquals 'bar', b.claimsBuilder.get('foo')
    }

    @Test
    void testAddClaimsWithoutInitializing() {
        def b = new DefaultJwtBuilder()
        def c = [foo: 'bar', baz: 'buz']
        b.addClaims(c)
        assertNotNull b.claimsBuilder
        assertEquals c, b.claimsBuilder
    }

    @Test
    void testClaim() {
        def b = new DefaultJwtBuilder()
        b.claim('foo', 'bar')
        assertNotNull b.claimsBuilder
        assertEquals b.claimsBuilder.size(), 1
        assertEquals b.claimsBuilder.foo, 'bar'
    }

    @Test
    void testExistingClaimsAndSetClaim() {
        Claims c = Jwts.claims().add('foo', 'bar').build()
        builder.claims().add(c)
        assertEquals c, builder.claimsBuilder
        assertEquals builder.claimsBuilder.size(), 1
        assertEquals c.size(), 1
        assertEquals builder.claimsBuilder.foo, 'bar'
        assertEquals c.foo, 'bar'
    }

    @Test
    void testRemoveClaimBySettingNullValue() {
        def b = new DefaultJwtBuilder()
        b.claim('foo', 'bar')
        assertNotNull b.claimsBuilder
        assertEquals b.claimsBuilder.size(), 1
        assertEquals b.claimsBuilder.foo, 'bar'

        b.claim('foo', null)
        assertNotNull b.claimsBuilder
        assertNull b.claimsBuilder.foo
    }

    @Test
    void testCompactWithoutPayloadOrClaims() {
        def header = Encoders.BASE64URL.encode(serialize(['alg': 'none']))
        assertEquals "$header.." as String, new DefaultJwtBuilder().compact()
    }

    @Test
    void testNullPayloadString() {
        String payload = null
        def header = Encoders.BASE64URL.encode(serialize(['alg': 'none']))
        assertEquals "$header.." as String, builder.setPayload((String) payload).compact()
    }

    @Test
    void testCompactWithBothPayloadAndClaims() {
        try {
            builder.setPayload('foo').claim('a', 'b').compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "Both 'content' and 'claims' cannot be specified. Choose either one."
        }
    }

    @Test
    void testCompactWithJwsHeader() {
        def b = new DefaultJwtBuilder()
        b.header().keyId('a')
        b.setPayload('foo')
        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        b.signWith(key, alg)
        String s1 = b.compact()
        //ensure deprecated with(alg, key) produces the same result:
        b.signWith(alg, key)
        String s2 = b.compact()
        assertEquals s1, s2
    }

    @Test
    void testHeaderSerializationErrorException() {
        def ex = new IOException('foo')
        def ser = new TestSerializer(ex: ex)
        def b = new DefaultJwtBuilder().json(ser)
        try {
            b.content('bar').compact()
            fail()
        } catch (SerializationException expected) {
            assertEquals 'Cannot serialize JWT Header to JSON. Cause: foo', expected.getMessage()
        }
    }

    @Test
    void testCompactCompressionCodecJsonProcessingException() {
        def ex = new IOException('dummy text')
        def ser = new TestSerializer(ex: ex)
        def b = new DefaultJwtBuilder()
                .setSubject("Joe") // ensures claims instance
                .compressWith(Jwts.ZIP.DEF)
                .json(ser)
        try {
            b.compact()
            fail()
        } catch (SerializationException expected) {
            assertEquals 'Cannot serialize JWT Header to JSON. Cause: dummy text', expected.message
        }
    }

    @Test
    void testSignWithKeyOnly() {

        builder.subject("Joe") // make Claims JWS

        for (SecureDigestAlgorithm alg : Jwts.SIG.get().values()) {
            if (alg.equals(Jwts.SIG.NONE)) { // skip
                continue;
            }
            def key, vkey
            if (alg instanceof KeyPairBuilderSupplier) {
                def keyPair = alg.keyPair().build()
                key = keyPair.private
                vkey = keyPair.public
            } else { // MAC
                key = ((MacAlgorithm) alg).key().build()
                vkey = key
            }

            def parser = Jwts.parser().verifyWith(vkey).build()

            String s1 = builder.signWith(key).compact()
            def jws = parser.parseSignedClaims(s1)

            String s2 = builder.signWith(key, alg).compact()
            def jws2 = parser.parseSignedClaims(s2)

            // signatures differ across duplicate operations for some algorithms, so we can't do
            // assertEquals jws, jws2 (since those .equals implementations use the signature)
            // So we check for header and payload equality instead, and check the signature when we can:
            assertEquals jws.getHeader(), jws2.getHeader()
            assertEquals jws2.getPayload(), jws2.getPayload()
            // ES* and PS* signatures are nondeterministic and differ on each sign operation, even for identical
            // input, so we can't assert signature equality for them.  But we can with the others:
            if (!alg.id.startsWith('ES') && !alg.id.startsWith('PS')) {
                assertTrue MessageDigest.isEqual(jws.getDigest(), jws2.getDigest())
            }
        }
    }

    @Test
    void testSignWithKeyOnlyUsingUnsupportedKey() {
        try {
            builder.signWith(new TestKey(algorithm: 'foo'))
            fail()
        } catch (UnsupportedKeyException expected) {
            String msg = 'Unable to determine a suitable MAC or Signature algorithm for the specified key using ' +
                    'available heuristics: either the key size is too weak be used with available algorithms, or ' +
                    'the key size is unavailable (e.g. if using a PKCS11 or HSM (Hardware Security Module) key ' +
                    'store). If you are using a PKCS11 or HSM keystore, consider using the ' +
                    'JwtBuilder.signWith(Key, SecureDigestAlgorithm) method instead.'
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testSignWithBytesWithoutHmac() {
        def bytes = new byte[16];
        try {
            new DefaultJwtBuilder().signWith(SignatureAlgorithm.ES256, bytes);
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "Key bytes may only be specified for HMAC signatures.  If using RSA or " +
                    "Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.", iae.message
        }
    }

    @Test
    void testSignWithBase64EncodedBytesWithoutHmac() {
        try {
            new DefaultJwtBuilder().signWith(SignatureAlgorithm.ES256, 'foo');
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "Base64-encoded key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.", iae.message
        }

    }

    @Test
    void testSetHeaderParamsWithNullMap() {
        builder.setHeaderParams(null)
        assertTrue builder.headerBuilder.isEmpty()
    }

    @Test
    void testSetHeaderParamsWithEmptyMap() {
        builder.setHeaderParams([:])
        assertTrue builder.headerBuilder.isEmpty()
    }

    @Test
    void testSetIssuerWithNull() {
        def b = new DefaultJwtBuilder()
        b.setIssuer(null)
        assertTrue b.claimsBuilder.isEmpty()
    }

    @Test
    void testSetSubjectWithNull() {
        builder.setSubject(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testSetAudienceWithNull() {
        builder.setAudience(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testSetIdWithNull() {
        builder.setId(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testClaimNullValue() {
        builder.claim('foo', null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testSetNullExpirationWithNullClaims() {
        builder.setExpiration(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testSetNullNotBeforeWithNullClaims() {
        builder.setNotBefore(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test
    void testSetNullIssuedAtWithNullClaims() {
        builder.setIssuedAt(null)
        assertTrue builder.claimsBuilder.isEmpty()
    }

    @Test(expected = IllegalArgumentException)
    void testBase64UrlEncodeWithNullArgument() {
        new DefaultJwtBuilder().base64UrlEncodeWith(null)
    }

    @Test
    void testBase64UrlEncodeWithCustomEncoder() {
        def encoder = new Encoder() {
            @Override
            Object encode(Object o) throws EncodingException {
                return null
            }
        }
        def b = new DefaultJwtBuilder().b64Url(encoder)
        assertSame encoder, b.encoder
    }

    @Test
    void base64UrlEncodeWith() {

        boolean invoked = false

        Encoder<byte[], String> encoder = new Encoder<byte[], String>() {
            @Override
            String encode(byte[] bytes) throws EncodingException {
                invoked = true
                return Encoders.BASE64URL.encode(bytes)
            }
        }

        def key = TestKeys.HS256
        def b = new DefaultJwtBuilder().signWith(key).subject('me')

        def jws1 = b.compact()
        def jws2 = b.base64UrlEncodeWith(encoder).compact()

        assertEquals jws1, jws2
        assertTrue invoked
    }

    @Test(expected = IllegalArgumentException)
    void testSerializeToJsonWithNullArgument() {
        new DefaultJwtBuilder().serializeToJsonWith(null)
    }

    @Test
    void testSerializeToJsonWithCustomSerializer() {
        boolean invoked = false
        def serializer = new AbstractSerializer() {
            @Override
            protected void doSerialize(Object o, OutputStream out) throws Exception {
                invoked = true
                byte[] data = objectMapper.writeValueAsBytes(o)
                out.write(data)
            }
        }

        def b = new DefaultJwtBuilder().serializeToJsonWith(serializer)

        def key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String jws = b.signWith(key, SignatureAlgorithm.HS256)
                .claim('foo', 'bar')
                .compact()

        assertTrue invoked // ensure we call our custom one
        assertEquals 'bar', Jwts.parser().setSigningKey(key).build().parseSignedClaims(jws).getPayload().get('foo')
    }

    @Test
    void testSignWithNoneAlgorithm() {
        def key = TestKeys.HS256
        try {
            builder.signWith(key, Jwts.SIG.NONE)
            fail()
        } catch (IllegalArgumentException expected) {
            String msg = "The 'none' JWS algorithm cannot be used to sign JWTs."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testSignWithPublicKey() {
        def key = TestKeys.RS256.pair.public
        def alg = Jwts.SIG.RS256
        try {
            builder.signWith(key, alg)
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals(DefaultJwtBuilder.PUB_KEY_SIGN_MSG, iae.getMessage())
        }
    }

    @Test
    void testCompactSimplestPayload() {
        def enc = Jwts.ENC.A128GCM
        def key = enc.key().build()
        def jwe = builder.setPayload("me").encryptWith(key, enc).compact()
        def jwt = Jwts.parser().decryptWith(key).build().parseEncryptedContent(jwe)
        assertEquals 'me', new String(jwt.getPayload(), StandardCharsets.UTF_8)
    }

    @Test
    void testCompactSimplestClaims() {
        def enc = Jwts.ENC.A128GCM
        def key = enc.key().build()
        def jwe = builder.setSubject('joe').encryptWith(key, enc).compact()
        def jwt = Jwts.parser().decryptWith(key).build().parseEncryptedClaims(jwe)
        assertEquals 'joe', jwt.getPayload().getSubject()
    }

    @Test
    void testSignWithAndEncryptWith() {
        def key = TestKeys.HS256
        try {
            builder.signWith(key).encryptWith(key, Jwts.ENC.A128GCM).compact()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "Both 'signWith' and 'encryptWith' cannot be specified. Choose either one."
            assertEquals msg, expected.getMessage()
        }
    }

    @Test
    void testEmptyPayloadAndClaimsJwe() {
        def key = TestKeys.HS256
        try {
            builder.encryptWith(key, Jwts.ENC.A128GCM).compact()
            fail()
        } catch (IllegalStateException expected) {
            String msg = "Encrypted JWTs must have either 'claims' or non-empty 'content'."
            assertEquals msg, expected.getMessage()
        }
    }

    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testAudienceSingle() {
        def key = TestKeys.HS256
        String audienceSingleString = 'test'
        def jwt = builder.audience().single(audienceSingleString).compact()
        // can't use the parser here to validate because it coerces the string value into an array automatically,
        // so we need to check the raw payload:
        def encoded = new JwtTokenizer().tokenize(Streams.reader(jwt)).getPayload()
        byte[] bytes = Decoders.BASE64URL.decode(encoded)
        def claims = deser(bytes)

        assertEquals audienceSingleString, claims.aud
    }

    /**
     * Asserts that an additional call to audienceSingle is a full replacement operation and fully replaces the
     * previous audienceSingle value
     */
    @Test
    void testAudienceSingleMultiple() {
        def first = 'first'
        def second = 'second'
        //noinspection GrDeprecatedAPIUsage
        def jwt = builder.audience().single(first).audience().single(second).compact()
        // can't use the parser here to validate because it coerces the string value into an array automatically,
        // so we need to check the raw payload:
        def encoded = new JwtTokenizer().tokenize(Streams.reader(jwt)).getPayload()
        byte[] bytes = Decoders.BASE64URL.decode(encoded)
        def claims = deser(bytes)

        assertEquals second, claims.aud // second audienceSingle call replaces first value
    }

    /**
     * Asserts that an additional call to audienceSingle is a full replacement operation and fully replaces the
     * previous audienceSingle value
     */
    @Test
    void testAudienceSingleThenNull() {
        def jwt = builder.id('test')
                .audience().single('single') // set one
                .audience().single(null) // remove it entirely
                .compact()

        // shouldn't be an audience at all:
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    /**
     * Asserts that, even if audienceSingle is called and then the value removed, a final call to audience(Collection)
     * still represents a collection without any value errors
     */
    @Test
    void testAudienceSingleThenNullThenCollection() {
        def first = 'first'
        def second = 'second'
        def expected = [first, second] as Set<String>
        def jwt = builder
                .audience().single(first) // sets single value
                .audience().single(null) // removes entirely
                .audience().add([first, second]).and() // sets collection
                .compact()

        def aud = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
        assertEquals expected, aud
    }

    /**
     * Test to ensure that if we receive a JWT with a single string value, that the parser coerces it to a String array
     * so we don't have to worry about different data types:
     */
    @SuppressWarnings('GrDeprecatedAPIUsage')
    @Test
    void testParseAudienceSingle() {
        def key = TestKeys.HS256
        String audienceSingleString = 'test'
        def jwt = builder.audience().single(audienceSingleString).compact()

        assertEquals audienceSingleString, Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload
                .getAudience().iterator().next() // a collection, not a single string
    }

    @Test
    void testAudience() {
        def aud = 'fubar'
        def jwt = Jwts.builder().audience().add(aud).and().compact()
        assertEquals aud, Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience().iterator().next()
    }

    @Test
    void testAudienceNullString() {
        def jwt = Jwts.builder().subject('me').audience().add(null).and().compact()
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    @Test
    void testAudienceEmptyString() {
        def jwt = Jwts.builder().subject('me').audience().add('  ').and().compact()
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    @Test
    void testAudienceMultipleTimes() {
        def one = 'one'
        def two = 'two'
        def jwt = Jwts.builder().audience().add(one).add(two).and().compact()
        def aud = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
        assertTrue aud.contains(one)
        assertTrue aud.contains(two)
    }

    @Test
    void testAudienceNullCollection() {
        Collection c = null
        def jwt = Jwts.builder().subject('me').audience().add(c).and().compact()
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    @Test
    void testAudienceEmptyCollection() {
        Collection c = new ArrayList()
        def jwt = Jwts.builder().subject('me').audience().add(c).and().compact()
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    @Test
    void testAudienceCollectionWithNullElement() {
        Collection c = new ArrayList()
        c.add(null)
        def jwt = Jwts.builder().subject('me').audience().add(c).and().compact()
        assertNull Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
    }

    /**
     * Asserts that if someone calls builder.audienceSingle and then audience(String), that the audience value
     * will automatically be coerced from a String to a Set<String> and contain both elements.
     */
    @Test
    void testAudienceSingleThenAudience() {
        def one = 'one'
        def two = 'two'
        //noinspection GrDeprecatedAPIUsage
        def jwt = Jwts.builder().audience().single(one).audience().add(two).and().compact()
        def aud = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
        assertTrue aud.contains(one)
        assertTrue aud.contains(two)
    }

    /**
     * Asserts that if someone calls builder.audience and then audienceSingle, that the audience value
     * will automatically be coerced to a single String contain only the single value since audienceSingle is a
     * full-replacement operation.
     */
    @Test
    void testAudienceThenAudienceSingle() {
        def one = 'one'
        def two = 'two'
        //noinspection GrDeprecatedAPIUsage
        def jwt = Jwts.builder().audience().add(one).and().audience().single(two).compact()

        // can't use the parser here to validate because it coerces the string value into an array automatically,
        // so we need to check the raw payload:
        def encoded = new JwtTokenizer().tokenize(Streams.reader(jwt)).getPayload()
        byte[] bytes = Decoders.BASE64URL.decode(encoded)
        def claims = Services.get(Deserializer).deserialize(Streams.reader(bytes))

        assertEquals two, claims.aud
    }

    /**
     * Asserts that if someone calls builder.audienceSingle and then audience(Collection), the builder coerces the
     * aud to a Set<String> and all elements will be applied since audience(Collection).
     */
    @Test
    void testAudienceSingleThenAudienceCollection() {
        def single = 'one'
        def collection = ['two', 'three'] as Set<String>
        def expected = ['one', 'two', 'three'] as Set<String>
        //noinspection GrDeprecatedAPIUsage
        def jwt = Jwts.builder().audience().single(single).audience().add(collection).and().compact()
        def aud = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt).payload.getAudience()
        assertEquals expected.size(), aud.size()
        assertTrue aud.contains(single) && aud.containsAll(collection)
    }

    /**
     * Asserts that if someone calls builder.audience(Collection) and then audienceSingle, that the audience value
     * will automatically be coerced to a single String contain only the single value since audienceSingle is a
     * full-replacement operation.
     */
    @Test
    void testAudienceCollectionThenAudienceSingle() {
        def one = 'one'
        def two = 'two'
        def three = 'three'
        def jwt = Jwts.builder().audience().add([one, two]).and().audience().single(three).compact()

        // can't use the parser here to validate because it coerces the string value into an array automatically,
        // so we need to check the raw payload:
        def encoded = new JwtTokenizer().tokenize(Streams.reader(jwt)).getPayload()
        byte[] bytes = Decoders.BASE64URL.decode(encoded)
        def claims = deser(bytes)

        assertEquals three, claims.aud
    }

    /**
     * Asserts that if a .audience() builder is used, and its .and() method is not called, the change to the
     * audience is still applied when building the JWT.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testAudienceWithoutConjunction() {
        def aud = 'my-web'
        def builder = Jwts.builder()
        builder.audience().add(aud) // no .and() call
        def jwt = builder.compact()

        // assert that the resulting claims has the audience array set as expected:
        def parsed = Jwts.parser().unsecured().build().parseUnsecuredClaims(jwt)
        assertEquals aud, parsed.payload.getAudience()[0]
    }

    /**
     * Asserts that if a .header().critical() builder is used, and its .and() method is not called, the change to the
     * crit collection is still applied when building the header.
     * @see <a href="https://github.com/jwtk/jjwt/issues/916">JJWT Issue 916</a>
     * @since 0.12.5
     */
    @Test
    void testCritWithoutConjunction() {
        def crit = 'test'
        def builder = Jwts.builder().issuer('me')
        def headerBuilder = builder.header()
        headerBuilder.critical().add(crit) // no .and() method
        headerBuilder.add(crit, 'foo') // no .and() method
        builder.signWith(TestKeys.HS256)
        def jwt = builder.compact()

        def headerBytes = Decoders.BASE64URL.decode(jwt.split('\\.')[0])
        def headerMap = Services.get(Deserializer).deserialize(Streams.reader(headerBytes)) as Map<String, ?>

        def expected = [crit] as Set<String>
        def val = headerMap.get('crit') as Set<String>
        assertNotNull val
        assertEquals expected, val
    }

}
