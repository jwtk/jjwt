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
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.io.Encoder
import io.jsonwebtoken.io.EncodingException
import io.jsonwebtoken.io.SerializationException
import io.jsonwebtoken.io.Serializer
import io.jsonwebtoken.security.Keys
import org.junit.Test

import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import java.security.KeyFactory

import static org.junit.Assert.*

class DefaultJwtBuilderTest {

    private static ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testSetHeader() {
        def h = Jwts.header()
        def b = new DefaultJwtBuilder()
        b.setHeader(h)
        assertSame b.header, h
    }

    @Test
    void testSetHeaderFromMap() {
        def m = [foo: 'bar']
        def b = new DefaultJwtBuilder()
        b.setHeader(m)
        assertNotNull b.header
        assertEquals b.header.size(), 1
        assertEquals b.header.foo, 'bar'
    }

    @Test
    void testSetHeaderParams() {
        def m = [a: 'b', c: 'd']
        def b = new DefaultJwtBuilder()
        b.setHeaderParams(m)
        assertNotNull b.header
        assertEquals b.header.size(), 2
        assertEquals b.header.a, 'b'
        assertEquals b.header.c, 'd'
    }

    @Test
    void testSetHeaderParam() {
        def b = new DefaultJwtBuilder()
        b.setHeaderParam('foo', 'bar')
        assertNotNull b.header
        assertEquals b.header.size(), 1
        assertEquals b.header.foo, 'bar'
    }

    @Test
    void testSetClaims() {
        def b = new DefaultJwtBuilder()
        def c = Jwts.claims()
        b.setClaims(c)
        assertNotNull b.claims
        assertSame b.claims, c
    }

    @Test
    void testAddClaims() {
        def b = new DefaultJwtBuilder()
        def c = Jwts.claims([initial: 'initial'])
        b.setClaims(c)
        def c2 = [foo: 'bar', baz: 'buz']
        b.addClaims(c2)
        assertEquals 'initial', b.claims.get('initial')
        assertEquals 'bar', b.claims.get('foo')
    }

    @Test
    void testAddClaimsWithoutInitializing() {
        def b = new DefaultJwtBuilder()
        def c = [foo: 'bar', baz: 'buz']
        b.addClaims(c)
        assertNotNull b.claims
        assertEquals b.claims, c
    }

    @Test
    void testClaim() {
        def b = new DefaultJwtBuilder()
        b.claim('foo', 'bar')
        assertNotNull b.claims
        assertEquals b.claims.size(), 1
        assertEquals b.claims.foo, 'bar'
    }

    @Test
    void testExistingClaimsAndSetClaim() {
        def b = new DefaultJwtBuilder()
        def c = Jwts.claims()
        b.setClaims(c)
        b.claim('foo', 'bar')
        assertSame b.claims, c
        assertEquals b.claims.size(), 1
        assertEquals c.size(), 1
        assertEquals b.claims.foo, 'bar'
        assertEquals c.foo, 'bar'
    }

    @Test
    void testRemoveClaimBySettingNullValue() {
        def b = new DefaultJwtBuilder()
        b.claim('foo', 'bar')
        assertNotNull b.claims
        assertEquals b.claims.size(), 1
        assertEquals b.claims.foo, 'bar'

        b.claim('foo', null)
        assertNotNull b.claims
        assertNull b.claims.foo
    }

    @Test
    void testCompactWithoutBody() {
        def b = new DefaultJwtBuilder()
        try {
            b.compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "Either 'payload' or 'claims' must be specified."
        }
    }

    @Test
    void testCompactWithoutPayloadOrClaims() {
        def b = new DefaultJwtBuilder()
        try {
            b.compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "Either 'payload' or 'claims' must be specified."
        }
    }

    @Test
    void testCompactWithBothPayloadAndClaims() {
        def b = new DefaultJwtBuilder()
        b.setPayload('foo')
        b.claim('a', 'b')
        try {
            b.compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "Both 'payload' and 'claims' cannot both be specified. Choose either one."
        }
    }

    @Test
    void testCompactWithJwsHeader() {
        def b = new DefaultJwtBuilder()
        b.setHeader(Jwts.jwsHeader().setKeyId('a'))
        b.setPayload('foo')
        def alg = SignatureAlgorithm.HS256
        def key = Keys.secretKeyFor(alg)
        b.signWith(key, alg)
        String s1 = b.compact()
        //ensure deprecated signWith(alg, key) produces the same result:
        b.signWith(alg, key)
        String s2 = b.compact()
        assertEquals s1, s2
    }

    @Test
    void testBase64UrlEncodeError() {

        def b = new DefaultJwtBuilder() {
            @Override
            protected byte[] toJson(Object o) throws SerializationException {
                throw new SerializationException('foo', new Exception())
            }
        }

        try {
            b.setPayload('foo').compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.cause.message, 'foo'
        }
    }

    @Test
    void testCompactCompressionCodecJsonProcessingException() {
        def b = new DefaultJwtBuilder() {
            @Override
            protected byte[] toJson(Object o) throws SerializationException {
                if (o instanceof DefaultJwsHeader) {
                    return super.toJson(o)
                }
                throw new SerializationException('dummy text', new Exception())
            }
        }

        def c = Jwts.claims().setSubject("Joe");

        try {
            b.setClaims(c).compressWith(CompressionCodecs.DEFLATE).compact()
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals iae.message, 'Unable to serialize claims object to json: dummy text'
        }
    }

    @Test
    void testSignWithKeyOnly() {

        def b = new DefaultJwtBuilder()
        b.setHeader(Jwts.jwsHeader().setKeyId('a'))
        b.setPayload('foo')

        def key = KeyGenerator.getInstance('HmacSHA256').generateKey()

        b.signWith(key)
        String s1 = b.compact()

        //ensure matches same result with specified algorithm:
        b.signWith(key, SignatureAlgorithm.HS256)
        String s2 = b.compact()

        assertEquals s1, s2
    }

    @Test
    void testSignWithBytesWithoutHmac() {
        def bytes = new byte[16];
        try {
            new DefaultJwtBuilder().signWith(SignatureAlgorithm.ES256, bytes);
            fail()
        } catch (IllegalArgumentException iae) {
            assertEquals "Key bytes may only be specified for HMAC signatures.  If using RSA or Elliptic Curve, use the signWith(SignatureAlgorithm, Key) method instead.", iae.message
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
        def b = new DefaultJwtBuilder()
        b.setHeaderParams(null)
        assertNull b.header
    }

    @Test
    void testSetHeaderParamsWithEmptyMap() {
        def b = new DefaultJwtBuilder()
        b.setHeaderParams([:])
        assertNull b.header
    }

    @Test
    void testSetIssuerWithNull() {
        def b = new DefaultJwtBuilder()
        b.setIssuer(null)
        assertNull b.claims
    }

    @Test
    void testSetSubjectWithNull() {
        def b = new DefaultJwtBuilder()
        b.setSubject(null)
        assertNull b.claims
    }

    @Test
    void testSetAudienceWithNull() {
        def b = new DefaultJwtBuilder()
        b.setAudience(null)
        assertNull b.claims
    }

    @Test
    void testSetIdWithNull() {
        def b = new DefaultJwtBuilder()
        b.setId(null)
        assertNull b.claims
    }

    @Test
    void testClaimNullValue() {
        def b = new DefaultJwtBuilder()
        b.claim('foo', null)
        assertNull b.claims
    }

    @Test
    void testSetNullExpirationWithNullClaims() {
        def b = new DefaultJwtBuilder()
        b.setExpiration(null)
        assertNull b.claims
    }

    @Test
    void testSetNullNotBeforeWithNullClaims() {
        def b = new DefaultJwtBuilder()
        b.setNotBefore(null)
        assertNull b.claims
    }

    @Test
    void testSetNullIssuedAtWithNullClaims() {
        def b = new DefaultJwtBuilder()
        b.setIssuedAt(null)
        assertNull b.claims
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
        def b = new DefaultJwtBuilder().base64UrlEncodeWith(encoder)
        assertSame encoder, b.base64UrlEncoder
    }

    @Test(expected = IllegalArgumentException)
    void testSerializeToJsonWithNullArgument() {
        new DefaultJwtBuilder().serializeToJsonWith(null)
    }

    @Test
    void testSerializeToJsonWithCustomSerializer() {
        def serializer = new Serializer() {
            @Override
            byte[] serialize(Object o) throws SerializationException {
                return objectMapper.writeValueAsBytes(o)
            }
        }

        def b = new DefaultJwtBuilder().serializeToJsonWith(serializer)
        assertSame serializer, b.serializer

        def key = Keys.secretKeyFor(SignatureAlgorithm.HS256)

        String jws = b.signWith(key, SignatureAlgorithm.HS256)
                .claim('foo', 'bar')
                .compact()

        assertEquals 'bar', Jwts.parser().setSigningKey(key).parseClaimsJws(jws).getBody().get('foo')
    }

}
