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

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.JsonMappingException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.impl.crypto.MacProvider
import org.junit.Test
import static org.junit.Assert.*

class DefaultJwtBuilderTest {

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
    void testCompactWithBothKeyAndKeyBytes() {
        def b = new DefaultJwtBuilder()
        b.setPayload('foo')
        def key = MacProvider.generateKey()
        b.signWith(SignatureAlgorithm.HS256, key)
        b.signWith(SignatureAlgorithm.HS256, key.encoded)
        try {
            b.compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.message, "A key object and key bytes cannot both be specified. Choose either one."
        }
    }

    @Test
    void testCompactWithJwsHeader() {
        def b = new DefaultJwtBuilder()
        b.setHeader(Jwts.jwsHeader().setKeyId('a'))
        b.setPayload('foo')
        def key = MacProvider.generateKey()
        b.signWith(SignatureAlgorithm.HS256, key)
        b.compact()
    }

    @Test
    void testBase64UrlEncodeError() {

        def b = new DefaultJwtBuilder() {
            @Override
            protected String toJson(Object o) throws JsonProcessingException {
                throw new JsonMappingException('foo')
            }
        }

        try {
            b.setPayload('foo').compact()
            fail()
        } catch (IllegalStateException ise) {
            assertEquals ise.cause.message, 'foo'
        }

    }
}
