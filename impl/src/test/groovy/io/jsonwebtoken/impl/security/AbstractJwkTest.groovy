/*
 * Copyright (C) 2021 jsonwebtoken.io
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
package io.jsonwebtoken.impl.security

import io.jsonwebtoken.lang.Collections
import io.jsonwebtoken.security.Jwk
import io.jsonwebtoken.security.Jwks
import io.jsonwebtoken.security.SecretJwk
import org.junit.Before
import org.junit.Test

import javax.crypto.SecretKey
import java.security.Key

import static org.junit.Assert.*

class AbstractJwkTest {

    AbstractJwk<? extends Key> jwk

    static JwkContext<SecretKey> newCtx() {
        return newCtx(null)
    }

    static JwkContext<SecretKey> newCtx(Map<String, ?> map) {
        def ctx = new DefaultJwkContext(AbstractJwk.PARAMS)
        ctx.put('kty', 'test')
        if (!Collections.isEmpty(map as Map)) {
            ctx.putAll(map)
        }
        ctx.setKey(TestKeys.HS256)
        return ctx
    }

    static AbstractJwk<SecretKey> newJwk(JwkContext<SecretKey> ctx) {
        return new AbstractJwk(ctx, Collections.of(AbstractJwk.KTY)) {
            @Override
            protected boolean equals(Jwk jwk) {
                return this.@context.equals(jwk.@context)
            }
        }
    }

    @Before
    void setUp() {
        jwk = newJwk(newCtx())
    }

    @Test
    void testGetFieldValue() {
        assertEquals 'test', jwk.get(AbstractJwk.KTY)
    }

    @Test
    void testContainsValue() {
        assertTrue jwk.containsValue('test')
        assertFalse jwk.containsValue('bar')
    }

    static void jwkImmutable(Closure c) {
        try {
            c.call()
            fail()
        } catch (UnsupportedOperationException expected) {
            String msg = 'JWKs are immutable and may not be modified.'
            assertEquals msg, expected.getMessage()
        }
    }

    static void jucImmutable(Closure c) {
        try {
            c.call()
            fail()
        } catch (UnsupportedOperationException expected) {
            assertNull expected.getMessage() // java.util.Collections.unmodifiable* doesn't give a message
        }
    }

    @Test
    void testImmutable() {
        jwk = newJwk(newCtx())
        jwkImmutable { jwk.put('foo', 'bar') }
        jwkImmutable { jwk.putAll([foo: 'bar']) }
        jwkImmutable { jwk.remove('kty') }
        jwkImmutable { jwk.clear() }
    }

    @Test
    // ensure that any map or collection returned from the JWK is immutable as well:
    void testCollectionsAreImmutable() {
        def vals = [
                map       : [foo: 'bar'],
                list      : ['a'],
                set       : ['b'] as Set,
                collection: ['c'] as Collection
        ]
        jwk = newJwk(newCtx(vals))
        jucImmutable { (jwk.get('map') as Map).remove('foo') }
        jucImmutable { (jwk.get('list') as List).remove(0) }
        jucImmutable { (jwk.get('set') as Set).remove('b') }
        jucImmutable { (jwk.get('collection') as Collection).remove('c') }
        jucImmutable { jwk.keySet().remove('map') }
        jucImmutable { jwk.values().remove('a') }
    }

    @Test
    // ensure that any array value returned from the JWK is a copy, so modifying it won't modify the original array
    void testArraysAreCopied() {
        def vals = [
                array: ['a', 'b'] as String[]
        ]
        jwk = newJwk(newCtx(vals))
        def returned = jwk.get('array')
        assertTrue returned instanceof String[]
        assertEquals 2, returned.length

        //now modify it:
        returned[0] = 'x'

        //ensure the array structure hasn't changed:
        def returned2 = jwk.get('array')
        assertEquals 'a', returned2[0]
        assertEquals 'b', returned2[1]
    }

    @Test
    void testPrivateJwkToStringHasRedactedValues() {
        def secretJwk = Jwks.builder().key(TestKeys.HS256).build()
        assertTrue secretJwk.toString().contains('k=<redacted>')

        def ecPrivJwk = Jwks.builder().key(TestKeys.ES256.pair.private).build()
        assertTrue ecPrivJwk.toString().contains('d=<redacted>')

        def rsaPrivJwk = Jwks.builder().key(TestKeys.RS256.pair.private).build()
        String s = 'd=<redacted>, p=<redacted>, q=<redacted>, dp=<redacted>, dq=<redacted>, qi=<redacted>'
        assertTrue rsaPrivJwk.toString().contains(s)
    }

    @Test
    void testPrivateJwkHashCode() {
        def secretJwk1 = Jwks.builder().key(TestKeys.HS256).add('hello', 'world').build()
        def secretJwk2 = Jwks.builder().key(TestKeys.HS256).add('hello', 'world').build()
        assertEquals secretJwk1.hashCode(), secretJwk2.hashCode()

        def ecPrivJwk1 = Jwks.builder().key(TestKeys.ES256.pair.private).add('hello', 'ecworld').build()
        def ecPrivJwk2 = Jwks.builder().key(TestKeys.ES256.pair.private).add('hello', 'ecworld').build()
        assertEquals ecPrivJwk1.hashCode(), ecPrivJwk2.hashCode()

        def rsaPrivJwk1 = Jwks.builder().key(TestKeys.RS256.pair.private).add('hello', 'rsaworld').build()
        def rsaPrivJwk2 = Jwks.builder().key(TestKeys.RS256.pair.private).add('hello', 'rsaworld').build()
        assertEquals rsaPrivJwk1.hashCode(), rsaPrivJwk2.hashCode()
    }

    @Test
    void testEqualsWithNonJwk() {
        SecretJwk jwk = Jwks.builder().key(TestKeys.HS256).build()
        assertFalse jwk.equals(42)
    }
}
