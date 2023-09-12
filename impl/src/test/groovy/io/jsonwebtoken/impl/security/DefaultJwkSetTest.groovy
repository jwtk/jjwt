/*
 * Copyright © 2023 jsonwebtoken.io
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

import io.jsonwebtoken.impl.lang.RedactedSupplier
import io.jsonwebtoken.security.Jwks
import org.junit.Test

import static org.junit.Assert.*

class DefaultJwkSetTest {

    @Test
    void testName() {
        assertEquals "JWK Set", new DefaultJwkSet(DefaultJwkSet.KEYS, [:]).getName()
    }

    private static void unsupported(Closure<?> c) {
        try {
            c()
            fail()
        } catch (UnsupportedOperationException expected) {
            String msg = 'JWK Set instance is immutable and may not be modified.'
            assertEquals msg, expected.message
        }
    }

    @Test
    void testImmutable() {
        def set = new DefaultJwkSet(DefaultJwkSet.KEYS, [a: 'b'])
        unsupported { set.put('foo', 'bar') }
        unsupported { set.putAll([c: 'd', e: 'f']) }
        unsupported { set.remove('a') }
        unsupported { set.clear() }
    }

    @Test(expected = UnsupportedOperationException)
    void testGetKeysImmutable() {
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        def set = new DefaultJwkSet(DefaultJwkSet.KEYS, [keys: [jwk]])
        def result = set.getKeys()
        result.remove(jwk) // shouldn't be able
        fail()
    }

    @Test(expected = UnsupportedOperationException)
    void testIteratorImmutable() {
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        def set = new DefaultJwkSet(DefaultJwkSet.KEYS, [keys: [jwk]])
        def i = set.iterator()
        assertEquals jwk, i.next()
        i.remove() // shouldn't be able to do this
        fail()
    }

    /**
     * Asserts that the raw keys value is a RedactedSupplier and not a raw value due to potential sensitivity if
     * the JwkSet contains secret or private JWKs.
     */
    @Test
    void testKeysFromGetIsRedactedSupplier() {
        def jwk = Jwks.builder().key(TestKeys.HS256).build()
        def set = new DefaultJwkSet(DefaultJwkSet.KEYS, [keys: [jwk]])
        def result = set.get('keys')
        assertTrue result instanceof RedactedSupplier
    }
}
